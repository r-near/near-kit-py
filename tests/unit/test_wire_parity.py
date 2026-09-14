"""Hand-computed Borsh layouts for the nearcore 2.13 action set.

Discriminants 9..14, the gas-key access-key permissions, ``TransactionNonce``
/ ``NonceMode``, the tagged V1 transaction, and the NEP-611 signing payload.
Golden vectors at the bottom were generated with near-kit-ts (its zorsh
schemas), so the two SDKs are proven byte-compatible.
"""

import base64
import hashlib

import base58
import pytest
from pyborsh import Borsh
from pydantic import BaseModel, ValidationError

from near import (
    add_full_access_key,
    add_gas_key,
    create_account,
    deterministic_state_init,
    function_call,
    generate_key,
    publish_contract,
    transfer,
    transfer_to_gas_key,
    use_global_contract,
    withdraw_from_gas_key,
)
from near.delegate import (
    encode_signed_delegate,
    sign_delegate_action,
    sign_delegate_action_v2,
)
from near.keys import KeyPairSigner
from near.wire import (
    NEP366_DELEGATE_PREFIX,
    NEP611_DELEGATE_V2_PREFIX,
    Action,
    AnyNonceMode,
    AnyTransactionNonce,
    DelegateAction,
    DelegateActionV2,
    GlobalContractIdentifier,
    NonceMode,
    PublicKeyWire,
    SignatureWire,
    SignedTransactionV1,
    Transaction,
    TransactionNonce,
    TransactionV1,
    VersionedDelegateActionPayload,
    delegate_action_v2_signing_hash,
    sign_transaction,
    to_global_contract_identifier,
    to_wire_public_key,
)


def _u16(n: int) -> bytes:
    return n.to_bytes(2, "little")


def _u32(n: int) -> bytes:
    return n.to_bytes(4, "little")


def _u64(n: int) -> bytes:
    return n.to_bytes(8, "little")


def _u128(n: int) -> bytes:
    return n.to_bytes(16, "little")


def _string(s: str) -> bytes:
    raw = s.encode()
    return _u32(len(raw)) + raw


def _bytes(b: bytes) -> bytes:
    return _u32(len(b)) + b


def _tx(actions, pk=None):
    pk = pk or generate_key().public_key
    return Transaction(
        signer_id="aa",
        public_key=to_wire_public_key(pk),
        nonce=0,
        receiver_id="bb",
        block_hash=bytes(32),
        actions=actions,
    )


# Prefix before actions for _tx(): 4+2 + 33 + 8 + 4+2 + 32 + 4 = 89 bytes.
ACTIONS_OFFSET = 89


def _action_bytes(action) -> bytes:
    return _tx([action]).to_borsh()[ACTIONS_OFFSET:]


def _signed_v2(signer, nonce=None):
    delegate = DelegateActionV2(
        sender_id=signer.account_id,
        receiver_id="bob.near",
        actions=[transfer("1 yocto")],
        nonce=nonce or TransactionNonce.GasKeyNonce(nonce=5, nonce_index=2),
        max_block_height=100,
        public_key=to_wire_public_key(signer.public_key),
    )
    return sign_delegate_action_v2(delegate, signer)


class TestActionDiscriminants:
    def test_every_variant_in_protocol_order(self):
        signer = KeyPairSigner("alice.near", generate_key())
        v1 = sign_delegate_action(
            DelegateAction(
                sender_id="alice.near",
                receiver_id="bob.near",
                actions=[transfer("1 yocto")],
                nonce=1,
                max_block_height=100,
                public_key=to_wire_public_key(signer.public_key),
            ),
            signer,
        )
        cases = [
            (create_account(), 0),
            (v1, 8),
            (publish_contract(b"\x00asm"), 9),
            (use_global_contract(account_id="p.near"), 10),
            (deterministic_state_init(account_id="p.near", deposit="1 yocto"), 11),
            (transfer_to_gas_key(signer.public_key, "1 yocto"), 12),
            (withdraw_from_gas_key(signer.public_key, "1 yocto"), 13),
            (_signed_v2(signer), 14),
        ]
        for action, discriminant in cases:
            assert _action_bytes(action)[0] == discriminant, type(action).__name__

    def test_all_fifteen_variants_round_trip_in_one_transaction(self):
        kp = generate_key()
        signer = KeyPairSigner("alice.near", kp)
        v1 = sign_delegate_action(
            DelegateAction(
                sender_id="alice.near",
                receiver_id="bob.near",
                actions=[transfer("1 yocto")],
                nonce=1,
                max_block_height=2,
                public_key=to_wire_public_key(kp.public_key),
            ),
            signer,
        )
        tx = _tx(
            [
                create_account(),
                publish_contract(b"wasm"),
                function_call("m"),
                transfer("1 yocto"),
                add_full_access_key(kp.public_key),
                add_gas_key(kp.public_key, 3),
                add_gas_key(kp.public_key, 3, contract_id="app.near", method_names=["m"]),
                v1,
                publish_contract(b"wasm", identified_by="hash"),
                use_global_contract(code_hash=bytes(32)),
                use_global_contract(account_id="p.near"),
                deterministic_state_init(code_hash=bytes(32), data={b"k": b"v"}, deposit="1 NEAR"),
                transfer_to_gas_key(kp.public_key, "1 NEAR"),
                withdraw_from_gas_key(kp.public_key, "1 NEAR"),
                _signed_v2(signer),
            ],
            kp.public_key,
        )
        assert Transaction.from_borsh(tx.to_borsh()) == tx


class TestGlobalContractLayout:
    def test_deploy_global_contract_by_hash(self):
        raw = _action_bytes(publish_contract(b"\x00asm\x01", identified_by="hash"))
        assert raw == b"\x09" + _bytes(b"\x00asm\x01") + b"\x00"

    def test_deploy_global_contract_by_account(self):
        raw = _action_bytes(publish_contract(b"\x00asm\x01"))
        assert raw == b"\x09" + _bytes(b"\x00asm\x01") + b"\x01"

    def test_use_global_contract_by_hash(self):
        digest = hashlib.sha256(b"code").digest()
        raw = _action_bytes(use_global_contract(code_hash=digest))
        assert raw == b"\x0a" + b"\x00" + digest
        # base58 form decodes to the same bytes
        b58 = base58.b58encode(digest).decode()
        assert _action_bytes(use_global_contract(code_hash=b58)) == raw

    def test_use_global_contract_by_account(self):
        raw = _action_bytes(use_global_contract(account_id="publisher.near"))
        assert raw == b"\x0a" + b"\x01" + _string("publisher.near")

    def test_deterministic_state_init_action(self):
        digest = bytes(range(32))
        action = deterministic_state_init(
            code_hash=digest, data={b"b": b"2", b"a": b"1"}, deposit="1 NEAR"
        )
        expected = (
            b"\x0b\x00\x00"  # DeterministicStateInit, state_init V1 tag, CodeHash variant
            + digest
            + _u32(2)  # BTreeMap length
            + _bytes(b"a")
            + _bytes(b"1")
            + _bytes(b"b")
            + _bytes(b"2")
            + _u128(10**24)
        )
        assert _action_bytes(action) == expected


class TestGlobalContractIdentifier:
    def test_exactly_one_reference_required(self):
        with pytest.raises(ValueError, match="exactly one"):
            to_global_contract_identifier()
        with pytest.raises(ValueError, match="exactly one"):
            to_global_contract_identifier(code_hash=bytes(32), account_id="p.near")

    def test_hash_must_be_32_bytes(self):
        with pytest.raises(ValueError, match="32 bytes"):
            to_global_contract_identifier(code_hash=b"short")
        with pytest.raises(ValueError, match="32 bytes"):
            to_global_contract_identifier(code_hash=base58.b58encode(b"short").decode())

    def test_invalid_base58_rejected(self):
        with pytest.raises(ValueError, match="base58"):
            to_global_contract_identifier(code_hash="0OIl-not-base58")

    def test_variants(self):
        by_hash = to_global_contract_identifier(code_hash=bytes(32))
        assert isinstance(by_hash, GlobalContractIdentifier.CodeHash)
        by_account = to_global_contract_identifier(account_id="p.near")
        assert isinstance(by_account, GlobalContractIdentifier.AccountId)
        assert by_account.account_id == "p.near"


class TestGasKeyLayout:
    def test_transfer_to_gas_key(self):
        pk = generate_key().public_key
        raw = _action_bytes(transfer_to_gas_key(pk, "2 NEAR"))
        assert raw == b"\x0c" + b"\x00" + pk.data + _u128(2 * 10**24)

    def test_withdraw_from_gas_key(self):
        pk = generate_key().public_key
        raw = _action_bytes(withdraw_from_gas_key(pk, "0.5 NEAR"))
        assert raw == b"\x0d" + b"\x00" + pk.data + _u128(5 * 10**23)

    def test_gas_key_full_access_permission(self):
        action = add_gas_key(generate_key().public_key, 4)
        # nonce u64(0) + discriminant 3 + GasKeyInfo { balance u128(0), num_nonces u16(4) }
        assert action.access_key.to_borsh() == _u64(0) + b"\x03" + _u128(0) + _u16(4)

    def test_gas_key_function_call_permission(self):
        action = add_gas_key(
            generate_key().public_key, 1024, contract_id="app.near", method_names=["deposit"]
        )
        expected = (
            _u64(0)
            + b"\x02"  # GasKeyFunctionCall
            + _u128(0)  # GasKeyInfo.balance (always 0 on AddKey)
            + _u16(1024)  # GasKeyInfo.num_nonces
            + b"\x00"  # FunctionCallPermission.allowance: None
            + _string("app.near")
            + _u32(1)
            + _string("deposit")
        )
        assert action.access_key.to_borsh() == expected

    def test_full_access_stays_discriminant_1(self):
        action = add_full_access_key(generate_key().public_key)
        assert action.access_key.to_borsh() == _u64(0) + b"\x01"

    def test_add_gas_key_round_trips(self):
        action = add_gas_key(generate_key().public_key, 7, contract_id="app.near")
        assert Action.AddKey.from_borsh(action.to_borsh()) == action


class _NonceHolder(Borsh, BaseModel):
    """pyborsh writes an enum's discriminant only for a union-typed field, so
    variants are encoded through a holder to observe their tags."""

    nonce: AnyTransactionNonce
    mode: AnyNonceMode


class TestTransactionNonceLayout:
    def test_plain_nonce(self):
        raw = _NonceHolder(nonce=TransactionNonce.Nonce(nonce=1), mode=NonceMode.Monotonic())
        assert raw.to_borsh() == b"\x00" + _u64(1) + b"\x00"

    def test_gas_key_nonce(self):
        raw = _NonceHolder(
            nonce=TransactionNonce.GasKeyNonce(nonce=1, nonce_index=2), mode=NonceMode.Strict()
        )
        assert raw.to_borsh() == b"\x01" + _u64(1) + _u16(2) + b"\x01"

    def test_round_trips(self):
        for holder in (
            _NonceHolder(nonce=TransactionNonce.Nonce(nonce=123), mode=NonceMode.Strict()),
            _NonceHolder(
                nonce=TransactionNonce.GasKeyNonce(nonce=456, nonce_index=7),
                mode=NonceMode.Monotonic(),
            ),
        ):
            assert _NonceHolder.from_borsh(holder.to_borsh()) == holder

    def test_u16_lane_index_bounds(self):
        _NonceHolder(
            nonce=TransactionNonce.GasKeyNonce(nonce=1, nonce_index=65535), mode=NonceMode.Strict()
        ).to_borsh()
        with pytest.raises(Exception, match="u16"):
            _NonceHolder(
                nonce=TransactionNonce.GasKeyNonce(nonce=1, nonce_index=65536),
                mode=NonceMode.Strict(),
            ).to_borsh()


class TestTransactionV1Layout:
    def _v1(self, pk, nonce_mode=None):
        return TransactionV1(
            signer_id="alice.near",
            public_key=to_wire_public_key(pk),
            nonce=TransactionNonce.GasKeyNonce(nonce=7, nonce_index=3),
            receiver_id="bob.near",
            block_hash=bytes(range(32)),
            actions=[transfer("1 yocto")],
            nonce_mode=nonce_mode or NonceMode.Strict(),
        )

    def test_exact_bytes_with_version_tag(self):
        pk = generate_key().public_key
        expected = (
            b"\x01"  # Transaction::V1 tag
            + _string("alice.near")
            + b"\x00"
            + pk.data
            + b"\x01"
            + _u64(7)
            + _u16(3)  # GasKeyNonce
            + _string("bob.near")
            + bytes(range(32))
            + _u32(1)
            + b"\x03"
            + _u128(1)  # Transfer
            + b"\x01"  # NonceMode::Strict
        )
        assert self._v1(pk).to_borsh() == expected

    def test_default_nonce_mode_is_monotonic(self):
        pk = generate_key().public_key
        tx = TransactionV1(
            signer_id="alice.near",
            public_key=to_wire_public_key(pk),
            nonce=TransactionNonce.Nonce(nonce=7),
            receiver_id="bob.near",
            block_hash=bytes(32),
            actions=[],
        )
        assert tx.to_borsh().endswith(_u32(0) + b"\x00")

    def test_v0_stays_tag_less(self):
        raw = _tx([transfer("1 yocto")]).to_borsh()
        assert raw[:4] == _u32(2)  # straight into the signer_id length

    def test_round_trip_and_version_check(self):
        pk = generate_key().public_key
        tx = self._v1(pk)
        assert TransactionV1.from_borsh(tx.to_borsh()) == tx
        with pytest.raises(Exception, match="version"):
            TransactionV1.from_borsh(b"\x02" + tx.to_borsh()[1:])

    def test_sign_transaction_hashes_tagged_bytes(self):
        kp = generate_key()
        signer = KeyPairSigner("alice.near", kp)
        tx = self._v1(kp.public_key)
        tx_hash_b58, signed_raw = sign_transaction(tx, signer)
        digest = base58.b58decode(tx_hash_b58)
        assert digest == hashlib.sha256(tx.to_borsh()).digest()
        assert tx.to_borsh()[0] == 1
        # signed = tagged tx bytes ++ Signature enum, plain concatenation
        assert signed_raw[: len(tx.to_borsh())] == tx.to_borsh()
        assert signed_raw[len(tx.to_borsh())] == 0  # ed25519
        assert len(signed_raw) == len(tx.to_borsh()) + 1 + 64
        signed = SignedTransactionV1.from_borsh(signed_raw)
        assert signed.transaction == tx
        assert kp.public_key.verify(signed.signature.data, digest)


class TestDelegateV2Layout:
    def test_versioned_payload_carries_tag(self):
        signer = KeyPairSigner("alice.near", generate_key())
        payload = _signed_v2(signer).delegate_action
        raw = payload.to_borsh()
        assert raw[0] == 0  # VersionedDelegateActionPayload::V2
        assert raw[1:] == payload.v2.to_borsh()
        assert VersionedDelegateActionPayload.from_borsh(raw) == payload
        with pytest.raises(Exception, match="version"):
            VersionedDelegateActionPayload.from_borsh(b"\x01" + raw[1:])

    def test_signing_hash_uses_nep611_prefix_over_tagged_payload(self):
        signer = KeyPairSigner("alice.near", generate_key())
        payload = _signed_v2(signer).delegate_action
        prefix = ((1 << 30) + 611).to_bytes(4, "little")
        assert prefix == b"\x63\x02\x00\x40"
        expected = hashlib.sha256(prefix + b"\x00" + payload.v2.to_borsh()).digest()
        assert delegate_action_v2_signing_hash(payload) == expected

    def test_v2_domain_is_distinct_from_v1(self):
        assert NEP611_DELEGATE_V2_PREFIX == 1073742435
        assert NEP366_DELEGATE_PREFIX == 1073742190

    def test_action_layout(self):
        signer = KeyPairSigner("alice.near", generate_key())
        signed = _signed_v2(signer)
        raw = _action_bytes(signed)
        assert raw[:2] == b"\x0e\x00"  # DelegateV2, then the V2 payload tag
        assert raw[2:].startswith(_string("alice.near") + _string("bob.near"))
        assert raw.endswith(b"\x00" + signed.signature.data)

    def test_plain_nonce_variant(self):
        signer = KeyPairSigner("alice.near", generate_key())
        signed = _signed_v2(signer, nonce=TransactionNonce.Nonce(nonce=9))
        inner = signed.delegate_action.v2.to_borsh()
        # after sender, receiver and the one-action vec comes the nonce enum
        offset = len(_string("alice.near") + _string("bob.near") + _u32(1) + b"\x03" + _u128(1))
        assert inner[offset : offset + 9] == b"\x00" + _u64(9)


class TestNonDelegateActionGuard:
    def test_v1_delegate_cannot_nest_either_version(self):
        signer = KeyPairSigner("alice.near", generate_key())
        v2 = _signed_v2(signer)
        v1 = sign_delegate_action(
            DelegateAction(
                sender_id="alice.near",
                receiver_id="bob.near",
                actions=[transfer("1 yocto")],
                nonce=1,
                max_block_height=2,
                public_key=to_wire_public_key(signer.public_key),
            ),
            signer,
        )
        for nested in (v1, v2):
            with pytest.raises(ValidationError):
                DelegateAction(
                    sender_id="alice.near",
                    receiver_id="bob.near",
                    actions=[nested],
                    nonce=1,
                    max_block_height=2,
                    public_key=to_wire_public_key(signer.public_key),
                )
            with pytest.raises(ValidationError):
                DelegateActionV2(
                    sender_id="alice.near",
                    receiver_id="bob.near",
                    actions=[nested],
                    nonce=TransactionNonce.Nonce(nonce=1),
                    max_block_height=2,
                    public_key=to_wire_public_key(signer.public_key),
                )

    def test_new_actions_keep_discriminants_inside_a_delegate(self):
        pk = generate_key().public_key
        delegate = DelegateActionV2(
            sender_id="alice.near",
            receiver_id="bob.near",
            actions=[
                publish_contract(b"w"),
                use_global_contract(account_id="p.near"),
                deterministic_state_init(account_id="p.near", deposit="1 yocto"),
                transfer_to_gas_key(pk, "1 yocto"),
                withdraw_from_gas_key(pk, "1 yocto"),
            ],
            nonce=TransactionNonce.Nonce(nonce=1),
            max_block_height=2,
            public_key=to_wire_public_key(pk),
        )
        raw = delegate.to_borsh()
        body = raw[len(_string("alice.near") + _string("bob.near")) + 4 :]
        assert body[0] == 9
        assert DelegateActionV2.from_borsh(raw) == delegate


# ---------------------------------------------------------------------------
# Cross-language golden vectors, generated with near-kit-ts (src/core/schema.ts,
# @zorsh/zorsh 0.5.0): serializeDelegateActionV2 / signedDelegateV2 /
# encodeSignedDelegateActionV2 / serializeTransactionV1 /
# serializeSignedTransactionV1 for the fixed inputs reproduced below.
# ---------------------------------------------------------------------------

_TS_PK = bytes([8]) * 32
_TS_SIG = bytes([12]) * 64
TS_V2_PAYLOAD_HEX = (
    "00"  # VersionedDelegateActionPayload::V2
    "0a000000616c6963652e6e656172"  # alice.near
    "08000000626f622e6e656172"  # bob.near
    "02000000"  # 2 actions
    "03e8030000000000000000000000000000"  # Transfer 1000 yocto
    "020500000067726565740e0000007b226e616d65223a22626f62227d"  # FunctionCall greet(args)
    "00e057eb481b0000"  # gas 30 Tgas
    "01000000000000000000000000000000"  # deposit 1 yocto
    "010500000000000000" + "0200"  # GasKeyNonce { nonce: 5, nonce_index: 2 }
    "e803000000000000"  # max_block_height 1000
    "00" + _TS_PK.hex()  # ed25519 public key
)
TS_V2_SIGNING_HASH = "107f7d2cc1bf1bea897d60c177e7757f18f219ff95ac0cf9ab05e5f9f36807c1"
TS_V2_ENCODED_B64 = (
    "AAoAAABhbGljZS5uZWFyCAAAAGJvYi5uZWFyAgAAAAPoAwAAAAAAAAAAAAAAAAAAAgUAAABncmVldA4AAAB7Im5h"
    "bWUiOiJib2IifQDgV+tIGwAAAQAAAAAAAAAAAAAAAAAAAAEFAAAAAAAAAAIA6AMAAAAAAAAACAgICAgICAgICAgI"
    "CAgICAgICAgICAgICAgICAgICAgADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw"
    "MDAwMDAwMDAwMDAwMDAwMDAwMDA=="
)
TS_TX_V1_HEX = (
    "01"  # Transaction::V1 tag
    "0a000000616c6963652e6e656172"
    "00" + _TS_PK.hex() + "012a00000000000000" + "0300"  # GasKeyNonce { 42, 3 }
    "08000000626f622e6e656172" + ("05" * 32) + "01000000"
    "03e8030000000000000000000000000000"  # Transfer 1000 yocto
    "01"  # NonceMode::Strict
)
TS_TX_V1_HASH_B58 = "CTiJAvymxtKdfAWh7uq1N8pSiXxH4tk7FpjvhQrhFdyq"


class TestNearKitTsGoldenVectors:
    def _payload(self):
        return VersionedDelegateActionPayload(
            v2=DelegateActionV2(
                sender_id="alice.near",
                receiver_id="bob.near",
                actions=[
                    transfer("1000 yocto"),
                    function_call("greet", {"name": "bob"}, gas="30 Tgas", deposit="1 yocto"),
                ],
                nonce=TransactionNonce.GasKeyNonce(nonce=5, nonce_index=2),
                max_block_height=1000,
                public_key=PublicKeyWire.Ed25519(data=_TS_PK),
            )
        )

    def test_delegate_v2_signing_bytes_and_hash(self):
        payload = self._payload()
        assert payload.to_borsh().hex() == TS_V2_PAYLOAD_HEX
        assert delegate_action_v2_signing_hash(payload).hex() == TS_V2_SIGNING_HASH

    def test_delegate_v2_action_and_transport_encoding(self):
        action = Action.DelegateV2(
            delegate_action=self._payload(), signature=SignatureWire.Ed25519(data=_TS_SIG)
        )
        assert _action_bytes(action).hex() == "0e" + TS_V2_PAYLOAD_HEX + "00" + _TS_SIG.hex()
        assert encode_signed_delegate(action) == TS_V2_ENCODED_B64
        assert base64.b64decode(TS_V2_ENCODED_B64) == action.to_borsh()

    def test_transaction_v1_bytes_hash_and_signed_form(self):
        tx = TransactionV1(
            signer_id="alice.near",
            public_key=PublicKeyWire.Ed25519(data=_TS_PK),
            nonce=TransactionNonce.GasKeyNonce(nonce=42, nonce_index=3),
            receiver_id="bob.near",
            block_hash=bytes([5]) * 32,
            actions=[transfer("1000 yocto")],
            nonce_mode=NonceMode.Strict(),
        )
        assert tx.to_borsh().hex() == TS_TX_V1_HEX
        digest = hashlib.sha256(tx.to_borsh()).digest()
        assert base58.b58encode(digest).decode() == TS_TX_V1_HASH_B58
        signed = SignedTransactionV1(transaction=tx, signature=SignatureWire.Ed25519(data=_TS_SIG))
        assert signed.to_borsh().hex() == TS_TX_V1_HEX + "00" + _TS_SIG.hex()
