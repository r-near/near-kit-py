import hashlib
from typing import cast

import base58
import pytest

from near.actions import (
    add_full_access_key,
    add_function_call_key,
    create_account,
    delete_account,
    delete_key,
    deploy_contract,
    function_call,
    stake,
    transfer,
)
from near.errors import InvalidKeyError
from near.keys import KeyType, PublicKey, generate_key, key_from_test_seed
from near.wire import (
    DelegateAction,
    SignedTransaction,
    Transaction,
    delegate_action_signing_hash,
    sign_transaction,
    to_wire_public_key,
    to_wire_signature,
)


def _u32(n: int) -> bytes:
    return n.to_bytes(4, "little")


def _u64(n: int) -> bytes:
    return n.to_bytes(8, "little")


def _u128(n: int) -> bytes:
    return n.to_bytes(16, "little")


def _string(s: str) -> bytes:
    raw = s.encode()
    return _u32(len(raw)) + raw


class TestByteLayout:
    """Hand-computed Borsh layouts. If these fail, every signature is wrong."""

    def test_transfer_transaction_exact_bytes(self):
        tx = Transaction(
            signer_id="alice.near",
            public_key=to_wire_public_key(key_from_test_seed("test").public_key),
            nonce=1,
            receiver_id="bob.near",
            block_hash=bytes(32),
            actions=[transfer("1 yocto")],
        )
        pk = key_from_test_seed("test").public_key.data
        expected = (
            _string("alice.near")
            + b"\x00"  # PublicKey discriminant: ed25519
            + pk
            + _u64(1)
            + _string("bob.near")
            + bytes(32)
            + _u32(1)  # 1 action
            + b"\x03"  # Action discriminant: Transfer
            + _u128(1)
        )
        assert tx.to_borsh() == expected

    def test_function_call_action_bytes(self):
        action = function_call("greet", {"name": "bob"}, gas="30 Tgas", deposit="1 yocto")
        tx = Transaction(
            signer_id="a.near",
            public_key=to_wire_public_key(generate_key().public_key),
            nonce=0,
            receiver_id="b.near",
            block_hash=bytes(32),
            actions=[action],
        )
        raw = tx.to_borsh()
        args = b'{"name":"bob"}'
        expected_action = (
            b"\x02"  # FunctionCall discriminant
            + _string("greet")
            + _u32(len(args))
            + args
            + _u64(30 * 10**12)
            + _u128(1)
        )
        assert raw.endswith(expected_action)

    def test_action_discriminants(self):
        kp = generate_key()
        cases = [
            (create_account(), 0),
            (deploy_contract(b"\x00asm"), 1),
            (function_call("m"), 2),
            (transfer("1 yocto"), 3),
            (stake("1 yocto", kp.public_key), 4),
            (add_full_access_key(kp.public_key), 5),
            (delete_key(kp.public_key), 6),
            (delete_account("bob.near"), 7),
        ]
        for action, discriminant in cases:
            tx = Transaction(
                signer_id="aa",
                public_key=to_wire_public_key(kp.public_key),
                nonce=0,
                receiver_id="bb",
                block_hash=bytes(32),
                actions=[action],
            )
            raw = tx.to_borsh()
            # Prefix before actions: 4+2 + 33 + 8 + 4+2 + 32 + 4 = 89 bytes.
            assert raw[89] == discriminant, f"{type(action).__name__} != {discriminant}"

    def test_full_access_key_permission_bytes(self):
        action = add_full_access_key(generate_key().public_key)
        raw_suffix = action.access_key.to_borsh()
        # nonce u64(0) + permission discriminant 1 (FullAccess), empty struct
        assert raw_suffix == _u64(0) + b"\x01"

    def test_function_call_key_permission_bytes(self):
        action = add_function_call_key(
            generate_key().public_key, "app.near", ["deposit"], allowance="1 NEAR"
        )
        raw = action.access_key.to_borsh()
        expected = (
            _u64(0)
            + b"\x00"  # FunctionCall permission discriminant
            + b"\x01"  # Option: Some
            + _u128(10**24)
            + _string("app.near")
            + _u32(1)
            + _string("deposit")
        )
        assert raw == expected

    def test_no_allowance_encodes_option_none(self):
        action = add_function_call_key(generate_key().public_key, "app.near")
        raw = action.access_key.to_borsh()
        assert raw == _u64(0) + b"\x00" + b"\x00" + _string("app.near") + _u32(0)


class TestSigning:
    def test_sign_transaction_round_trip(self):
        kp = key_from_test_seed("test")
        tx = Transaction(
            signer_id="test.near",
            public_key=to_wire_public_key(kp.public_key),
            nonce=7,
            receiver_id="bob.near",
            block_hash=bytes(range(32)),
            actions=[transfer("1 NEAR")],
        )
        tx_hash_b58, signed_raw = sign_transaction(tx, _signer("test.near", kp))

        assert base58.b58decode(tx_hash_b58) == hashlib.sha256(tx.to_borsh()).digest()

        signed = SignedTransaction.from_borsh(signed_raw)
        assert signed.transaction == tx
        assert kp.public_key.verify(signed.signature.data, base58.b58decode(tx_hash_b58))

    def test_delegate_signing_hash_uses_nep461_prefix(self):
        kp = generate_key()
        delegate = DelegateAction(
            sender_id="alice.near",
            receiver_id="bob.near",
            actions=[transfer("1 yocto")],
            nonce=1,
            max_block_height=100,
            public_key=to_wire_public_key(kp.public_key),
        )
        prefix = ((1 << 30) + 366).to_bytes(4, "little")
        expected = hashlib.sha256(prefix + delegate.to_borsh()).digest()
        assert delegate_action_signing_hash(delegate) == expected

    def test_borsh_round_trip_all_actions(self):
        kp = generate_key()
        tx = Transaction(
            signer_id="alice.near",
            public_key=to_wire_public_key(kp.public_key),
            nonce=1,
            receiver_id="bob.near",
            block_hash=bytes(32),
            actions=[
                create_account(),
                deploy_contract(b"wasm-bytes"),
                function_call("init", {"a": 1}, deposit="0.1 NEAR"),
                transfer("2.5 NEAR"),
                stake("1 NEAR", kp.public_key),
                add_full_access_key(kp.public_key),
                add_function_call_key(kp.public_key, "app.near", ["m"], allowance="1 NEAR"),
                delete_key(kp.public_key),
                delete_account("bob.near"),
            ],
        )
        assert Transaction.from_borsh(tx.to_borsh()) == tx


class TestWireConversions:
    def test_unknown_curve_rejected(self):
        # A custom Signer could report a curve this library has no wire format
        # for; the conversion must fail loudly rather than corrupt bytes.
        fake_type = cast("KeyType", 99)
        with pytest.raises(InvalidKeyError, match="Unsupported key type"):
            to_wire_public_key(PublicKey(fake_type, b""))
        with pytest.raises(InvalidKeyError, match="Unsupported key type"):
            to_wire_signature(fake_type, b"sig")


def _signer(account_id: str, key_pair):
    from near.keys import KeyPairSigner

    return KeyPairSigner(account_id=account_id, key_pair=key_pair)
