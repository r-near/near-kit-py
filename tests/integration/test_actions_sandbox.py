"""nearcore 2.13 action parity against a real sandbox: global contracts,
NEP-616 deterministic accounts and gas keys (V1 transactions, strict nonces).

The node is the oracle: a wrong discriminant, an unsorted state-init map or a
mis-hashed V1 transaction would be rejected outright, so every passing test
here is a byte-level proof.
"""

import base64
import hashlib

import base58
import pytest

from near import (
    AccessKeyNotFoundError,
    Amount,
    AsyncNear,
    ContractNotFoundError,
    InsufficientBalanceError,
    Near,
    RpcError,
    add_full_access_key,
    add_gas_key,
    create_account,
    derive_deterministic_account_id,
    deterministic_state_init,
    function_call,
    generate_key,
    is_deterministic_account_id,
    publish_contract,
    transfer,
    transfer_to_gas_key,
    use_global_contract,
    withdraw_from_gas_key,
)
from near.keys import KeyPairSigner

pytestmark = pytest.mark.integration


def _funded(near: Near, name: str, deposit: str = "10 NEAR") -> KeyPairSigner:
    account_id = f"{name}.{near.signer.account_id}"
    key = generate_key()
    near.send_transaction(
        account_id,
        actions=[create_account(), transfer(deposit), add_full_access_key(key.public_key)],
        wait_until="FINAL",
    )
    return KeyPairSigner(account_id=account_id, key_pair=key)


def _gas_key_owner(near: Near, name: str, num_nonces: int = 4) -> tuple[KeyPairSigner, Near]:
    """An account with a funded full-access gas key; returns (gas-key signer, client)."""
    owner = _funded(near, name, "20 NEAR")
    gas_key = generate_key()
    near.with_signer(owner).send_transaction(
        owner.account_id,
        [
            add_gas_key(gas_key.public_key, num_nonces),
            transfer_to_gas_key(gas_key.public_key, "2 NEAR"),
        ],
        wait_until="FINAL",
    )
    signer = KeyPairSigner(account_id=owner.account_id, key_pair=gas_key)
    return signer, near.with_signer(signer)


@pytest.fixture(scope="module")
def publisher(near, run_id, guestbook_wasm):
    """An account that published the guestbook both by account ID and by code hash."""
    signer = _funded(near, f"gpub-{run_id}", "40 NEAR")
    as_publisher = near.with_signer(signer)
    as_publisher.send_transaction(
        signer.account_id, [publish_contract(guestbook_wasm)], wait_until="FINAL"
    )
    as_publisher.send_transaction(
        signer.account_id,
        [publish_contract(guestbook_wasm, identified_by="hash")],
        wait_until="FINAL",
    )
    return signer


@pytest.fixture(scope="module")
def code_hash(guestbook_wasm) -> str:
    return base58.b58encode(hashlib.sha256(guestbook_wasm).digest()).decode()


class TestGlobalContracts:
    def test_publish_and_use_by_account(
        self, near, publisher, code_hash, unique_id, guestbook_wasm
    ):
        published = near.global_contract(account_id=publisher.account_id)
        assert published.code == guestbook_wasm
        assert published.hash == code_hash

        user = _funded(near, unique_id)
        as_user = near.with_signer(user)
        as_user.send_transaction(
            user.account_id,
            [use_global_contract(account_id=publisher.account_id)],
            wait_until="FINAL",
        )
        assert near.account(user.account_id).global_contract_account_id == publisher.account_id
        as_user.call(
            user.account_id,
            "add_message",
            {"text": "global"},
            deposit="1 yocto",
            wait_until="FINAL",
        )
        assert any(m["text"] == "global" for m in near.view(user.account_id, "get_messages"))
        # The account runs the published code even though it stores none itself.
        assert near.contract_code(user.account_id).code == guestbook_wasm
        assert near.contract_code(user.account_id, block="final").code == guestbook_wasm

    def test_publish_and_use_by_hash(self, near, publisher, code_hash, unique_id, guestbook_wasm):
        published = near.global_contract(code_hash=code_hash)
        assert published.code == guestbook_wasm
        assert published.hash == code_hash

        user = _funded(near, unique_id)
        as_user = near.with_signer(user)
        as_user.send_transaction(
            user.account_id, [use_global_contract(code_hash=code_hash)], wait_until="FINAL"
        )
        assert near.account(user.account_id).global_contract_hash == code_hash
        as_user.call(
            user.account_id,
            "add_message",
            {"text": "by hash"},
            deposit="1 yocto",
            wait_until="FINAL",
        )
        assert any(m["text"] == "by hash" for m in near.view(user.account_id, "get_messages"))

    def test_exists_and_not_found(self, near, publisher, code_hash):
        assert near.global_contract_exists(account_id=publisher.account_id)
        assert near.global_contract_exists(code_hash=code_hash)
        assert not near.global_contract_exists(account_id="nobody.sandbox")
        assert not near.global_contract_exists(code_hash=bytes(32))
        # block= works like view(): a finality or a concrete height.
        assert near.global_contract_exists(account_id=publisher.account_id, block="final")
        height = near.rpc("block", {"finality": "final"})["header"]["height"]
        assert near.global_contract(code_hash=code_hash, block=height).hash == code_hash
        with pytest.raises(ContractNotFoundError) as exc_info:
            near.global_contract(account_id="nobody.sandbox")
        assert exc_info.value.code == "CONTRACT_NOT_FOUND"
        assert "nobody.sandbox" in exc_info.value.identifier

    def test_contract_code_of_plain_account_raises(self, near):
        with pytest.raises(ContractNotFoundError, match="account sandbox"):
            near.contract_code("sandbox")


class TestDeterministicAccounts:
    def test_state_init_creates_the_derived_account(self, near, publisher, guestbook_wasm):
        # Keys inserted out of order, and "zeta" > "alpha" bytewise but not as
        # JS-style stringified arrays: the node accepting the derived ID proves
        # the map is encoded canonically.
        action = deterministic_state_init(
            account_id=publisher.account_id,
            data={b"zeta": b"last", b"alpha": b"first"},
            deposit="2 NEAR",
        )
        derived = derive_deterministic_account_id(action.state_init)
        assert is_deterministic_account_id(derived)
        assert not near.account_exists(derived)

        near.send_transaction(derived, [action], wait_until="FINAL")

        account = near.account(derived)
        assert account.global_contract_account_id == publisher.account_id
        assert near.contract_code(derived).code == guestbook_wasm
        state = near.rpc(
            "query",
            {
                "request_type": "view_state",
                "account_id": derived,
                "prefix_base64": "",
                "finality": "final",
            },
        )
        stored = {
            (base64.b64decode(entry["key"]), base64.b64decode(entry["value"]))
            for entry in state["values"]
        }
        assert stored == {(b"alpha", b"first"), (b"zeta", b"last")}

    def test_by_code_hash(self, near, code_hash):
        action = deterministic_state_init(code_hash=code_hash, deposit="1 NEAR")
        derived = derive_deterministic_account_id(action.state_init)
        near.send_transaction(derived, [action], wait_until="FINAL")
        assert near.account(derived).global_contract_hash == code_hash

    def test_wrong_derivation_is_rejected(self, near, publisher):
        action = deterministic_state_init(
            account_id=publisher.account_id, data={b"k": b"v"}, deposit="2 NEAR"
        )
        derived = derive_deterministic_account_id(action.state_init)
        different_state = deterministic_state_init(
            account_id=publisher.account_id, data={b"k": b"w"}, deposit="2 NEAR"
        )
        with pytest.raises(RpcError) as exc_info:
            near.send_transaction(derived, [different_state], wait_until="FINAL")
        assert exc_info.value.code == "INVALID_TRANSACTION"
        assert not near.account_exists(derived)


class TestGasKeys:
    def test_lifecycle(self, near, unique_id):
        owner = _funded(near, unique_id, "20 NEAR")
        as_owner = near.with_signer(owner)
        gas_key = generate_key()

        as_owner.send_transaction(
            owner.account_id, [add_gas_key(gas_key.public_key, num_nonces=4)], wait_until="FINAL"
        )
        view = near.access_key(owner.account_id, gas_key.public_key)
        assert view.is_gas_key
        assert view.is_full_access  # GasKeyFullAccess is unrestricted, like FullAccess
        assert view.gas_key_balance == Amount("0 NEAR")

        as_owner.send_transaction(
            owner.account_id,
            [transfer_to_gas_key(gas_key.public_key, "2 NEAR")],
            wait_until="FINAL",
        )
        assert near.access_key(owner.account_id, gas_key.public_key).gas_key_balance == Amount(
            "2 NEAR"
        )
        lanes = near.gas_key_nonces(owner.account_id, gas_key.public_key)
        assert len(lanes) == 4
        assert near.gas_key_nonces(owner.account_id, gas_key.public_key, block="final") == lanes

        recipient = _funded(near, f"{unique_id}r", "1 NEAR")
        as_gas = near.with_signer(KeyPairSigner(owner.account_id, gas_key))
        owner_before = near.balance(owner.account_id)
        result = as_gas.send_transaction(
            recipient.account_id, [transfer("1 NEAR")], gas_key_index=2, wait_until="FINAL"
        )
        assert result.transaction["nonce_index"] == 2
        assert near.balance(recipient.account_id) == Amount("2 NEAR")
        # The deposit came out of the account, the gas out of the key.
        assert owner_before - near.balance(owner.account_id) == Amount("1 NEAR")
        assert near.access_key(owner.account_id, gas_key.public_key).gas_key_balance < Amount(
            "2 NEAR"
        )
        after = near.gas_key_nonces(owner.account_id, gas_key.public_key)
        assert after[2] == lanes[2] + 1
        assert [after[i] for i in (0, 1, 3)] == [lanes[i] for i in (0, 1, 3)]

        # Same lane again (served from the nonce cache) and an independent lane.
        as_gas.send_transaction(
            recipient.account_id, [transfer("0.5 NEAR")], gas_key_index=2, wait_until="FINAL"
        )
        as_gas.send_transaction(
            recipient.account_id, [transfer("0.5 NEAR")], gas_key_index=0, wait_until="FINAL"
        )
        final = near.gas_key_nonces(owner.account_id, gas_key.public_key)
        assert final[2] == lanes[2] + 2
        assert final[0] == lanes[0] + 1

        key_before = near.access_key(owner.account_id, gas_key.public_key).gas_key_balance
        as_owner.send_transaction(
            owner.account_id,
            [withdraw_from_gas_key(gas_key.public_key, "0.5 NEAR")],
            wait_until="FINAL",
        )
        key_after = near.access_key(owner.account_id, gas_key.public_key).gas_key_balance
        assert key_before - key_after == Amount("0.5 NEAR")

        # Reads default to the optimistic head, so a send that is executed but
        # not yet final is already visible to the next read.
        as_gas.send_transaction(recipient.account_id, [transfer("0.1 NEAR")], gas_key_index=3)
        assert near.gas_key_nonces(owner.account_id, gas_key.public_key)[3] == lanes[3] + 1

    def test_underfunded_gas_key_is_a_typed_error(self, near, unique_id):
        owner = _funded(near, unique_id)
        gas_key = generate_key()
        near.with_signer(owner).send_transaction(
            owner.account_id,
            [
                add_gas_key(gas_key.public_key, 1),
                transfer_to_gas_key(gas_key.public_key, "1 yocto"),
            ],
            wait_until="FINAL",
        )
        as_gas = near.with_signer(KeyPairSigner(owner.account_id, gas_key))
        with pytest.raises(InsufficientBalanceError, match="gas key of") as exc_info:
            as_gas.send_transaction("sandbox", [transfer("1 yocto")], gas_key_index=0)
        assert exc_info.value.available == 1
        assert exc_info.value.required > 1

    def test_gas_key_needs_a_lane(self, near, unique_id):
        _, as_gas = _gas_key_owner(near, unique_id)
        # A gas key cannot sign the classic V0 transaction: the node wants a lane.
        with pytest.raises(RpcError) as exc_info:
            as_gas.send_transaction("sandbox", [transfer("1 yocto")])
        assert exc_info.value.code == "INVALID_TRANSACTION"
        # A lane the key never allocated is refused before anything is sent.
        with pytest.raises(ValueError, match="4 nonce lanes"):
            as_gas.send_transaction("sandbox", [transfer("1 yocto")], gas_key_index=4)

    def test_function_call_gas_key(self, near, unique_id, guestbook):
        owner = _funded(near, unique_id, "20 NEAR")
        as_owner = near.with_signer(owner)
        gas_key = generate_key()
        as_owner.send_transaction(
            owner.account_id,
            [
                add_gas_key(
                    gas_key.public_key, 2, contract_id=guestbook, method_names=["add_message"]
                ),
                transfer_to_gas_key(gas_key.public_key, "1 NEAR"),
            ],
            wait_until="FINAL",
        )
        assert not near.access_key(owner.account_id, gas_key.public_key).is_full_access
        as_gas = near.with_signer(KeyPairSigner(owner.account_id, gas_key))
        as_gas.send_transaction(
            guestbook,
            [function_call("add_message", {"text": "gas key"})],
            gas_key_index=1,
            wait_until="FINAL",
        )
        assert any(m["text"] == "gas key" for m in near.view(guestbook, "get_messages"))
        with pytest.raises(RpcError) as exc_info:
            as_gas.send_transaction("sandbox", [transfer("1 yocto")], gas_key_index=0)
        assert exc_info.value.code == "INVALID_TRANSACTION"

    def test_missing_gas_key_raises(self, near):
        with pytest.raises(AccessKeyNotFoundError) as exc_info:
            near.gas_key_nonces("sandbox", generate_key().public_key)
        assert exc_info.value.account_id == "sandbox"

    def test_strict_nonce_round_trip(self, near, unique_id):
        owner = _funded(near, unique_id)
        as_owner = near.with_signer(owner)
        strict = [
            as_owner.send_transaction(
                "sandbox", [transfer("1 yocto")], strict_nonce=True, wait_until="FINAL"
            )
            for _ in range(2)
        ]
        # The node recorded strict mode (its view omits nonce_mode when monotonic).
        assert [r.transaction["nonce_mode"] for r in strict] == ["strict", "strict"]
        # Back to monotonic mode on the same key: the cache is in step with the chain.
        monotonic = as_owner.send("sandbox", "1 yocto", wait_until="FINAL")
        assert "nonce_mode" not in monotonic.transaction
        assert len({r.transaction_hash for r in [*strict, monotonic]}) == 3

        gas_signer, as_gas = _gas_key_owner(near, f"{unique_id}g")
        lanes = near.gas_key_nonces(gas_signer.account_id, gas_signer.public_key)
        for _ in range(2):
            as_gas.send_transaction(
                "sandbox",
                [transfer("1 yocto")],
                gas_key_index=1,
                strict_nonce=True,
                wait_until="FINAL",
            )
        after = near.gas_key_nonces(gas_signer.account_id, gas_signer.public_key)
        assert after[1] == lanes[1] + 2


class TestAsyncSurface:
    async def test_gas_key_send(self, anear, unique_id, sandbox_url):
        owner_id = f"{unique_id}ao.sandbox"
        owner_key, gas_key = generate_key(), generate_key()
        await anear.send_transaction(
            owner_id,
            [
                create_account(),
                transfer("20 NEAR"),
                add_full_access_key(owner_key.public_key),
                add_gas_key(gas_key.public_key, 3),
            ],
            wait_until="FINAL",
        )
        await anear.with_signer(KeyPairSigner(owner_id, owner_key)).send_transaction(
            owner_id, [transfer_to_gas_key(gas_key.public_key, "2 NEAR")], wait_until="FINAL"
        )
        lanes = await anear.gas_key_nonces(owner_id, gas_key.public_key)
        assert len(lanes) == 3
        assert (await anear.access_key(owner_id, gas_key.public_key)).gas_key_balance == Amount(
            "2 NEAR"
        )

        as_gas = anear.with_signer(KeyPairSigner(owner_id, gas_key))
        result = await as_gas.send_transaction(
            "sandbox", [transfer("1 yocto")], gas_key_index=1, strict_nonce=True, wait_until="FINAL"
        )
        assert result.transaction["nonce_index"] == 1
        assert result.transaction["nonce_mode"] == "strict"
        after = await anear.gas_key_nonces(owner_id, gas_key.public_key, block="final")
        assert after[1] == lanes[1] + 1
        assert after[2] == lanes[2]

        assert not await anear.global_contract_exists(account_id=owner_id)
        with pytest.raises(ContractNotFoundError):
            await anear.contract_code(owner_id)
        with pytest.raises(AccessKeyNotFoundError) as exc_info:
            await anear.gas_key_nonces(owner_id, owner_key.public_key)
        assert exc_info.value.account_id == owner_id

    async def test_global_contract_reads(
        self, publisher, code_hash, guestbook, guestbook_wasm, sandbox_url
    ):
        async with AsyncNear(rpc_url=sandbox_url) as anear:
            assert (
                await anear.global_contract(account_id=publisher.account_id)
            ).code == guestbook_wasm
            assert (await anear.global_contract(code_hash=code_hash)).hash == code_hash
            assert await anear.global_contract_exists(code_hash=code_hash)
            assert await anear.global_contract_exists(code_hash=code_hash, block="final")
            assert not await anear.global_contract_exists(code_hash=bytes(32))
            # A locally deployed contract reads back the same way.
            assert (await anear.contract_code(guestbook)).code == guestbook_wasm
