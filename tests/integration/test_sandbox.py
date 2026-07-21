"""End-to-end tests against a real nearcore sandbox.

The node is the oracle: if any Borsh byte were wrong, signature verification
would fail and every transaction here would be rejected.
"""

import asyncio

import pytest

import near as near_module
from near import (
    Amount,
    ContractPanicError,
    Near,
    add_full_access_key,
    create_account,
    generate_key,
    transfer,
)
from near.delegate import encode_signed_delegate
from near.keys import KeyPairSigner, MlDsa65KeyPair

pytestmark = pytest.mark.integration


def _make_account(near: Near, name: str, deposit: str = "10 NEAR") -> KeyPairSigner:
    """Create a funded subaccount of the root and return its signer."""
    account_id = f"{name}.{near.signer.account_id}"
    key = generate_key()
    near.send_transaction(
        account_id,
        actions=[create_account(), transfer(deposit), add_full_access_key(key.public_key)],
        wait_until="FINAL",
    )
    return KeyPairSigner(account_id=account_id, key_pair=key)


class TestBasics:
    def test_status_and_root_account(self, near):
        assert near.account_exists("sandbox")
        assert near.balance("sandbox") > Amount("1000 NEAR")

    def test_send_money(self, near, unique_id):
        alice = _make_account(near, unique_id)
        before = near.balance(alice.account_id)
        near.send(alice.account_id, "2.5 NEAR", wait_until="FINAL")
        after = near.balance(alice.account_id)
        assert after - before == Amount("2.5 NEAR")

    def test_multi_action_account_creation(self, near, unique_id):
        signer = _make_account(near, unique_id, deposit="3 NEAR")
        account = near.account(signer.account_id)
        assert account.amount == Amount("3 NEAR")
        keys = near.access_keys(signer.account_id)
        assert [k.public_key for k in keys] == [str(signer.public_key)]
        assert keys[0].access_key.is_full_access

    def test_with_signer_sends_from_other_account(self, near, unique_id):
        alice = _make_account(near, unique_id)
        as_alice = near.with_signer(alice)
        as_alice.send("sandbox", "1 NEAR", wait_until="FINAL")
        assert near.balance(alice.account_id) < Amount("9 NEAR")

    def test_account_not_found(self, near):
        assert not near.account_exists("definitely-not-here.sandbox")

    def test_transaction_status(self, near):
        result = near.send("sandbox", "1 yocto", wait_until="FINAL")
        assert result.transaction_hash
        looked_up = near.transaction_status(result.transaction_hash)
        assert looked_up.transaction_hash == result.transaction_hash

    def test_rpc_escape_hatch(self, near):
        block = near.rpc("block", {"finality": "final"})
        assert block["header"]["height"] > 0

    def test_module_one_shots(self):
        assert near_module.balance("sandbox", rpc_url="http://localhost:3030") > 0
        assert near_module.account_exists("sandbox", rpc_url="http://localhost:3030")


class TestContracts:
    def test_call_and_view(self, near, guestbook):
        near.call(
            guestbook,
            "add_message",
            {"text": "hello from python"},
            deposit="0.1 NEAR",
            wait_until="FINAL",
        )
        messages = near.view(guestbook, "get_messages")
        assert any(m["text"] == "hello from python" for m in messages)

    def test_call_returns_logs_and_result(self, near, guestbook):
        result = near.call(guestbook, "add_message", {"text": "logged"}, deposit="1 yocto")
        assert result.transaction_hash

    def test_missing_method_panics(self, near, guestbook):
        with pytest.raises(ContractPanicError) as exc_info:
            near.call(guestbook, "no_such_method", {})
        assert "MethodResolveError" in exc_info.value.panic or "MethodNotFound" in str(
            exc_info.value
        )

    def test_view_missing_method_raises(self, near, guestbook):
        with pytest.raises(ContractPanicError):
            near.view(guestbook, "no_such_view")


class TestAsync:
    async def test_basic_flow(self, anear, unique_id):
        account_id = f"{unique_id}a.sandbox"
        key = generate_key()
        await anear.send_transaction(
            account_id,
            actions=[create_account(), transfer("5 NEAR"), add_full_access_key(key.public_key)],
            wait_until="FINAL",
        )
        assert await anear.account_exists(account_id)
        assert await anear.balance(account_id) == Amount("5 NEAR")

    async def test_concurrent_sends_share_nonce_cache(self, anear, unique_id):
        alice = KeyPairSigner(f"{unique_id}c.sandbox", generate_key())
        await anear.send_transaction(
            alice.account_id,
            actions=[create_account(), transfer("1 NEAR"), add_full_access_key(alice.public_key)],
            wait_until="FINAL",
        )
        results = await asyncio.gather(
            *(anear.send(alice.account_id, "0.1 NEAR") for _ in range(5))
        )
        assert len({r.transaction_hash for r in results}) == 5
        assert await anear.balance(alice.account_id) == Amount("1.5 NEAR")


class TestDelegate:
    def test_relay_flow(self, near, unique_id):
        # User (no NEAR spent on gas) signs a delegate; root relays and pays.
        user = _make_account(near, f"{unique_id}u")
        recipient = _make_account(near, f"{unique_id}r", deposit="1 NEAR")

        as_user = near.with_signer(user)
        signed = as_user.sign_delegate(recipient.account_id, actions=[transfer("2 NEAR")])
        payload = encode_signed_delegate(signed)  # what a user would POST to a relayer

        result = near.send_delegate(payload, wait_until="FINAL")
        assert result.transaction_hash
        assert near.balance(recipient.account_id) == Amount("3 NEAR")


class TestMlDsa:
    def test_post_quantum_key_signs_transactions(self, near, unique_id):
        # Create an account whose ONLY key is ML-DSA-65, then sign with it.
        ml_key = MlDsa65KeyPair.generate()
        account_id = f"{unique_id}pq.sandbox"
        near.send_transaction(
            account_id,
            actions=[create_account(), transfer("5 NEAR"), add_full_access_key(ml_key.public_key)],
            wait_until="FINAL",
        )
        pq_signer = KeyPairSigner(account_id=account_id, key_pair=ml_key)
        as_pq = near.with_signer(pq_signer)
        as_pq.send("sandbox", "1 NEAR", wait_until="FINAL")
        assert near.balance(account_id) < Amount("4 NEAR")
