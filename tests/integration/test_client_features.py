"""Integration tests for client construction, wire-level error classification,
nonce recovery, and the async client surface — all against a real sandbox.
"""

import json

import pytest

import near as near_module
from near import (
    AccessKeyNotFoundError,
    AccountView,
    Amount,
    AsyncNear,
    InsufficientBalanceError,
    Near,
    RpcError,
    add_full_access_key,
    create_account,
    generate_key,
    transfer,
)
from near.delegate import encode_signed_delegate
from near.keys import KeyPairSigner
from near.testing import sandbox_signer

pytestmark = pytest.mark.integration


def _funded_account(near: Near, name: str, deposit: str = "10 NEAR") -> KeyPairSigner:
    account_id = f"{name}.{near.signer.account_id}"
    key = generate_key()
    near.send_transaction(
        account_id,
        actions=[create_account(), transfer(deposit), add_full_access_key(key.public_key)],
        wait_until="FINAL",
    )
    return KeyPairSigner(account_id=account_id, key_pair=key)


async def _afunded_account(anear: AsyncNear, name: str, deposit: str = "10 NEAR") -> KeyPairSigner:
    account_id = f"{name}.{anear.signer.account_id}"
    key = generate_key()
    await anear.send_transaction(
        account_id,
        actions=[create_account(), transfer(deposit), add_full_access_key(key.public_key)],
        wait_until="FINAL",
    )
    return KeyPairSigner(account_id=account_id, key_pair=key)


class TestConstructionOnChain:
    def test_env_discovery_connects(self, monkeypatch, sandbox_url):
        root = sandbox_signer()
        monkeypatch.setenv("NEAR_NETWORK", "sandbox")
        monkeypatch.setenv("NEAR_RPC_URL", sandbox_url)
        monkeypatch.setenv("NEAR_ACCOUNT_ID", root.account_id)
        monkeypatch.setenv("NEAR_PRIVATE_KEY", root.key_pair.secret_key)
        with Near() as client:
            assert client.network == "sandbox"
            assert client.signer is not None
            # balance() with no argument reads the env-discovered signer's account.
            assert client.balance() > Amount("1000 NEAR")

    def test_from_file(self, tmp_path, sandbox_url):
        root = sandbox_signer()
        creds = tmp_path / "sandbox"
        creds.mkdir()
        (creds / "sandbox.json").write_text(
            json.dumps({"account_id": "sandbox", "private_key": root.key_pair.secret_key})
        )
        with Near.from_file(
            "sandbox", "sandbox", credentials_dir=tmp_path, rpc_url=sandbox_url
        ) as client:
            assert client.signer.public_key == root.public_key
            assert client.balance() > 0

    async def test_async_from_file(self, tmp_path, sandbox_url):
        root = sandbox_signer()
        creds = tmp_path / "sandbox"
        creds.mkdir()
        (creds / "sandbox.json").write_text(
            json.dumps({"account_id": "sandbox", "private_key": root.key_pair.secret_key})
        )
        async with AsyncNear.from_file(
            "sandbox", "sandbox", credentials_dir=tmp_path, rpc_url=sandbox_url
        ) as client:
            assert client.signer.account_id == "sandbox"
            assert await client.balance() > 0


class TestModuleOneShots:
    def test_view(self, guestbook, sandbox_url):
        messages = near_module.view(guestbook, "get_messages", rpc_url=sandbox_url)
        assert isinstance(messages, list)

    def test_account(self, sandbox_url):
        view = near_module.account("sandbox", rpc_url=sandbox_url)
        assert isinstance(view, AccountView)
        assert view.amount > 0


class TestErrorsOverTheWire:
    def test_unknown_method_is_classified(self, near):
        with pytest.raises(RpcError) as exc_info:
            near.rpc("definitely_not_a_method", {})
        assert exc_info.value.code == "METHOD_NOT_FOUND"
        assert exc_info.value.retryable is False

    def test_access_key_lookup(self, near):
        view = near.access_key("sandbox", near.signer.public_key)
        assert view.is_full_access
        assert view.nonce >= 0

    def test_access_key_not_found(self, near):
        with pytest.raises(AccessKeyNotFoundError) as exc_info:
            near.access_key("sandbox", generate_key().public_key)
        assert exc_info.value.account_id == "sandbox"
        assert exc_info.value.code == "ACCESS_KEY_NOT_FOUND"

    def test_insufficient_balance(self, near, unique_id):
        poor = _funded_account(near, unique_id, deposit="1 NEAR")
        as_poor = near.with_signer(poor)
        with pytest.raises(InsufficientBalanceError) as exc_info:
            as_poor.send("sandbox", "50 NEAR")
        err = exc_info.value
        assert err.required is not None
        assert err.available is not None
        assert err.available < err.required


class TestNonceHandling:
    def test_stale_cache_resyncs_and_retries(self, near, unique_id):
        # Two clients signing for the same key, each with its own nonce cache:
        # after c1 advances the chain, c2's cached nonce is stale and its next
        # send must hit InvalidNonce internally, resync, and succeed.
        alice = _funded_account(near, unique_id)
        c1, c2 = near.with_signer(alice), near.with_signer(alice)
        hashes = [c2.send("sandbox", "1 yocto", wait_until="FINAL").transaction_hash]
        hashes.append(c1.send("sandbox", "1 yocto", wait_until="FINAL").transaction_hash)
        hashes.append(c2.send("sandbox", "1 yocto", wait_until="FINAL").transaction_hash)
        assert len(set(hashes)) == 3

    def test_wait_until_none_fire_and_forget(self, near):
        result = near.send("sandbox", "1 yocto", wait_until="NONE")
        assert result.final_execution_status == "NONE"
        assert result.transaction_hash is None


class TestDelegateExplicitParams:
    def test_explicit_nonce_and_height_relayed_as_object(self, near, unique_id):
        user = _funded_account(near, f"{unique_id}u")
        recipient = _funded_account(near, f"{unique_id}r", deposit="1 NEAR")
        as_user = near.with_signer(user)

        ak_nonce = near.access_key(user.account_id, user.public_key).nonce
        height = int(near.rpc("block", {"finality": "final"})["header"]["height"])
        signed = as_user.sign_delegate(
            recipient.account_id,
            [transfer("1 NEAR")],
            nonce=ak_nonce + 1,
            max_block_height=height + 600,
        )
        assert signed.delegate_action.nonce == ak_nonce + 1
        assert signed.delegate_action.max_block_height == height + 600

        # Relay the model object directly (not the base64 form).
        result = near.send_delegate(signed, wait_until="FINAL")
        assert result.transaction_hash
        assert near.balance(recipient.account_id) == Amount("2 NEAR")


class TestAsyncSurface:
    async def test_context_manager_reads_and_access_keys(self, guestbook, sandbox_url):
        async with AsyncNear(rpc_url=sandbox_url, signer=sandbox_signer()) as anear:
            assert "sandbox" in repr(anear)
            block = await anear.rpc("block", {"finality": "final"})
            assert block["header"]["height"] > 0
            assert not await anear.account_exists("definitely-not-here.sandbox")
            messages = await anear.view(guestbook, "get_messages")
            assert isinstance(messages, list)
            keys = await anear.access_keys(guestbook)
            assert len(keys) == 1
            view = await anear.access_key(guestbook, keys[0].public_key)
            assert view.is_full_access
            with pytest.raises(AccessKeyNotFoundError):
                await anear.access_key("sandbox", generate_key().public_key)

    async def test_call_and_transaction_status(self, anear, guestbook):
        result = await anear.call(
            guestbook,
            "add_message",
            {"text": "hello from asyncio"},
            deposit="1 yocto",
            wait_until="FINAL",
        )
        assert result.transaction_hash
        looked_up = await anear.transaction_status(result.transaction_hash)
        assert looked_up.transaction_hash == result.transaction_hash
        messages = await anear.view(guestbook, "get_messages")
        assert any(m["text"] == "hello from asyncio" for m in messages)

    async def test_wait_until_none_fire_and_forget(self, anear):
        result = await anear.send("sandbox", "1 yocto", wait_until="NONE")
        assert result.final_execution_status == "NONE"
        assert result.transaction_hash is None

    async def test_stale_cache_resyncs_and_retries(self, anear, unique_id):
        alice = await _afunded_account(anear, unique_id)
        c1, c2 = anear.with_signer(alice), anear.with_signer(alice)
        hashes = [(await c2.send("sandbox", "1 yocto", wait_until="FINAL")).transaction_hash]
        hashes.append((await c1.send("sandbox", "1 yocto", wait_until="FINAL")).transaction_hash)
        hashes.append((await c2.send("sandbox", "1 yocto", wait_until="FINAL")).transaction_hash)
        assert len(set(hashes)) == 3

    async def test_delegate_relay_flow(self, anear, unique_id):
        user = await _afunded_account(anear, f"{unique_id}au")
        recipient = await _afunded_account(anear, f"{unique_id}ar", deposit="1 NEAR")

        as_user = anear.with_signer(user)
        signed = await as_user.sign_delegate(recipient.account_id, [transfer("2 NEAR")])
        payload = encode_signed_delegate(signed)

        result = await anear.send_delegate(payload, wait_until="FINAL")
        assert result.transaction_hash
        assert await anear.balance(recipient.account_id) == Amount("3 NEAR")

        # Relaying the model object directly (not base64) works the same way.
        signed_again = await as_user.sign_delegate(recipient.account_id, [transfer("1 NEAR")])
        result = await anear.send_delegate(signed_again, wait_until="FINAL")
        assert result.transaction_hash
        assert await anear.balance(recipient.account_id) == Amount("4 NEAR")
