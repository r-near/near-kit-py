"""Client behavior that needs no chain: construction, signer resolution, and
offline signing. Nothing here opens a connection (clients only touch the
network when a method is called), so these run as plain unit tests.
"""

import pytest

from near import AsyncNear, Near, SignerRequiredError, transfer
from near.keys import KeyPairSigner, generate_key
from near.nep413 import verify_message
from near.wire import delegate_action_signing_hash


@pytest.fixture
def clean_env(monkeypatch):
    for var in ("NEAR_NETWORK", "NEAR_RPC_URL", "NEAR_ACCOUNT_ID", "NEAR_PRIVATE_KEY"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def signer():
    return KeyPairSigner("alice.sandbox", generate_key())


class TestConstruction:
    def test_defaults_to_read_only_mainnet(self, clean_env):
        with Near() as near:
            assert near.network == "mainnet"
            assert near.rpc_url == "https://rpc.mainnet.near.org"
            assert near.signer is None
            assert repr(near) == "Near(network='mainnet', signer='read-only')"

    def test_env_discovery(self, clean_env, monkeypatch):
        key = generate_key()
        monkeypatch.setenv("NEAR_NETWORK", "localnet")
        monkeypatch.setenv("NEAR_RPC_URL", "http://127.0.0.1:39997")
        monkeypatch.setenv("NEAR_ACCOUNT_ID", "alice.test")
        monkeypatch.setenv("NEAR_PRIVATE_KEY", key.secret_key)
        with Near() as near:
            assert near.network == "localnet"
            assert near.rpc_url == "http://127.0.0.1:39997"
            assert near.signer is not None
            assert near.signer.account_id == "alice.test"
            assert near.signer.public_key == key.public_key

    def test_unknown_network_without_rpc_url_raises(self, clean_env):
        with pytest.raises(ValueError, match="Unknown network"):
            Near("betanet-nope")

    def test_missing_credentials_file_means_read_only(self, clean_env, tmp_path):
        with Near("sandbox", account_id="ghost.sandbox", credentials_dir=tmp_path) as near:
            assert near.signer is None

    def test_repr_shows_signer(self, clean_env, signer):
        with Near("sandbox", signer=signer) as near:
            assert repr(near) == "Near(network='sandbox', signer='alice.sandbox')"

    async def test_async_construction_mirrors_sync(self, clean_env, signer):
        async with AsyncNear("sandbox", signer=signer) as near:
            assert near.network == "sandbox"
            assert repr(near) == "AsyncNear(network='sandbox', signer='alice.sandbox')"
        async with AsyncNear() as near:
            assert near.signer is None
            assert "read-only" in repr(near)


class TestSignerRequired:
    def test_writes_fail_fast_without_signer(self, clean_env):
        with Near("sandbox") as near:
            with pytest.raises(SignerRequiredError):
                near.send("bob.sandbox", "1 NEAR")
            with pytest.raises(SignerRequiredError):
                near.sign_message("hi", "app.near")

    def test_account_default_needs_signer(self, clean_env):
        with Near("sandbox") as near, pytest.raises(ValueError, match="account_id is required"):
            near.account()

    async def test_async_writes_fail_fast_without_signer(self, clean_env):
        async with AsyncNear("sandbox") as near:
            with pytest.raises(SignerRequiredError):
                await near.send("bob.sandbox", "1 NEAR")
            with pytest.raises(SignerRequiredError):
                await near.sign_delegate("bob.sandbox", [transfer("1 yocto")])


class TestWithSigner:
    def test_clone_shares_pool_but_not_nonces(self, clean_env, signer):
        with Near("sandbox", signer=signer) as near:
            other = KeyPairSigner("bob.sandbox", generate_key())
            clone = near.with_signer(other)
            assert clone.signer is other
            assert clone._transport is near._transport
            assert clone._nonces is not near._nonces
            assert near.signer is signer  # original untouched

    async def test_async_clone_shares_pool_but_not_nonces(self, clean_env, signer):
        async with AsyncNear("sandbox", signer=signer) as near:
            other = KeyPairSigner("bob.sandbox", generate_key())
            clone = near.with_signer(other)
            assert clone.signer is other
            assert clone._transport is near._transport
            assert clone._nonces is not near._nonces


class TestOfflineSigning:
    def test_sign_message_via_client(self, clean_env, signer):
        with Near("sandbox", signer=signer) as near:
            nonce = bytes(32)
            signed = near.sign_message("hello", "app.near", nonce=nonce)
            assert signed.account_id == "alice.sandbox"
            assert verify_message(signed, "hello", "app.near", nonce, max_age_ms=None)

    async def test_async_sign_message_via_client(self, clean_env, signer):
        async with AsyncNear("sandbox", signer=signer) as near:
            nonce = bytes(32)
            signed = near.sign_message("hello", "app.near", nonce=nonce)
            assert verify_message(signed, "hello", "app.near", nonce, max_age_ms=None)

    def test_sign_delegate_with_explicit_nonce_and_height(self, clean_env, signer):
        # With both nonce and max_block_height given, no RPC round trips happen.
        with Near("sandbox", signer=signer) as near:
            signed = near.sign_delegate(
                "bob.sandbox", [transfer("1 yocto")], nonce=7, max_block_height=99
            )
            delegate = signed.delegate_action
            assert delegate.sender_id == "alice.sandbox"
            assert delegate.nonce == 7
            assert delegate.max_block_height == 99
            digest = delegate_action_signing_hash(delegate)
            assert signer.public_key.verify(signed.signature.data, digest)

    async def test_async_sign_delegate_with_explicit_nonce_and_height(self, clean_env, signer):
        async with AsyncNear("sandbox", signer=signer) as near:
            signed = await near.sign_delegate(
                "bob.sandbox", [transfer("1 yocto")], nonce=7, max_block_height=99
            )
            assert signed.delegate_action.nonce == 7
            assert signed.delegate_action.max_block_height == 99
            digest = delegate_action_signing_hash(signed.delegate_action)
            assert signer.public_key.verify(signed.signature.data, digest)
