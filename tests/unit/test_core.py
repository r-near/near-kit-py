import json
import threading

import pytest

from near import _core
from near.errors import ContractPanicError, RpcError, SignerRequiredError
from near.keys import KeyPairSigner, generate_key
from near.units import Amount


@pytest.fixture
def clean_env(monkeypatch):
    for var in ("NEAR_NETWORK", "NEAR_RPC_URL", "NEAR_ACCOUNT_ID", "NEAR_PRIVATE_KEY"):
        monkeypatch.delenv(var, raising=False)


class TestResolveNetwork:
    def test_defaults_to_mainnet(self, clean_env):
        assert _core.resolve_network(None) == "mainnet"

    def test_env_variable(self, clean_env, monkeypatch):
        monkeypatch.setenv("NEAR_NETWORK", "testnet")
        assert _core.resolve_network(None) == "testnet"

    def test_explicit_wins_over_env(self, clean_env, monkeypatch):
        monkeypatch.setenv("NEAR_NETWORK", "testnet")
        assert _core.resolve_network("sandbox") == "sandbox"


class TestResolveRpcUrl:
    def test_known_networks(self, clean_env):
        assert _core.resolve_rpc_url("mainnet", None) == "https://rpc.mainnet.near.org"
        assert _core.resolve_rpc_url("sandbox", None) == "http://localhost:3030"

    def test_explicit_url_wins(self, clean_env):
        assert _core.resolve_rpc_url("mainnet", "http://my-node:3030") == "http://my-node:3030"

    def test_env_url(self, clean_env, monkeypatch):
        monkeypatch.setenv("NEAR_RPC_URL", "http://env-node:3030")
        assert _core.resolve_rpc_url("mainnet", None) == "http://env-node:3030"

    def test_unknown_network_raises(self, clean_env):
        with pytest.raises(ValueError, match="Unknown network 'betanet-nope'"):
            _core.resolve_rpc_url("betanet-nope", None)


class TestResolveSigner:
    def test_explicit_signer_wins(self, clean_env):
        signer = KeyPairSigner("alice.near", generate_key())
        resolved = _core.resolve_signer(
            network="mainnet",
            account_id="other.near",
            private_key=None,
            signer=signer,
        )
        assert resolved is signer

    def test_private_key_with_account(self, clean_env):
        key = generate_key()
        resolved = _core.resolve_signer(
            network="mainnet",
            account_id="alice.near",
            private_key=key.secret_key,
            signer=None,
        )
        assert isinstance(resolved, KeyPairSigner)
        assert resolved.account_id == "alice.near"
        assert resolved.public_key == key.public_key

    def test_private_key_without_account_raises(self, clean_env):
        with pytest.raises(ValueError, match="account_id is missing"):
            _core.resolve_signer(
                network="mainnet",
                account_id=None,
                private_key=generate_key().secret_key,
                signer=None,
            )

    def test_env_account_and_key(self, clean_env, monkeypatch):
        key = generate_key()
        monkeypatch.setenv("NEAR_ACCOUNT_ID", "env.near")
        monkeypatch.setenv("NEAR_PRIVATE_KEY", key.secret_key)
        resolved = _core.resolve_signer(
            network="mainnet", account_id=None, private_key=None, signer=None
        )
        assert isinstance(resolved, KeyPairSigner)
        assert resolved.account_id == "env.near"

    def test_account_falls_back_to_credentials_file(self, clean_env, tmp_path):
        key = generate_key()
        creds = tmp_path / "testnet"
        creds.mkdir()
        (creds / "alice.testnet.json").write_text(
            json.dumps({"account_id": "alice.testnet", "private_key": key.secret_key})
        )
        resolved = _core.resolve_signer(
            network="testnet",
            account_id="alice.testnet",
            private_key=None,
            signer=None,
            credentials_dir=tmp_path,
        )
        assert isinstance(resolved, KeyPairSigner)
        assert resolved.public_key == key.public_key

    def test_account_without_credentials_is_none(self, clean_env, tmp_path):
        resolved = _core.resolve_signer(
            network="testnet",
            account_id="ghost.testnet",
            private_key=None,
            signer=None,
            credentials_dir=tmp_path,
        )
        assert resolved is None

    def test_nothing_resolves_to_none(self, clean_env):
        assert (
            _core.resolve_signer(network="mainnet", account_id=None, private_key=None, signer=None)
            is None
        )


class TestRequireSigner:
    def test_passes_through(self):
        signer = KeyPairSigner("a.near", generate_key())
        assert _core.require_signer(signer) is signer

    def test_none_raises(self):
        with pytest.raises(SignerRequiredError):
            _core.require_signer(None)


class TestQueryParams:
    def test_default_block_is_optimistic_finality(self):
        params = _core.account_params("alice.near")
        assert params == {
            "request_type": "view_account",
            "account_id": "alice.near",
            "finality": "optimistic",
        }

    def test_int_block_is_block_id(self):
        assert _core.account_params("a.near", block=12345)["block_id"] == 12345

    @pytest.mark.parametrize("finality", ["optimistic", "near-final", "final"])
    def test_finality_strings(self, finality):
        assert _core.account_params("a.near", block=finality)["finality"] == finality

    def test_other_string_is_block_hash(self):
        params = _core.account_params("a.near", block="4Zn6mLc7T")
        assert params["block_id"] == "4Zn6mLc7T"

    def test_view_params(self):
        params = _core.view_params("counter.near", "get", "e30=", None)
        assert params["request_type"] == "call_function"
        assert params["method_name"] == "get"
        assert params["args_base64"] == "e30="
        assert params["finality"] == "optimistic"

    def test_access_key_params_always_final(self):
        params = _core.access_key_params("a.near", "ed25519:abc")
        assert params["request_type"] == "view_access_key"
        assert params["finality"] == "final"

    def test_access_key_list_params(self):
        params = _core.access_key_list_params("a.near", block=7)
        assert params["request_type"] == "view_access_key_list"
        assert params["block_id"] == 7


class TestDecodeViewResult:
    def test_json_result(self):
        raw = list(b'{"count": 3}')
        assert _core.decode_view_result({"result": raw}, "c.near", "get") == {"count": 3}

    def test_empty_result_is_none(self):
        assert _core.decode_view_result({"result": []}, "c.near", "get") is None

    def test_non_json_bytes_returned_raw(self):
        raw = list(b"\xff\xfe\x00binary")
        assert _core.decode_view_result({"result": raw}, "c.near", "get") == b"\xff\xfe\x00binary"

    def test_error_raises_contract_panic(self):
        result = {"error": "MethodNotFound", "logs": ["before it died"]}
        with pytest.raises(ContractPanicError) as exc_info:
            _core.decode_view_result(result, "c.near", "missing")
        assert "c.near.missing" in str(exc_info.value)
        assert exc_info.value.logs == ["before it died"]


class TestDefaultAccountId:
    def test_explicit_account_wins(self):
        signer = KeyPairSigner("signer.near", generate_key())
        assert _core.default_account_id(signer, "other.near") == "other.near"

    def test_falls_back_to_signer(self):
        signer = KeyPairSigner("signer.near", generate_key())
        assert _core.default_account_id(signer, None) == "signer.near"

    def test_neither_raises(self):
        with pytest.raises(ValueError, match="account_id is required"):
            _core.default_account_id(None, None)


class TestResponseHelpers:
    def test_balance_from_account(self):
        balance = _core.balance_from_account({"amount": str(10**24)})
        assert isinstance(balance, Amount)
        assert balance == Amount("1 NEAR")

    def test_block_hash_of(self):
        assert _core.block_hash_of({"header": {"hash": "abc123"}}) == "abc123"

    @pytest.mark.parametrize("payload", [{}, {"header": None}, {"header": {}}])
    def test_malformed_block_raises(self, payload):
        with pytest.raises(RpcError, match="Malformed block response"):
            _core.block_hash_of(payload)


class TestNonceCache:
    def test_key_format(self):
        signer = KeyPairSigner("alice.near", generate_key())
        assert _core.NonceCache.key(signer) == f"alice.near:{signer.public_key}"

    def test_reserve_from_scratch(self):
        cache = _core.NonceCache()
        assert not cache.has("k")
        assert cache.reserve("k", None) == 1
        assert cache.has("k")

    def test_reserve_folds_in_on_chain_nonce(self):
        cache = _core.NonceCache()
        assert cache.reserve("k", 10) == 11
        assert cache.reserve("k", None) == 12
        # A stale (lower) on-chain value must not rewind the cache.
        assert cache.reserve("k", 5) == 13

    def test_sync_to_advances_only(self):
        cache = _core.NonceCache()
        cache.reserve("k", 10)  # cache: 11
        cache.sync_to("k", 20)
        assert cache.reserve("k", None) == 21
        cache.sync_to("k", 5)  # lower: no-op
        assert cache.reserve("k", None) == 22

    def test_keys_are_independent(self):
        cache = _core.NonceCache()
        assert cache.reserve("a", 100) == 101
        assert cache.reserve("b", None) == 1

    def test_concurrent_reservations_are_unique(self):
        cache = _core.NonceCache()
        results = []

        def grab():
            results.append(cache.reserve("k", None))

        threads = [threading.Thread(target=grab) for _ in range(32)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert sorted(results) == list(range(1, 33))
