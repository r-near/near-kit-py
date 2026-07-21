import pytest

from near.errors import (
    AccessKeyNotFoundError,
    AccountNotFoundError,
    ContractPanicError,
    InsufficientBalanceError,
    InvalidAccountIdError,
    InvalidKeyError,
    InvalidNonceError,
    NearError,
    RpcError,
    SignerRequiredError,
    TransactionExpiredError,
    UnitParseError,
)


class TestErrorAttributes:
    def test_base_error_defaults(self):
        err = NearError("boom")
        assert err.code == "NEAR_ERROR"
        assert err.retryable is False
        assert err.data is None
        assert str(err) == "boom"

    def test_base_error_carries_data(self):
        payload = {"cause": "something"}
        assert NearError("boom", data=payload).data is payload

    def test_rpc_error(self):
        err = RpcError("timed out", method="block", retryable=True, data={"x": 1})
        assert err.code == "RPC_ERROR"
        assert err.method == "block"
        assert err.retryable is True
        assert err.data == {"x": 1}

    def test_rpc_error_defaults(self):
        err = RpcError("bad")
        assert err.method is None
        assert err.retryable is False

    def test_account_not_found(self):
        err = AccountNotFoundError("ghost.near")
        assert err.code == "ACCOUNT_NOT_FOUND"
        assert err.account_id == "ghost.near"
        assert "ghost.near" in str(err)

    def test_access_key_not_found(self):
        err = AccessKeyNotFoundError("alice.near", "ed25519:abc")
        assert err.code == "ACCESS_KEY_NOT_FOUND"
        assert err.account_id == "alice.near"
        assert err.public_key == "ed25519:abc"
        assert "ed25519:abc" in str(err)

    def test_contract_panic(self):
        err = ContractPanicError("assertion failed", logs=["log1"], receipt_id="r1")
        assert err.code == "CONTRACT_PANIC"
        assert err.panic == "assertion failed"
        assert err.logs == ["log1"]
        assert err.receipt_id == "r1"
        assert "assertion failed" in str(err)

    def test_contract_panic_default_logs(self):
        assert ContractPanicError("x").logs == []

    def test_invalid_nonce_is_retryable(self):
        err = InvalidNonceError("nonce too small", ak_nonce=42)
        assert err.code == "INVALID_NONCE"
        assert err.retryable is True
        assert err.ak_nonce == 42

    def test_insufficient_balance(self):
        err = InsufficientBalanceError("too poor", required=200, available=100)
        assert err.code == "INSUFFICIENT_BALANCE"
        assert err.required == 200
        assert err.available == 100
        assert err.retryable is False

    def test_transaction_expired_default_message(self):
        err = TransactionExpiredError()
        assert err.code == "TRANSACTION_EXPIRED"
        assert err.retryable is True
        assert "expired" in str(err).lower()

    def test_signer_required_default_message(self):
        err = SignerRequiredError()
        assert err.code == "SIGNER_REQUIRED"
        assert "signer" in str(err)


class TestErrorHierarchy:
    def test_all_are_near_errors(self):
        for err in (
            RpcError("x"),
            AccountNotFoundError("a.near"),
            AccessKeyNotFoundError("a.near", "ed25519:k"),
            ContractPanicError("p"),
            InvalidNonceError("n"),
            InsufficientBalanceError("b"),
            TransactionExpiredError(),
            InvalidAccountIdError("BAD"),
            InvalidKeyError("k"),
            SignerRequiredError(),
            UnitParseError("u"),
        ):
            assert isinstance(err, NearError)

    def test_validation_errors_are_value_errors(self):
        assert isinstance(InvalidAccountIdError("BAD"), ValueError)
        assert isinstance(InvalidKeyError("bad"), ValueError)
        assert isinstance(UnitParseError("bad"), ValueError)

    def test_invalid_account_id_catchable_either_way(self):
        with pytest.raises(ValueError, match="Invalid account ID"):
            raise InvalidAccountIdError("UPPER")
