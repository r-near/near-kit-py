"""Typed error hierarchy for near-kit.

Every error carries a stable ``code`` string and a ``retryable`` flag so
applications can branch on failures without string-matching messages.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "AccessKeyNotFoundError",
    "AccountNotFoundError",
    "ContractPanicError",
    "InsufficientBalanceError",
    "InvalidAccountIdError",
    "InvalidKeyError",
    "InvalidNonceError",
    "NearError",
    "RpcError",
    "SignerRequiredError",
    "TransactionExpiredError",
    "UnitParseError",
]


class NearError(Exception):
    """Base class for all near-kit errors."""

    code: str = "NEAR_ERROR"
    retryable: bool = False

    def __init__(self, message: str, *, data: Any = None) -> None:
        super().__init__(message)
        self.data = data


class RpcError(NearError):
    """An RPC request failed (transport failure or an unclassified node error)."""

    code = "RPC_ERROR"

    def __init__(
        self,
        message: str,
        *,
        method: str | None = None,
        retryable: bool = False,
        data: Any = None,
    ) -> None:
        super().__init__(message, data=data)
        self.method = method
        self.retryable = retryable


class AccountNotFoundError(NearError):
    """The account does not exist on chain."""

    code = "ACCOUNT_NOT_FOUND"

    def __init__(self, account_id: str, *, data: Any = None) -> None:
        super().__init__(f"Account not found: {account_id}", data=data)
        self.account_id = account_id


class AccessKeyNotFoundError(NearError):
    """The access key does not exist for the account."""

    code = "ACCESS_KEY_NOT_FOUND"

    def __init__(self, account_id: str, public_key: str, *, data: Any = None) -> None:
        super().__init__(f"Access key {public_key} not found for {account_id}", data=data)
        self.account_id = account_id
        self.public_key = public_key


class ContractPanicError(NearError):
    """A contract function call failed (panic, abort, or execution error)."""

    code = "CONTRACT_PANIC"

    def __init__(
        self,
        panic: str,
        *,
        logs: list[str] | None = None,
        receipt_id: str | None = None,
        data: Any = None,
    ) -> None:
        super().__init__(f"Contract panicked: {panic}", data=data)
        self.panic = panic
        self.logs = logs or []
        self.receipt_id = receipt_id


class InvalidNonceError(NearError):
    """The transaction nonce did not match the access key nonce.

    ``ak_nonce`` is the access key's current nonce as reported by the node,
    which callers (and the client's retry loop) use to resynchronize.
    """

    code = "INVALID_NONCE"
    retryable = True

    def __init__(self, message: str, *, ak_nonce: int | None = None, data: Any = None) -> None:
        super().__init__(message, data=data)
        self.ak_nonce = ak_nonce


class InsufficientBalanceError(NearError):
    """The signer's balance cannot cover the transfer/deposit plus fees."""

    code = "INSUFFICIENT_BALANCE"

    def __init__(
        self,
        message: str,
        *,
        required: int | None = None,
        available: int | None = None,
        data: Any = None,
    ) -> None:
        super().__init__(message, data=data)
        self.required = required
        self.available = available


class TransactionExpiredError(NearError):
    """The transaction's block hash was too old by the time it was processed."""

    code = "TRANSACTION_EXPIRED"
    retryable = True

    def __init__(self, message: str = "Transaction expired", *, data: Any = None) -> None:
        super().__init__(message, data=data)


class InvalidAccountIdError(NearError, ValueError):
    """The account ID does not satisfy NEAR's account naming rules."""

    code = "INVALID_ACCOUNT_ID"

    def __init__(self, account_id: str, *, data: Any = None) -> None:
        super().__init__(f"Invalid account ID: {account_id!r}", data=data)
        self.account_id = account_id


class InvalidKeyError(NearError, ValueError):
    """A key string or key material could not be parsed."""

    code = "INVALID_KEY"


class SignerRequiredError(NearError):
    """The operation signs a transaction but the client has no signer configured."""

    code = "SIGNER_REQUIRED"

    def __init__(
        self,
        message: str = (
            "This operation signs a transaction, but the client has no signer. "
            "Construct the client with private_key=, signer=, or Near.from_file()."
        ),
        *,
        data: Any = None,
    ) -> None:
        super().__init__(message, data=data)


class UnitParseError(NearError, ValueError):
    """An amount or gas value was ambiguous or malformed."""

    code = "UNIT_PARSE_ERROR"
