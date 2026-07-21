"""JSON-RPC transports (sync + async) and NEAR error classification.

The transports are thin: build the JSON-RPC envelope, retry transient
failures with exponential backoff, and route every error payload through
:func:`classify_rpc_error` so callers only ever see typed ``NearError``s.
"""

from __future__ import annotations

import asyncio
import itertools
import time
from typing import Any

import httpx

from .errors import (
    AccountNotFoundError,
    InsufficientBalanceError,
    InvalidAccountIdError,
    InvalidNonceError,
    NearError,
    RpcError,
    TransactionExpiredError,
)
from .units import Amount

__all__ = [
    "NETWORK_RPC_URLS",
    "AsyncRpcTransport",
    "RpcTransport",
    "classify_rpc_error",
    "raise_for_execution_failure",
]

NETWORK_RPC_URLS = {
    "mainnet": "https://rpc.mainnet.near.org",
    "testnet": "https://rpc.testnet.near.org",
    "localnet": "http://localhost:3030",
    "sandbox": "http://localhost:3030",
}

_RETRYABLE_STATUS = frozenset({408, 429, 503})
_RETRYABLE_CAUSES = frozenset(
    {"TIMEOUT_ERROR", "NO_SYNCED_BLOCKS", "NOT_SYNCED_YET", "INTERNAL_ERROR"}
)

_request_ids = itertools.count(1)


def classify_rpc_error(error: dict[str, Any], status_code: int | None = None) -> NearError:
    """Convert a NEAR JSON-RPC error payload into a typed exception (returned, not raised)."""
    cause = error.get("cause") or {}
    cause_name = cause.get("name") or error.get("name") or "UNKNOWN"
    info = cause.get("info") or {}
    message = error.get("message") or "RPC error"
    data = error.get("data")

    if cause_name == "UNKNOWN_ACCOUNT":
        return AccountNotFoundError(str(info.get("requested_account_id", "unknown")), data=error)
    if cause_name == "INVALID_ACCOUNT":
        return InvalidAccountIdError(str(info.get("requested_account_id", "unknown")), data=error)

    if cause_name == "INVALID_TRANSACTION" and isinstance(data, dict):
        tx_error = data.get("TxExecutionError") or data
        invalid_tx = tx_error.get("InvalidTxError") if isinstance(tx_error, dict) else None
        if isinstance(invalid_tx, dict):
            if isinstance(invalid_tx.get("InvalidNonce"), dict):
                nonce_info = invalid_tx["InvalidNonce"]
                return InvalidNonceError(
                    f"Invalid nonce: tx nonce {nonce_info.get('tx_nonce')} vs "
                    f"access key nonce {nonce_info.get('ak_nonce')}",
                    ak_nonce=nonce_info.get("ak_nonce"),
                    data=error,
                )
            if isinstance(invalid_tx.get("NotEnoughBalance"), dict):
                balance_info = invalid_tx["NotEnoughBalance"]
                required = balance_info.get("cost")
                available = balance_info.get("balance")
                return InsufficientBalanceError(
                    f"Not enough balance: {balance_info.get('signer_id')} has "
                    f"{Amount.yocto(int(available)) if available else '?'}, needs "
                    f"{Amount.yocto(int(required)) if required else '?'}",
                    required=int(required) if required else None,
                    available=int(available) if available else None,
                    data=error,
                )
            if "Expired" in invalid_tx:
                return TransactionExpiredError(data=error)

    retryable = cause_name in _RETRYABLE_CAUSES or (
        status_code is not None and (status_code in _RETRYABLE_STATUS or status_code >= 500)
    )
    rpc_error = RpcError(f"RPC error [{cause_name}]: {message}", retryable=retryable, data=error)
    rpc_error.code = cause_name
    return rpc_error


def raise_for_execution_failure(result: dict[str, Any]) -> None:
    """Raise :class:`ContractPanicError` if any outcome in a tx result failed."""
    from .errors import ContractPanicError

    outcomes = [result.get("transaction_outcome"), *result.get("receipts_outcome", [])]
    status = result.get("status")
    failures = [o for o in outcomes if isinstance(o, dict) and _failure_of(o.get("outcome", {}))]
    if not failures and not (isinstance(status, dict) and "Failure" in status):
        return

    failure: dict[str, Any] = (
        _failure_of(failures[0]["outcome"]) or {} if failures else status["Failure"]  # type: ignore[index]
    )
    panic = _extract_panic(failure) or _summarize_failure(failure)
    logs: list[str] = []
    for outcome in outcomes:
        if isinstance(outcome, dict):
            logs.extend(outcome.get("outcome", {}).get("logs", []))
    receipt_id = failures[0].get("id") if failures else None
    raise ContractPanicError(panic, logs=logs, receipt_id=receipt_id, data=result)


def _failure_of(outcome: dict[str, Any]) -> dict[str, Any] | None:
    status = outcome.get("status")
    if isinstance(status, dict) and isinstance(status.get("Failure"), dict):
        return dict(status["Failure"])
    return None


def _extract_panic(failure: dict[str, Any]) -> str | None:
    fn_error = failure.get("ActionError", {}).get("kind", {}).get(
        "FunctionCallError"
    ) or failure.get("FunctionCallError")
    if not isinstance(fn_error, dict):
        return None
    for key in ("ExecutionError", "HostError"):
        value = fn_error.get(key)
        if isinstance(value, str):
            return value
    return str(fn_error)


def _summarize_failure(failure: dict[str, Any]) -> str:
    kind = failure.get("ActionError", {}).get("kind")
    if isinstance(kind, dict) and kind:
        error_type, error_data = next(iter(kind.items()))
        if isinstance(error_data, dict) and error_data:
            details = ", ".join(f"{k}: {v}" for k, v in error_data.items())
            return f"{error_type} ({details})"
        return str(error_type)
    return str(failure)


class _TransportBase:
    def __init__(
        self,
        rpc_url: str,
        *,
        timeout: float = 30.0,
        retries: int = 4,
        retry_initial_delay: float = 1.0,
    ) -> None:
        self.rpc_url = rpc_url
        self.timeout = timeout
        self.retries = retries
        self.retry_initial_delay = retry_initial_delay

    def _body(self, method: str, params: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": str(next(_request_ids)), "method": method, "params": params}

    def _handle(self, response: httpx.Response, method: str) -> Any:
        try:
            payload = response.json()
        except ValueError as exc:
            raise RpcError(
                f"Non-JSON response from {self.rpc_url} (HTTP {response.status_code})",
                method=method,
                retryable=response.status_code >= 500,
            ) from exc
        if payload.get("error"):
            raise classify_rpc_error(payload["error"], response.status_code)
        return payload.get("result")


class RpcTransport(_TransportBase):
    """Synchronous JSON-RPC transport over a pooled httpx client."""

    def __init__(self, rpc_url: str, **kwargs: Any) -> None:
        super().__init__(rpc_url, **kwargs)
        self._client = httpx.Client(timeout=self.timeout)

    def call(self, method: str, params: Any) -> Any:
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            if attempt:
                time.sleep(self.retry_initial_delay * 2 ** (attempt - 1))
            try:
                response = self._client.post(self.rpc_url, json=self._body(method, params))
                return self._handle(response, method)
            except httpx.HTTPError as exc:
                last_error = RpcError(f"RPC request failed: {exc}", method=method, retryable=True)
            except RpcError as exc:
                if not exc.retryable:
                    raise
                last_error = exc
        raise last_error  # type: ignore[misc]

    def close(self) -> None:
        self._client.close()


class AsyncRpcTransport(_TransportBase):
    """Asynchronous JSON-RPC transport over a pooled httpx client."""

    def __init__(self, rpc_url: str, **kwargs: Any) -> None:
        super().__init__(rpc_url, **kwargs)
        self._client = httpx.AsyncClient(timeout=self.timeout)

    async def call(self, method: str, params: Any) -> Any:
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            if attempt:
                await asyncio.sleep(self.retry_initial_delay * 2 ** (attempt - 1))
            try:
                response = await self._client.post(self.rpc_url, json=self._body(method, params))
                return self._handle(response, method)
            except httpx.HTTPError as exc:
                last_error = RpcError(f"RPC request failed: {exc}", method=method, retryable=True)
            except RpcError as exc:
                if not exc.retryable:
                    raise
                last_error = exc
        raise last_error  # type: ignore[misc]

    async def aclose(self) -> None:
        await self._client.aclose()
