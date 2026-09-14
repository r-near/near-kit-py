"""Pydantic models for RPC responses.

These validate at the RPC boundary and give balances back as
:class:`~near.units.Amount` so callers never touch raw yocto strings.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, model_validator

from .units import Amount, Gas

__all__ = [
    "AccessKeyView",
    "AccountView",
    "ContractCode",
    "ExecutionOutcome",
    "KeyInfo",
    "TransactionResult",
]


class _Model(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=False)


class AccountView(_Model):
    """Result of a ``view_account`` query."""

    amount: Amount
    locked: Amount
    code_hash: str
    storage_usage: int
    block_height: int | None = None
    block_hash: str | None = None


class AccessKeyView(_Model):
    """An access key's nonce and permission."""

    nonce: int
    permission: Literal["FullAccess"] | dict[str, Any]

    @property
    def is_full_access(self) -> bool:
        return self.permission == "FullAccess"

    @property
    def is_gas_key(self) -> bool:
        """Whether this is a gas key (its ``nonce`` is then unused; see ``gas_key_nonces``)."""
        return self._gas_key_info() is not None

    @property
    def gas_key_balance(self) -> Amount | None:
        """The prepaid gas balance of a gas key, ``None`` for ordinary keys."""
        info = self._gas_key_info()
        return Amount.yocto(int(info["balance"])) if info is not None else None

    def _gas_key_info(self) -> dict[str, Any] | None:
        if isinstance(self.permission, dict):
            for kind in ("GasKeyFullAccess", "GasKeyFunctionCall"):
                if isinstance(info := self.permission.get(kind), dict):
                    return info
        return None


class KeyInfo(_Model):
    """One entry of a ``view_access_key_list`` query."""

    public_key: str
    access_key: AccessKeyView


class ContractCode(_Model):
    """Deployed WASM and its hash (``view_code`` / ``view_global_contract_code``)."""

    code: bytes
    hash: str

    @model_validator(mode="before")
    @classmethod
    def _decode_rpc_code(cls, data: Any) -> Any:
        # The RPC ships the WASM as ``code_base64`` text; decode it into ``code``.
        if isinstance(data, dict) and "code_base64" in data:
            encoded = data["code_base64"]
            data = {k: v for k, v in data.items() if k != "code_base64"}
            data.setdefault("code", base64.b64decode(encoded))
        return data


class ExecutionOutcome(_Model):
    """One receipt/transaction outcome within a transaction result."""

    id: str | None = None
    outcome: dict[str, Any]

    @property
    def logs(self) -> list[str]:
        return list(self.outcome.get("logs", []))

    @property
    def gas_burnt(self) -> Gas:
        return Gas(int(self.outcome.get("gas_burnt", 0)))


class TransactionResult(_Model):
    """The final result of a sent transaction."""

    transaction: dict[str, Any] | None = None
    status: dict[str, Any] | str | None = None
    final_execution_status: str | None = None
    transaction_outcome: ExecutionOutcome | None = None
    receipts_outcome: list[ExecutionOutcome] = []

    @property
    def transaction_hash(self) -> str | None:
        return (self.transaction or {}).get("hash")

    @property
    def success_value(self) -> bytes | None:
        """The decoded SuccessValue, if the transaction returned one."""
        if isinstance(self.status, dict) and "SuccessValue" in self.status:
            return base64.b64decode(self.status["SuccessValue"])
        return None

    def json_value(self) -> Any:
        """The transaction's return value, JSON-decoded (None if empty)."""
        raw = self.success_value
        if not raw:
            return None
        return json.loads(raw)

    @property
    def logs(self) -> list[str]:
        """All logs across the transaction and its receipts, in order."""
        collected: list[str] = []
        if self.transaction_outcome:
            collected.extend(self.transaction_outcome.logs)
        for receipt in self.receipts_outcome:
            collected.extend(receipt.logs)
        return collected
