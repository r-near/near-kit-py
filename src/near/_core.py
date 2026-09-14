"""Shared pure logic for the sync and async clients (no I/O here)."""

from __future__ import annotations

import json
import os
import threading
from typing import Any

import base58

from .errors import RpcError, SignerRequiredError
from .keys import KeyPairSigner, Signer, load_credentials, parse_key
from .rpc import NETWORK_RPC_URLS
from .units import Amount
from .wire import (
    AnyAction,
    AnyTransaction,
    AnyTransactionNonce,
    GlobalContractIdentifier,
    NonceMode,
    Transaction,
    TransactionNonce,
    TransactionV1,
    to_global_contract_identifier,
    to_wire_public_key,
)

DEFAULT_WAIT = "EXECUTED_OPTIMISTIC"


def resolve_network(network: str | None) -> str:
    return network or os.environ.get("NEAR_NETWORK") or "mainnet"


def resolve_rpc_url(network: str, rpc_url: str | None) -> str:
    url = rpc_url or os.environ.get("NEAR_RPC_URL") or NETWORK_RPC_URLS.get(network)
    if not url:
        raise ValueError(
            f"Unknown network {network!r}: pass rpc_url= or one of {sorted(NETWORK_RPC_URLS)}"
        )
    return url


def resolve_signer(
    *,
    network: str,
    account_id: str | None,
    private_key: str | None,
    signer: Signer | None,
    credentials_dir: Any = None,
) -> Signer | None:
    """Resolution order: explicit signer > private key > env > credentials file."""
    if signer is not None:
        return signer
    account_id = account_id or os.environ.get("NEAR_ACCOUNT_ID")
    private_key = private_key or os.environ.get("NEAR_PRIVATE_KEY")
    if private_key:
        if not account_id:
            raise ValueError(
                "private_key was given but account_id is missing (set account_id= or NEAR_ACCOUNT_ID)"
            )
        return KeyPairSigner(account_id=account_id, key_pair=parse_key(private_key))
    if account_id:
        try:
            return load_credentials(account_id, network, credentials_dir=credentials_dir)
        except Exception:
            return None
    return None


def require_signer(signer: Signer | None) -> Signer:
    if signer is None:
        raise SignerRequiredError
    return signer


# ---------------------------------------------------------------------------
# Query parameter builders
# ---------------------------------------------------------------------------


def _block_ref(block: int | str | None) -> dict[str, Any]:
    if block is None:
        return {"finality": "optimistic"}
    if isinstance(block, int):
        return {"block_id": block}
    if block in ("optimistic", "near-final", "final"):
        return {"finality": block}
    return {"block_id": block}  # block hash


def view_params(
    contract_id: str, method: str, args_b64: str, block: int | str | None
) -> dict[str, Any]:
    return {
        "request_type": "call_function",
        "account_id": contract_id,
        "method_name": method,
        "args_base64": args_b64,
        **_block_ref(block),
    }


def account_params(account_id: str, block: int | str | None = None) -> dict[str, Any]:
    return {"request_type": "view_account", "account_id": account_id, **_block_ref(block)}


def access_key_params(account_id: str, public_key: str, finality: str = "final") -> dict[str, Any]:
    return {
        "request_type": "view_access_key",
        "account_id": account_id,
        "public_key": public_key,
        "finality": finality,
    }


def access_key_list_params(account_id: str, block: int | str | None = None) -> dict[str, Any]:
    return {"request_type": "view_access_key_list", "account_id": account_id, **_block_ref(block)}


def gas_key_nonces_params(
    account_id: str, public_key: str, finality: str = "final"
) -> dict[str, Any]:
    return {
        "request_type": "view_gas_key_nonces",
        "account_id": account_id,
        "public_key": public_key,
        "finality": finality,
    }


def contract_code_params(account_id: str, block: int | str | None = None) -> dict[str, Any]:
    return {"request_type": "view_code", "account_id": account_id, **_block_ref(block)}


def global_contract_params(
    *, code_hash: str | bytes | None = None, account_id: str | None = None
) -> dict[str, Any]:
    """Query params for a global contract by hash or publisher (exactly one)."""
    identifier = to_global_contract_identifier(code_hash=code_hash, account_id=account_id)
    if isinstance(identifier, GlobalContractIdentifier.CodeHash):
        return {
            "request_type": "view_global_contract_code",
            "code_hash": base58.b58encode(identifier.code_hash).decode(),
            "finality": "final",
        }
    return {
        "request_type": "view_global_contract_code_by_account_id",
        "account_id": identifier.account_id,
        "finality": "final",
    }


def decode_view_result(result: dict[str, Any], contract_id: str, method: str) -> Any:
    """Decode a call_function result: JSON if possible, raw bytes otherwise."""
    if error := result.get("error"):
        from .errors import ContractPanicError

        raise ContractPanicError(
            f"{contract_id}.{method}: {error}", logs=list(result.get("logs", []))
        )
    raw = bytes(result.get("result", []))
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return raw


def nonces_from_result(result: dict[str, Any]) -> list[int]:
    """The per-lane nonces of a ``view_gas_key_nonces`` result."""
    try:
        return [int(nonce) for nonce in result["nonces"]]
    except (KeyError, TypeError, ValueError) as exc:
        raise RpcError("Malformed view_gas_key_nonces response (no nonces list)") from exc


def lane_nonce(nonces: list[int], gas_key_index: int, account_id: str, public_key: str) -> int:
    """The current nonce of one gas-key lane, rejecting an index the key never allocated."""
    if gas_key_index >= len(nonces):
        raise ValueError(
            f"Gas key {public_key} on {account_id} has {len(nonces)} nonce lanes; "
            f"gas_key_index {gas_key_index} is out of range"
        )
    return nonces[gas_key_index]


def validate_gas_key_index(gas_key_index: int | None) -> int | None:
    """A gas-key lane index must be a u16 (the lane count itself is checked on fetch)."""
    if gas_key_index is None:
        return None
    if isinstance(gas_key_index, bool) or not isinstance(gas_key_index, int):
        raise TypeError(f"gas_key_index must be an int, got {type(gas_key_index).__name__}")
    if not 0 <= gas_key_index <= 0xFFFF:
        raise ValueError(f"gas_key_index must be in 0..=65535, got {gas_key_index}")
    return gas_key_index


def transaction_nonce(nonce: int, gas_key_index: int | None) -> AnyTransactionNonce:
    """A V1 nonce: a gas-key lane nonce when an index is given, a plain nonce otherwise."""
    if gas_key_index is None:
        return TransactionNonce.Nonce(nonce=nonce)
    return TransactionNonce.GasKeyNonce(nonce=nonce, nonce_index=gas_key_index)


def build_transaction(
    signer: Signer,
    receiver_id: str,
    actions: list[AnyAction],
    nonce: int,
    block_hash_b58: str,
    *,
    gas_key_index: int | None = None,
    strict_nonce: bool = False,
) -> AnyTransaction:
    """A V0 transaction, or V1 when a gas-key lane or strict nonce mode needs it.

    The default path is byte-for-byte the classic V0 format; only gas keys
    and strict nonces exist in V1, so nothing else opts into it.
    """
    if gas_key_index is None and not strict_nonce:
        return Transaction(
            signer_id=signer.account_id,
            public_key=to_wire_public_key(signer.public_key),
            nonce=nonce,
            receiver_id=receiver_id,
            block_hash=base58.b58decode(block_hash_b58),
            actions=actions,
        )
    return TransactionV1(
        signer_id=signer.account_id,
        public_key=to_wire_public_key(signer.public_key),
        nonce=transaction_nonce(nonce, gas_key_index),
        receiver_id=receiver_id,
        block_hash=base58.b58decode(block_hash_b58),
        actions=actions,
        nonce_mode=NonceMode.Strict() if strict_nonce else NonceMode.Monotonic(),
    )


def default_account_id(signer: Signer | None, account_id: str | None) -> str:
    if account_id:
        return account_id
    if signer is not None:
        return signer.account_id
    raise ValueError("account_id is required when the client has no signer")


def balance_from_account(result: dict[str, Any]) -> Amount:
    return Amount.yocto(int(result["amount"]))


def block_hash_of(block_result: dict[str, Any]) -> str:
    try:
        return str(block_result["header"]["hash"])
    except (KeyError, TypeError) as exc:
        raise RpcError("Malformed block response (no header.hash)") from exc


class NonceCache:
    """Per-client nonce reservation, safe under threads and asyncio tasks.

    Keys are ``account:public_key``, or ``account:public_key#lane`` for a
    gas key's nonce lanes — each lane is an independent counter on chain.
    """

    def __init__(self) -> None:
        self._nonces: dict[str, int] = {}
        self._lock = threading.Lock()

    @staticmethod
    def key(signer: Signer, gas_key_index: int | None = None) -> str:
        base = f"{signer.account_id}:{signer.public_key}"
        return base if gas_key_index is None else f"{base}#{gas_key_index}"

    def reserve(self, key: str, on_chain_nonce: int | None) -> int:
        """Reserve the next nonce, folding in a freshly fetched on-chain value."""
        with self._lock:
            base = self._nonces.get(key, 0)
            if on_chain_nonce is not None:
                base = max(base, on_chain_nonce)
            nxt = base + 1
            self._nonces[key] = nxt
            return nxt

    def has(self, key: str) -> bool:
        with self._lock:
            return key in self._nonces

    def sync_to(self, key: str, ak_nonce: int) -> None:
        """Resynchronize after an InvalidNonceError using the node-reported nonce."""
        with self._lock:
            self._nonces[key] = max(self._nonces.get(key, 0), ak_nonce)
