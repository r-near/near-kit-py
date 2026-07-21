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
from .wire import AnyAction, Transaction, to_wire_public_key

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


def access_key_params(account_id: str, public_key: str) -> dict[str, Any]:
    return {
        "request_type": "view_access_key",
        "account_id": account_id,
        "public_key": public_key,
        "finality": "final",
    }


def access_key_list_params(account_id: str, block: int | str | None = None) -> dict[str, Any]:
    return {"request_type": "view_access_key_list", "account_id": account_id, **_block_ref(block)}


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


def build_transaction(
    signer: Signer,
    receiver_id: str,
    actions: list[AnyAction],
    nonce: int,
    block_hash_b58: str,
) -> Transaction:
    return Transaction(
        signer_id=signer.account_id,
        public_key=to_wire_public_key(signer.public_key),
        nonce=nonce,
        receiver_id=receiver_id,
        block_hash=base58.b58decode(block_hash_b58),
        actions=actions,
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
    """Per-client nonce reservation, safe under threads and asyncio tasks."""

    def __init__(self) -> None:
        self._nonces: dict[str, int] = {}
        self._lock = threading.Lock()

    @staticmethod
    def key(signer: Signer) -> str:
        return f"{signer.account_id}:{signer.public_key}"

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
