"""near-kit: a Pythonic SDK for NEAR Protocol. Feels like requests.

Stateless reads work straight off the module::

    import near

    near.view("counter.near", "get_count")
    near.balance("alice.near", network="testnet")

Anything that signs needs a client (it holds your signer, nonce cache, and
connection pool)::

    from near import Near

    client = Near(network="testnet", account_id="alice.testnet", private_key="ed25519:...")
    client.call("counter.testnet", "increment", deposit="0.1 NEAR")
"""

from typing import Any

from .aclient import AsyncNear
from .actions import (
    add_full_access_key,
    add_function_call_key,
    create_account,
    delete_account,
    delete_key,
    deploy_contract,
    function_call,
    stake,
    transfer,
)
from .client import Near
from .errors import (
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
from .keys import (
    Ed25519KeyPair,
    KeyPairSigner,
    KeyType,
    MlDsa65KeyPair,
    PublicKey,
    Signer,
    generate_key,
    generate_seed_phrase,
    is_valid_account_id,
    key_from_seed_phrase,
    parse_key,
    validate_account_id,
)
from .models import AccessKeyView, AccountView, KeyInfo, TransactionResult
from .nep413 import SignedMessage, generate_nonce, verify_message
from .tokens import FTMetadata, TokenAmount
from .units import DEFAULT_GAS, MAX_GAS, ONE_YOCTO, ZERO, Amount, Gas

__version__ = "1.1.0"


# ---------------------------------------------------------------------------
# Module-level one-shots: stateless reads, requests-style.
# If it signs, you need a client.
# ---------------------------------------------------------------------------


def view(
    contract_id: str,
    method: str,
    args: dict[str, Any] | bytes | None = None,
    *,
    network: str | None = None,
    rpc_url: str | None = None,
    block: int | str | None = None,
) -> Any:
    """One-shot read-only contract call (defaults to mainnet)."""
    with Near(network, rpc_url=rpc_url) as client:
        return client.view(contract_id, method, args, block=block)


def balance(account_id: str, *, network: str | None = None, rpc_url: str | None = None) -> Amount:
    """One-shot balance lookup (defaults to mainnet)."""
    with Near(network, rpc_url=rpc_url) as client:
        return client.balance(account_id)


def account(
    account_id: str, *, network: str | None = None, rpc_url: str | None = None
) -> AccountView:
    """One-shot account lookup (defaults to mainnet)."""
    with Near(network, rpc_url=rpc_url) as client:
        return client.account(account_id)


def account_exists(
    account_id: str, *, network: str | None = None, rpc_url: str | None = None
) -> bool:
    """One-shot existence check (defaults to mainnet)."""
    with Near(network, rpc_url=rpc_url) as client:
        return client.account_exists(account_id)


__all__ = [
    "DEFAULT_GAS",
    "MAX_GAS",
    "ONE_YOCTO",
    "ZERO",
    "AccessKeyNotFoundError",
    "AccessKeyView",
    "AccountNotFoundError",
    "AccountView",
    "Amount",
    "AsyncNear",
    "ContractPanicError",
    "Ed25519KeyPair",
    "FTMetadata",
    "Gas",
    "InsufficientBalanceError",
    "InvalidAccountIdError",
    "InvalidKeyError",
    "InvalidNonceError",
    "KeyInfo",
    "KeyPairSigner",
    "KeyType",
    "MlDsa65KeyPair",
    "Near",
    "NearError",
    "PublicKey",
    "RpcError",
    "SignedMessage",
    "Signer",
    "SignerRequiredError",
    "TokenAmount",
    "TransactionExpiredError",
    "TransactionResult",
    "UnitParseError",
    "account",
    "account_exists",
    "add_full_access_key",
    "add_function_call_key",
    "balance",
    "create_account",
    "delete_account",
    "delete_key",
    "deploy_contract",
    "function_call",
    "generate_key",
    "generate_nonce",
    "generate_seed_phrase",
    "is_valid_account_id",
    "key_from_seed_phrase",
    "parse_key",
    "stake",
    "transfer",
    "validate_account_id",
    "verify_message",
    "view",
]
