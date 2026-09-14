"""Action constructors — the building blocks of ``send_transaction(actions=[...])``.

Each function returns a wire-ready action model. Amounts and gas are
human-readable strings (or Amount/Gas); public keys are ``ed25519:...``
strings (or PublicKey).

Example::

    near.send_transaction(
        "sub.alice.near",
        actions=[
            create_account(),
            transfer("5 NEAR"),
            deploy_contract(wasm),
            function_call("init", {"owner": "alice.near"}),
        ],
    )
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from .keys import PublicKey
from .units import DEFAULT_GAS, ZERO, Amount, Gas, as_amount, as_gas
from .wire import (
    MAX_GAS_KEY_NONCES,
    AccessKey,
    AccessKeyPermission,
    Action,
    DeterministicAccountStateInit,
    FunctionCallPermission,
    GasKeyInfo,
    GlobalContractDeployMode,
    to_global_contract_identifier,
    to_wire_public_key,
)

__all__ = [
    "add_full_access_key",
    "add_function_call_key",
    "add_gas_key",
    "create_account",
    "delete_account",
    "delete_key",
    "deploy_contract",
    "deterministic_state_init",
    "encode_args",
    "function_call",
    "publish_contract",
    "stake",
    "transfer",
    "transfer_to_gas_key",
    "use_global_contract",
    "withdraw_from_gas_key",
]


def encode_args(args: dict[str, Any] | Sequence[Any] | bytes | None) -> bytes:
    """Encode function-call args: JSON for dicts/lists, raw bytes pass through.

    ``None`` becomes ``{}`` (what JSON-args contracts expect for "no
    arguments"); pass ``b""`` explicitly for truly empty input.
    """
    if args is None:
        return b"{}"
    if isinstance(args, bytes):
        return args
    return json.dumps(args, separators=(",", ":")).encode()


def _public_key(value: str | PublicKey) -> PublicKey:
    return PublicKey.parse(value) if isinstance(value, str) else value


def create_account() -> Action.CreateAccount:
    """Create the transaction's receiver account (a subaccount of the signer)."""
    return Action.CreateAccount()


def deploy_contract(code: bytes) -> Action.DeployContract:
    """Deploy WASM contract code to the receiver account."""
    return Action.DeployContract(code=code)


def function_call(
    method: str,
    args: dict[str, Any] | Sequence[Any] | bytes | None = None,
    *,
    gas: str | Gas = DEFAULT_GAS,
    deposit: str | Amount = ZERO,
) -> Action.FunctionCall:
    """Call a contract method on the receiver account."""
    return Action.FunctionCall(
        method_name=method,
        args=encode_args(args),
        gas=int(as_gas(gas)),
        deposit=int(as_amount(deposit, "deposit")),
    )


def transfer(amount: str | Amount) -> Action.Transfer:
    """Transfer NEAR to the receiver account."""
    return Action.Transfer(deposit=int(as_amount(amount)))


def stake(amount: str | Amount, public_key: str | PublicKey) -> Action.Stake:
    """Stake NEAR with a validator key (validators only)."""
    return Action.Stake(
        stake=int(as_amount(amount, "stake")),
        public_key=to_wire_public_key(_public_key(public_key)),
    )


def add_full_access_key(public_key: str | PublicKey) -> Action.AddKey:
    """Add a full-access key to the receiver account."""
    return Action.AddKey(
        public_key=to_wire_public_key(_public_key(public_key)),
        access_key=AccessKey(nonce=0, permission=AccessKeyPermission.FullAccess()),
    )


def add_function_call_key(
    public_key: str | PublicKey,
    contract_id: str,
    method_names: Sequence[str] = (),
    *,
    allowance: str | Amount | None = None,
) -> Action.AddKey:
    """Add a function-call key restricted to ``contract_id`` (and optionally methods)."""
    return Action.AddKey(
        public_key=to_wire_public_key(_public_key(public_key)),
        access_key=AccessKey(
            nonce=0,
            permission=AccessKeyPermission.FunctionCall(
                allowance=int(as_amount(allowance, "allowance")) if allowance is not None else None,
                receiver_id=contract_id,
                method_names=list(method_names),
            ),
        ),
    )


def add_gas_key(
    public_key: str | PublicKey,
    num_nonces: int,
    *,
    contract_id: str | None = None,
    method_names: Sequence[str] = (),
) -> Action.AddKey:
    """Add a gas key: an access key whose own prepaid balance pays for gas.

    The key gets ``num_nonces`` independent nonce lanes (1..=1024), so that
    many transactions can be in flight at once — pick a lane with
    ``send_transaction(..., gas_key_index=n)``. It is added with an empty
    balance; fund it with :func:`transfer_to_gas_key`. ``contract_id``
    restricts it to function calls on that contract like
    :func:`add_function_call_key`, minus the allowance: the protocol forbids
    one on gas keys, whose prepaid balance plays that role.
    """
    if isinstance(num_nonces, bool) or not isinstance(num_nonces, int):
        raise TypeError(f"num_nonces must be an int, got {type(num_nonces).__name__}")
    if not 1 <= num_nonces <= MAX_GAS_KEY_NONCES:
        raise ValueError(f"num_nonces must be in 1..={MAX_GAS_KEY_NONCES}, got {num_nonces}")
    info = GasKeyInfo(balance=0, num_nonces=num_nonces)
    permission: AccessKeyPermission.GasKeyFullAccess | AccessKeyPermission.GasKeyFunctionCall
    if contract_id is None:
        if method_names:
            raise ValueError("method_names requires contract_id")
        permission = AccessKeyPermission.GasKeyFullAccess(gas_key_info=info)
    else:
        permission = AccessKeyPermission.GasKeyFunctionCall(
            gas_key_info=info,
            function_call=FunctionCallPermission(
                allowance=None, receiver_id=contract_id, method_names=list(method_names)
            ),
        )
    return Action.AddKey(
        public_key=to_wire_public_key(_public_key(public_key)),
        access_key=AccessKey(nonce=0, permission=permission),
    )


def delete_key(public_key: str | PublicKey) -> Action.DeleteKey:
    """Remove an access key from the receiver account."""
    return Action.DeleteKey(public_key=to_wire_public_key(_public_key(public_key)))


def delete_account(beneficiary_id: str) -> Action.DeleteAccount:
    """Delete the receiver account, sending its balance to ``beneficiary_id``."""
    return Action.DeleteAccount(beneficiary_id=beneficiary_id)


def transfer_to_gas_key(
    public_key: str | PublicKey, amount: str | Amount
) -> Action.TransferToGasKey:
    """Move NEAR from the receiver account into one of its gas keys' balance."""
    return Action.TransferToGasKey(
        public_key=to_wire_public_key(_public_key(public_key)),
        deposit=int(as_amount(amount)),
    )


def withdraw_from_gas_key(
    public_key: str | PublicKey, amount: str | Amount
) -> Action.WithdrawFromGasKey:
    """Move NEAR from a gas key's balance back to the receiver account (transactions only)."""
    return Action.WithdrawFromGasKey(
        public_key=to_wire_public_key(_public_key(public_key)),
        amount=int(as_amount(amount)),
    )


def publish_contract(
    code: bytes, *, identified_by: Literal["account", "hash"] = "account"
) -> Action.DeployGlobalContract:
    """Publish WASM as a global contract that any account can deploy by reference.

    ``"account"`` (default) identifies it by the publisher's account ID and
    stays updatable: re-publishing swaps the code for every account using
    it. ``"hash"`` identifies it by code hash and is immutable. Publishing
    burns storage cost for the code size (from the signer's balance).
    """
    if identified_by == "hash":
        mode: GlobalContractDeployMode.CodeHash | GlobalContractDeployMode.AccountId = (
            GlobalContractDeployMode.CodeHash()
        )
    elif identified_by == "account":
        mode = GlobalContractDeployMode.AccountId()
    else:
        raise ValueError(f'identified_by must be "account" or "hash", got {identified_by!r}')
    return Action.DeployGlobalContract(code=code, deploy_mode=mode)


def use_global_contract(
    *, code_hash: str | bytes | None = None, account_id: str | None = None
) -> Action.UseGlobalContract:
    """Deploy a published global contract to the receiver account.

    Reference it by ``code_hash`` (base58 string or 32 raw bytes) or by the
    publisher's ``account_id`` — exactly one of the two.
    """
    return Action.UseGlobalContract(
        contract_identifier=to_global_contract_identifier(
            code_hash=code_hash, account_id=account_id
        )
    )


def deterministic_state_init(
    *,
    code_hash: str | bytes | None = None,
    account_id: str | None = None,
    data: Mapping[bytes, bytes] | None = None,
    deposit: str | Amount,
) -> Action.DeterministicStateInit:
    """Create a NEP-616 deterministic account from a global contract plus initial storage.

    The account's ID is a function of this exact state — derive it with
    :func:`~near.state_init.derive_deterministic_account_id` on the returned
    action's ``state_init`` and use it as the transaction receiver. ``data``
    seeds the contract's storage (raw key/value bytes). ``deposit`` covers
    the storage stake; whatever is not needed is refunded.
    """
    state_init = DeterministicAccountStateInit(
        code=to_global_contract_identifier(code_hash=code_hash, account_id=account_id),
        data=list((data or {}).items()),
    )
    return Action.DeterministicStateInit(
        state_init=state_init, deposit=int(as_amount(deposit, "deposit"))
    )
