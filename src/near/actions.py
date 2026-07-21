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
from collections.abc import Sequence
from typing import Any

from .keys import PublicKey
from .units import DEFAULT_GAS, ZERO, Amount, Gas, as_amount, as_gas
from .wire import AccessKey, AccessKeyPermission, Action, to_wire_public_key

__all__ = [
    "add_full_access_key",
    "add_function_call_key",
    "create_account",
    "delete_account",
    "delete_key",
    "deploy_contract",
    "encode_args",
    "function_call",
    "stake",
    "transfer",
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


def delete_key(public_key: str | PublicKey) -> Action.DeleteKey:
    """Remove an access key from the receiver account."""
    return Action.DeleteKey(public_key=to_wire_public_key(_public_key(public_key)))


def delete_account(beneficiary_id: str) -> Action.DeleteAccount:
    """Delete the receiver account, sending its balance to ``beneficiary_id``."""
    return Action.DeleteAccount(beneficiary_id=beneficiary_id)
