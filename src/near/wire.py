"""Borsh wire types for NEAR transactions (pyborsh/Pydantic models).

Variant declaration order IS the Borsh discriminant and must match nearcore
exactly — reordering anything here breaks every signature this library
produces. Reference: nearcore ``core/primitives/src/transaction.rs`` and
near-kit-ts ``src/core/schema.ts``.

Only V0 transactions are modeled (the standard format for everything except
gas keys, which are out of scope until the gas-keys fast-follow).
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Annotated, Literal, cast

import base58
from pyborsh import U64, U128, Borsh, BorshEnum, Bytes
from pydantic import BaseModel

from .errors import InvalidKeyError
from .keys import KeyType, PublicKey

if TYPE_CHECKING:
    from .keys import Signer

# NEP-461 domain tags: prepended (as borsh u32) before hashing so signatures
# over these payloads can never collide with transaction signatures.
NEP366_DELEGATE_PREFIX = (1 << 30) + 366  # meta-transactions
NEP413_MESSAGE_TAG = (1 << 31) + 413  # off-chain message signing


class PublicKeyWire(BorshEnum):
    """PublicKey enum: 0 = Ed25519, 1 = Secp256k1, 2 = ML-DSA-65."""

    class Ed25519(Borsh, BaseModel):
        variant: Literal["Ed25519"] = "Ed25519"
        data: Annotated[bytes, Bytes(32)]

    class Secp256k1(Borsh, BaseModel):
        variant: Literal["Secp256k1"] = "Secp256k1"
        data: Annotated[bytes, Bytes(64)]

    class MlDsa65(Borsh, BaseModel):
        variant: Literal["MlDsa65"] = "MlDsa65"
        data: Annotated[bytes, Bytes(1952)]


AnyPublicKey = PublicKeyWire.Ed25519 | PublicKeyWire.Secp256k1 | PublicKeyWire.MlDsa65


class SignatureWire(BorshEnum):
    """Signature enum: 0 = Ed25519 (64 B), 1 = Secp256k1 (65 B), 2 = ML-DSA-65 (3309 B)."""

    class Ed25519(Borsh, BaseModel):
        variant: Literal["Ed25519"] = "Ed25519"
        data: Annotated[bytes, Bytes(64)]

    class Secp256k1(Borsh, BaseModel):
        variant: Literal["Secp256k1"] = "Secp256k1"
        data: Annotated[bytes, Bytes(65)]

    class MlDsa65(Borsh, BaseModel):
        variant: Literal["MlDsa65"] = "MlDsa65"
        data: Annotated[bytes, Bytes(3309)]


AnySignature = SignatureWire.Ed25519 | SignatureWire.Secp256k1 | SignatureWire.MlDsa65


class AccessKeyPermission(BorshEnum):
    """AccessKeyPermission enum: 0 = FunctionCall, 1 = FullAccess.

    (Discriminants 2/3 are the gas-key permissions, which this library never
    serializes; omitting trailing variants does not affect 0/1 encodings.)
    """

    class FunctionCall(Borsh, BaseModel):
        variant: Literal["FunctionCall"] = "FunctionCall"
        # NOTE: the width annotation must live INSIDE the union arm
        # (Annotated[int, U128] | None) to encode Option<u128>.
        allowance: Annotated[int, U128] | None
        receiver_id: str
        method_names: list[str]

    class FullAccess(Borsh, BaseModel):
        variant: Literal["FullAccess"] = "FullAccess"


AnyAccessKeyPermission = AccessKeyPermission.FunctionCall | AccessKeyPermission.FullAccess


class AccessKey(Borsh, BaseModel):
    nonce: Annotated[int, U64]
    permission: AnyAccessKeyPermission


class Action(BorshEnum):
    """The NEAR Action enum. Declaration order = protocol discriminants 0..8."""

    class CreateAccount(Borsh, BaseModel):
        variant: Literal["CreateAccount"] = "CreateAccount"

    class DeployContract(Borsh, BaseModel):
        variant: Literal["DeployContract"] = "DeployContract"
        code: bytes

    class FunctionCall(Borsh, BaseModel):
        variant: Literal["FunctionCall"] = "FunctionCall"
        method_name: str
        args: bytes
        gas: Annotated[int, U64]
        deposit: Annotated[int, U128]

    class Transfer(Borsh, BaseModel):
        variant: Literal["Transfer"] = "Transfer"
        deposit: Annotated[int, U128]

    class Stake(Borsh, BaseModel):
        variant: Literal["Stake"] = "Stake"
        stake: Annotated[int, U128]
        public_key: AnyPublicKey

    class AddKey(Borsh, BaseModel):
        variant: Literal["AddKey"] = "AddKey"
        public_key: AnyPublicKey
        access_key: AccessKey

    class DeleteKey(Borsh, BaseModel):
        variant: Literal["DeleteKey"] = "DeleteKey"
        public_key: AnyPublicKey

    class DeleteAccount(Borsh, BaseModel):
        variant: Literal["DeleteAccount"] = "DeleteAccount"
        beneficiary_id: str

    class SignedDelegate(Borsh, BaseModel):
        variant: Literal["SignedDelegate"] = "SignedDelegate"
        delegate_action: DelegateAction
        signature: AnySignature


AnyAction = (
    Action.CreateAccount
    | Action.DeployContract
    | Action.FunctionCall
    | Action.Transfer
    | Action.Stake
    | Action.AddKey
    | Action.DeleteKey
    | Action.DeleteAccount
    | Action.SignedDelegate
)

# Actions permitted inside a DelegateAction (nearcore's NonDelegateAction).
# Same discriminants as Action (0..7); nesting delegates is forbidden.
NonDelegateAction = (
    Action.CreateAccount
    | Action.DeployContract
    | Action.FunctionCall
    | Action.Transfer
    | Action.Stake
    | Action.AddKey
    | Action.DeleteKey
    | Action.DeleteAccount
)


class DelegateAction(Borsh, BaseModel):
    """NEP-366 delegate action: intent signed by a user, relayed by someone else."""

    sender_id: str
    receiver_id: str
    actions: list[NonDelegateAction]
    nonce: Annotated[int, U64]
    max_block_height: Annotated[int, U64]
    public_key: AnyPublicKey


Action.SignedDelegate.model_rebuild()


class Transaction(Borsh, BaseModel):
    """A V0 NEAR transaction (the standard wire format)."""

    signer_id: str
    public_key: AnyPublicKey
    nonce: Annotated[int, U64]
    receiver_id: str
    block_hash: Annotated[bytes, Bytes(32)]
    actions: list[AnyAction]


class SignedTransaction(Borsh, BaseModel):
    transaction: Transaction
    signature: AnySignature


class Nep413Payload(Borsh, BaseModel):
    """NEP-413 message payload (hashed together with the NEP413_MESSAGE_TAG)."""

    message: str
    nonce: Annotated[bytes, Bytes(32)]
    recipient: str
    callback_url: str | None


# ---------------------------------------------------------------------------
# Conversions and signing
# ---------------------------------------------------------------------------

_PK_WIRE_BY_TYPE = {
    KeyType.ED25519: PublicKeyWire.Ed25519,
    KeyType.SECP256K1: PublicKeyWire.Secp256k1,
    KeyType.ML_DSA_65: PublicKeyWire.MlDsa65,
}
_SIG_WIRE_BY_TYPE = {
    KeyType.ED25519: SignatureWire.Ed25519,
    KeyType.SECP256K1: SignatureWire.Secp256k1,
    KeyType.ML_DSA_65: SignatureWire.MlDsa65,
}


def to_wire_public_key(public_key: PublicKey) -> AnyPublicKey:
    wire_cls = _PK_WIRE_BY_TYPE.get(public_key.key_type)
    if wire_cls is None:
        raise InvalidKeyError(f"Unsupported key type: {public_key.key_type}")
    return cast("AnyPublicKey", wire_cls(data=public_key.data))


def to_wire_signature(key_type: KeyType, data: bytes) -> AnySignature:
    wire_cls = _SIG_WIRE_BY_TYPE.get(key_type)
    if wire_cls is None:
        raise InvalidKeyError(f"Unsupported key type: {key_type}")
    return cast("AnySignature", wire_cls(data=data))


def sign_transaction(tx: Transaction, signer: Signer) -> tuple[str, bytes]:
    """Sign a transaction; returns (base58 tx hash, borsh of the SignedTransaction)."""
    raw = tx.to_borsh()
    tx_hash = hashlib.sha256(raw).digest()
    signature = signer.sign(tx_hash)
    signed = SignedTransaction(
        transaction=tx,
        signature=to_wire_signature(signer.public_key.key_type, signature),
    )
    return base58.b58encode(tx_hash).decode(), signed.to_borsh()


def delegate_action_signing_hash(delegate: DelegateAction) -> bytes:
    """The SHA-256 hash a NEP-366 delegate-action signature is made over.

    Per NEP-461, the payload is the u32 domain prefix (2^30 + 366, borsh
    little-endian) followed by the borsh of the DelegateAction.
    """
    prefix = NEP366_DELEGATE_PREFIX.to_bytes(4, "little")
    return hashlib.sha256(prefix + delegate.to_borsh()).digest()
