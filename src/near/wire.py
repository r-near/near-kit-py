"""Borsh wire types for NEAR transactions (pyborsh/Pydantic models).

Variant declaration order IS the Borsh discriminant and must match nearcore
exactly — reordering anything here breaks every signature this library
produces. Reference: nearcore 2.13 ``core/primitives/src/{transaction.rs,
action/mod.rs, action/delegate.rs}``, ``core/primitives-core/src/{account.rs,
global_contract.rs, deterministic_account_id.rs}`` and near-kit-ts
``src/core/schema.ts``.

Single-variant versioned enums (``DeterministicAccountStateInit``,
``VersionedDelegateActionPayload``) and the ``Transaction::V1`` tag are
modeled with an explicit leading ``u8`` field pinned by a ``Literal``: a
one-member union gives pyborsh no discriminant to write, and the byte is
identical either way.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from itertools import pairwise
from typing import TYPE_CHECKING, Annotated, Any, Literal, cast

import base58
from pyborsh import U8, U16, U64, U128, Borsh, BorshEnum, Bytes
from pydantic import BaseModel, field_validator

from .errors import InvalidKeyError
from .keys import KeyType, PublicKey

if TYPE_CHECKING:
    from .keys import Signer

# NEP-461 domain tags: prepended (as borsh u32) before hashing so signatures
# over these payloads can never collide with transaction signatures.
NEP366_DELEGATE_PREFIX = (1 << 30) + 366  # meta-transactions
NEP611_DELEGATE_V2_PREFIX = (1 << 30) + 611  # gas-key meta-transactions (DelegateV2)
NEP413_MESSAGE_TAG = (1 << 31) + 413  # off-chain message signing

# A gas key may allocate at most this many parallel nonce lanes (nearcore
# AccessKeyPermission::MAX_NONCES_FOR_GAS_KEY).
MAX_GAS_KEY_NONCES = 1024


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


# ---------------------------------------------------------------------------
# Access keys (including gas keys)
# ---------------------------------------------------------------------------


class GasKeyInfo(Borsh, BaseModel):
    """A gas key's prepaid gas balance and its number of parallel nonce lanes."""

    balance: Annotated[int, U128]
    num_nonces: Annotated[int, U16]


class FunctionCallPermission(Borsh, BaseModel):
    """The restriction shared by ``FunctionCall`` and ``GasKeyFunctionCall`` keys."""

    # NOTE: the width annotation must live INSIDE the union arm
    # (Annotated[int, U128] | None) to encode Option<u128>.
    allowance: Annotated[int, U128] | None
    receiver_id: str
    method_names: list[str]


class AccessKeyPermission(BorshEnum):
    """AccessKeyPermission enum: 0 = FunctionCall, 1 = FullAccess,
    2 = GasKeyFunctionCall, 3 = GasKeyFullAccess.

    nearcore's ``GasKeyFunctionCall(GasKeyInfo, FunctionCallPermission)`` is a
    tuple variant; a struct with those two fields in that order is
    byte-identical.
    """

    class FunctionCall(FunctionCallPermission):
        variant: Literal["FunctionCall"] = "FunctionCall"

    class FullAccess(Borsh, BaseModel):
        variant: Literal["FullAccess"] = "FullAccess"

    class GasKeyFunctionCall(Borsh, BaseModel):
        variant: Literal["GasKeyFunctionCall"] = "GasKeyFunctionCall"
        gas_key_info: GasKeyInfo
        function_call: FunctionCallPermission

    class GasKeyFullAccess(Borsh, BaseModel):
        variant: Literal["GasKeyFullAccess"] = "GasKeyFullAccess"
        gas_key_info: GasKeyInfo


AnyAccessKeyPermission = (
    AccessKeyPermission.FunctionCall
    | AccessKeyPermission.FullAccess
    | AccessKeyPermission.GasKeyFunctionCall
    | AccessKeyPermission.GasKeyFullAccess
)


class AccessKey(Borsh, BaseModel):
    nonce: Annotated[int, U64]
    permission: AnyAccessKeyPermission


# ---------------------------------------------------------------------------
# Global contracts and NEP-616 deterministic accounts
# ---------------------------------------------------------------------------


class GlobalContractDeployMode(BorshEnum):
    """How a published contract is referenced: 0 = CodeHash (immutable),
    1 = AccountId (the publisher can re-publish and every user follows)."""

    class CodeHash(Borsh, BaseModel):
        variant: Literal["CodeHash"] = "CodeHash"

    class AccountId(Borsh, BaseModel):
        variant: Literal["AccountId"] = "AccountId"


AnyGlobalContractDeployMode = GlobalContractDeployMode.CodeHash | GlobalContractDeployMode.AccountId


class GlobalContractIdentifier(BorshEnum):
    """GlobalContractIdentifier enum: 0 = CodeHash([u8; 32]), 1 = AccountId(String).

    nearcore's tuple variants carry the value directly; a single-field struct
    serializes identically.
    """

    class CodeHash(Borsh, BaseModel):
        variant: Literal["CodeHash"] = "CodeHash"
        code_hash: Annotated[bytes, Bytes(32)]

    class AccountId(Borsh, BaseModel):
        variant: Literal["AccountId"] = "AccountId"
        account_id: str


AnyGlobalContractIdentifier = GlobalContractIdentifier.CodeHash | GlobalContractIdentifier.AccountId


class DeterministicAccountStateInit(Borsh, BaseModel):
    """NEP-616 state init: nearcore's single-variant versioned enum (V1 = tag 0).

    ``data`` is a ``BTreeMap<Vec<u8>, Vec<u8>>`` on the wire: entries sorted
    bytewise by key, no duplicates. pyborsh writes dicts unsorted, so the map
    is held as a canonically sorted list of pairs — ``Vec<(K, V)>`` encodes to
    exactly the same bytes as a borsh map. Mappings are accepted on input.
    """

    version: Annotated[Literal[0], U8] = 0
    code: AnyGlobalContractIdentifier
    data: list[tuple[bytes, bytes]] = []

    @field_validator("data", mode="before")
    @classmethod
    def _canonical_entries(cls, value: Any) -> list[tuple[bytes, bytes]]:
        entries: Iterable[tuple[bytes, bytes]] = (
            value.items() if isinstance(value, Mapping) else value
        )
        ordered = sorted(((bytes(k), bytes(v)) for k, v in entries), key=lambda kv: kv[0])
        for (left, _), (right, _) in pairwise(ordered):
            if left == right:
                raise ValueError(f"duplicate state-init key: {left!r}")
        return ordered


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


class TransactionNonce(BorshEnum):
    """TransactionNonce enum: 0 = Nonce {nonce}, 1 = GasKeyNonce {nonce, nonce_index}."""

    class Nonce(Borsh, BaseModel):
        variant: Literal["Nonce"] = "Nonce"
        nonce: Annotated[int, U64]

    class GasKeyNonce(Borsh, BaseModel):
        variant: Literal["GasKeyNonce"] = "GasKeyNonce"
        nonce: Annotated[int, U64]
        nonce_index: Annotated[int, U16]


AnyTransactionNonce = TransactionNonce.Nonce | TransactionNonce.GasKeyNonce


class NonceMode(BorshEnum):
    """NonceMode enum: 0 = Monotonic (nonce > current), 1 = Strict (nonce == current + 1)."""

    class Monotonic(Borsh, BaseModel):
        variant: Literal["Monotonic"] = "Monotonic"

    class Strict(Borsh, BaseModel):
        variant: Literal["Strict"] = "Strict"


AnyNonceMode = NonceMode.Monotonic | NonceMode.Strict


class Action(BorshEnum):
    """The NEAR Action enum. Declaration order = protocol discriminants 0..14."""

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

    class DeployGlobalContract(Borsh, BaseModel):
        variant: Literal["DeployGlobalContract"] = "DeployGlobalContract"
        code: bytes
        deploy_mode: AnyGlobalContractDeployMode

    class UseGlobalContract(Borsh, BaseModel):
        variant: Literal["UseGlobalContract"] = "UseGlobalContract"
        contract_identifier: AnyGlobalContractIdentifier

    class DeterministicStateInit(Borsh, BaseModel):
        variant: Literal["DeterministicStateInit"] = "DeterministicStateInit"
        state_init: DeterministicAccountStateInit
        deposit: Annotated[int, U128]

    class TransferToGasKey(Borsh, BaseModel):
        variant: Literal["TransferToGasKey"] = "TransferToGasKey"
        public_key: AnyPublicKey
        deposit: Annotated[int, U128]

    class WithdrawFromGasKey(Borsh, BaseModel):
        variant: Literal["WithdrawFromGasKey"] = "WithdrawFromGasKey"
        public_key: AnyPublicKey
        amount: Annotated[int, U128]

    class DelegateV2(Borsh, BaseModel):
        """nearcore's ``VersionedSignedDelegateAction``, carried by ``Action::DelegateV2``."""

        variant: Literal["DelegateV2"] = "DelegateV2"
        delegate_action: VersionedDelegateActionPayload
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
    | Action.DeployGlobalContract
    | Action.UseGlobalContract
    | Action.DeterministicStateInit
    | Action.TransferToGasKey
    | Action.WithdrawFromGasKey
    | Action.DelegateV2
)

# Actions permitted inside a delegate action (nearcore's NonDelegateAction):
# every Action except the two delegate variants (8 and 14), so nesting is
# impossible. A subset union keeps the parent's discriminants.
NonDelegateAction = (
    Action.CreateAccount
    | Action.DeployContract
    | Action.FunctionCall
    | Action.Transfer
    | Action.Stake
    | Action.AddKey
    | Action.DeleteKey
    | Action.DeleteAccount
    | Action.DeployGlobalContract
    | Action.UseGlobalContract
    | Action.DeterministicStateInit
    | Action.TransferToGasKey
    | Action.WithdrawFromGasKey
)

AnySignedDelegate = Action.SignedDelegate | Action.DelegateV2


class DelegateAction(Borsh, BaseModel):
    """NEP-366 delegate action: intent signed by a user, relayed by someone else."""

    sender_id: str
    receiver_id: str
    actions: list[NonDelegateAction]
    nonce: Annotated[int, U64]
    max_block_height: Annotated[int, U64]
    public_key: AnyPublicKey


class DelegateActionV2(Borsh, BaseModel):
    """NEP-611 delegate action: like V1, but the nonce may address a gas-key lane."""

    sender_id: str
    receiver_id: str
    actions: list[NonDelegateAction]
    nonce: AnyTransactionNonce
    max_block_height: Annotated[int, U64]
    public_key: AnyPublicKey


class VersionedDelegateActionPayload(Borsh, BaseModel):
    """nearcore's ``VersionedDelegateActionPayload`` enum, whose only variant is V2 (tag 0).

    The tag is part of the NEP-611 signed bytes, so it is modeled explicitly.
    """

    version: Annotated[Literal[0], U8] = 0
    v2: DelegateActionV2


VersionedSignedDelegateAction = Action.DelegateV2

Action.SignedDelegate.model_rebuild()
Action.DelegateV2.model_rebuild()


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------


class Transaction(Borsh, BaseModel):
    """A V0 NEAR transaction (the standard, tag-less wire format)."""

    signer_id: str
    public_key: AnyPublicKey
    nonce: Annotated[int, U64]
    receiver_id: str
    block_hash: Annotated[bytes, Bytes(32)]
    actions: list[AnyAction]


class SignedTransaction(Borsh, BaseModel):
    transaction: Transaction
    signature: AnySignature


class TransactionV1(Borsh, BaseModel):
    """A V1 transaction: gas-key nonces and strict nonce mode (nearcore 2.13).

    On the wire a V1 transaction is ``[0x01] ++ borsh(TransactionV1)`` while V0
    stays tag-less; the leading ``version`` field writes that tag so
    ``to_borsh()`` is the exact signing payload.
    """

    version: Annotated[Literal[1], U8] = 1
    signer_id: str
    public_key: AnyPublicKey
    nonce: AnyTransactionNonce
    receiver_id: str
    block_hash: Annotated[bytes, Bytes(32)]
    actions: list[AnyAction]
    nonce_mode: AnyNonceMode = NonceMode.Monotonic()


class SignedTransactionV1(Borsh, BaseModel):
    """``[0x01] ++ borsh(TransactionV1) ++ borsh(Signature)`` — plain concatenation."""

    transaction: TransactionV1
    signature: AnySignature


AnyTransaction = Transaction | TransactionV1


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


def to_global_contract_identifier(
    *, code_hash: str | bytes | None = None, account_id: str | None = None
) -> AnyGlobalContractIdentifier:
    """A global contract reference from exactly one of a code hash or a publisher account.

    ``code_hash`` is a base58 string (as the RPC reports it) or 32 raw bytes.
    """
    if (code_hash is None) == (account_id is None):
        raise ValueError("Pass exactly one of code_hash= or account_id=")
    if account_id is not None:
        return GlobalContractIdentifier.AccountId(account_id=account_id)
    if isinstance(code_hash, str):
        try:
            raw = base58.b58decode(code_hash)
        except ValueError as exc:
            raise ValueError(f"code_hash is not valid base58: {code_hash!r}") from exc
    else:
        raw = bytes(cast("bytes", code_hash))
    if len(raw) != 32:
        raise ValueError(f"code_hash must be 32 bytes, got {len(raw)}")
    return GlobalContractIdentifier.CodeHash(code_hash=raw)


def sign_transaction(tx: AnyTransaction, signer: Signer) -> tuple[str, bytes]:
    """Sign a transaction; returns (base58 tx hash, wire bytes of the signed transaction).

    The hash is SHA-256 of the transaction's wire bytes — for V1 that
    includes the version tag, exactly as nearcore hashes it.
    """
    raw = tx.to_borsh()
    tx_hash = hashlib.sha256(raw).digest()
    signature = to_wire_signature(signer.public_key.key_type, signer.sign(tx_hash))
    signed: SignedTransaction | SignedTransactionV1 = (
        SignedTransactionV1(transaction=tx, signature=signature)
        if isinstance(tx, TransactionV1)
        else SignedTransaction(transaction=tx, signature=signature)
    )
    return base58.b58encode(tx_hash).decode(), signed.to_borsh()


def delegate_action_signing_hash(delegate: DelegateAction) -> bytes:
    """The SHA-256 hash a NEP-366 delegate-action signature is made over.

    Per NEP-461, the payload is the u32 domain prefix (2^30 + 366, borsh
    little-endian) followed by the borsh of the DelegateAction.
    """
    prefix = NEP366_DELEGATE_PREFIX.to_bytes(4, "little")
    return hashlib.sha256(prefix + delegate.to_borsh()).digest()


def delegate_action_v2_signing_hash(payload: VersionedDelegateActionPayload) -> bytes:
    """The SHA-256 hash a NEP-611 (DelegateV2) signature is made over.

    The domain prefix is 2^30 + 611 — distinct from V1, so a V1 signature can
    never validate a V2 action — and the signed bytes are the *versioned*
    payload, i.e. the ``0x00`` V2 tag is included.
    """
    prefix = NEP611_DELEGATE_V2_PREFIX.to_bytes(4, "little")
    return hashlib.sha256(prefix + payload.to_borsh()).digest()
