"""Meta-transactions: NEP-366 delegate actions and their NEP-611 (V2) successor.

A user signs a :class:`~near.wire.DelegateAction` (or
:class:`~near.wire.DelegateActionV2`, which can be signed by a gas key)
off-chain; a relayer wraps it in a transaction and pays the gas.
``encode``/``decode`` give you a base64 string safe to ship between the two
parties.
"""

from __future__ import annotations

import base64 as b64

from .keys import Signer
from .wire import (
    Action,
    AnySignedDelegate,
    DelegateAction,
    DelegateActionV2,
    VersionedDelegateActionPayload,
    delegate_action_signing_hash,
    delegate_action_v2_signing_hash,
    to_wire_signature,
)

__all__ = [
    "decode_any_signed_delegate",
    "decode_signed_delegate",
    "decode_signed_delegate_v2",
    "delegate_sender",
    "encode_signed_delegate",
    "sign_delegate_action",
    "sign_delegate_action_v2",
]


def sign_delegate_action(delegate: DelegateAction, signer: Signer) -> Action.SignedDelegate:
    """Sign a delegate action under the NEP-461 delegate domain tag."""
    digest = delegate_action_signing_hash(delegate)
    signature = signer.sign(digest)
    return Action.SignedDelegate(
        delegate_action=delegate,
        signature=to_wire_signature(signer.public_key.key_type, signature),
    )


def sign_delegate_action_v2(delegate: DelegateActionV2, signer: Signer) -> Action.DelegateV2:
    """Sign a V2 delegate action under the NEP-611 domain tag (distinct from V1's)."""
    payload = VersionedDelegateActionPayload(v2=delegate)
    signature = signer.sign(delegate_action_v2_signing_hash(payload))
    return Action.DelegateV2(
        delegate_action=payload,
        signature=to_wire_signature(signer.public_key.key_type, signature),
    )


def encode_signed_delegate(signed: AnySignedDelegate) -> str:
    """Base64-encode a signed delegate (either version) for transport to a relayer."""
    return b64.b64encode(signed.to_borsh()).decode()


def decode_signed_delegate(payload: str) -> Action.SignedDelegate:
    """Decode a base64 NEP-366 signed delegate received from a user."""
    return Action.SignedDelegate.from_borsh(b64.b64decode(payload))


def decode_signed_delegate_v2(payload: str) -> Action.DelegateV2:
    """Decode a base64 NEP-611 (V2) signed delegate received from a user."""
    return Action.DelegateV2.from_borsh(b64.b64decode(payload))


def decode_any_signed_delegate(payload: str) -> AnySignedDelegate:
    """Decode a signed delegate of either version.

    The two encodings cannot be confused: a V2 payload starts with its
    ``0x00`` version tag, a V1 payload with the sender ID's length (never
    zero — account IDs are at least two characters).
    """
    raw = b64.b64decode(payload)
    if raw[:1] == b"\x00":
        return Action.DelegateV2.from_borsh(raw)
    return Action.SignedDelegate.from_borsh(raw)


def delegate_sender(signed: AnySignedDelegate) -> str:
    """The account whose intent a signed delegate carries (the relay transaction's receiver)."""
    if isinstance(signed, Action.DelegateV2):
        return signed.delegate_action.v2.sender_id
    return signed.delegate_action.sender_id
