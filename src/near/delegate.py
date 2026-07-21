"""NEP-366 meta-transactions (delegate actions).

A user signs a :class:`~near.wire.DelegateAction` off-chain; a relayer wraps
it in a transaction and pays the gas. ``encode``/``decode`` give you a
base64 string safe to ship between the two parties.
"""

from __future__ import annotations

import base64 as b64

from .keys import Signer
from .wire import (
    Action,
    DelegateAction,
    delegate_action_signing_hash,
    to_wire_signature,
)

__all__ = ["decode_signed_delegate", "encode_signed_delegate", "sign_delegate_action"]


def sign_delegate_action(delegate: DelegateAction, signer: Signer) -> Action.SignedDelegate:
    """Sign a delegate action under the NEP-461 delegate domain tag."""
    digest = delegate_action_signing_hash(delegate)
    signature = signer.sign(digest)
    return Action.SignedDelegate(
        delegate_action=delegate,
        signature=to_wire_signature(signer.public_key.key_type, signature),
    )


def encode_signed_delegate(signed: Action.SignedDelegate) -> str:
    """Base64-encode a signed delegate for transport to a relayer."""
    return b64.b64encode(signed.to_borsh()).decode()


def decode_signed_delegate(payload: str) -> Action.SignedDelegate:
    """Decode a base64 signed delegate received from a user."""
    return Action.SignedDelegate.from_borsh(b64.b64decode(payload))
