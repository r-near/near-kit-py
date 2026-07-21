"""NEP-413 off-chain message signing.

Signs human-readable messages (login flows, ownership proofs) with a NEAR
key, domain-separated from transactions by the NEP-413 tag so a signed
message can never be replayed as a transaction.

Spec: https://github.com/near/NEPs/blob/master/neps/nep-0413.md
"""

from __future__ import annotations

import base64 as b64
import hashlib
import os
import time

from pydantic import BaseModel

from .errors import InvalidKeyError
from .keys import KeyType, PublicKey, Signer
from .wire import NEP413_MESSAGE_TAG, Nep413Payload

__all__ = ["SignedMessage", "generate_nonce", "nep413_hash", "sign_message", "verify_message"]


class SignedMessage(BaseModel):
    """A NEP-413 signed message (signature is standard base64)."""

    account_id: str
    public_key: str
    signature: str


def nep413_hash(
    message: str,
    recipient: str,
    nonce: bytes,
    callback_url: str | None = None,
) -> bytes:
    """SHA-256 of the NEP-413 tag + borsh payload — the bytes that get signed."""
    if len(nonce) != 32:
        raise ValueError(f"NEP-413 nonce must be exactly 32 bytes, got {len(nonce)}")
    payload = Nep413Payload(
        message=message, nonce=nonce, recipient=recipient, callback_url=callback_url
    )
    tag = NEP413_MESSAGE_TAG.to_bytes(4, "little")
    return hashlib.sha256(tag + payload.to_borsh()).digest()


def generate_nonce() -> bytes:
    """A 32-byte nonce: 8 bytes big-endian ms timestamp + 24 random bytes.

    The embedded timestamp is a near-kit convention that lets
    :func:`verify_message` check expiry; NEP-413 itself treats nonces as
    opaque.
    """
    timestamp = int(time.time() * 1000).to_bytes(8, "big")
    return timestamp + os.urandom(24)


def sign_message(
    signer: Signer,
    message: str,
    recipient: str,
    nonce: bytes | None = None,
    callback_url: str | None = None,
) -> SignedMessage:
    """Sign a NEP-413 message with ``signer`` (must be an ed25519 key)."""
    if signer.public_key.key_type != KeyType.ED25519:
        raise InvalidKeyError("NEP-413 signing requires an ed25519 key")
    nonce = nonce if nonce is not None else generate_nonce()
    digest = nep413_hash(message, recipient, nonce, callback_url)
    return SignedMessage(
        account_id=signer.account_id,
        public_key=str(signer.public_key),
        signature=b64.b64encode(signer.sign(digest)).decode(),
    )


def verify_message(
    signed: SignedMessage,
    message: str,
    recipient: str,
    nonce: bytes,
    callback_url: str | None = None,
    *,
    max_age_ms: int | None = 5 * 60 * 1000,
) -> bool:
    """Verify a NEP-413 signature (and, by default, the timestamp-nonce expiry).

    Pass ``max_age_ms=None`` for custom nonce schemes; you are then
    responsible for nonce/replay validation. Note this checks the signature
    only — to also prove the key belongs to the account on chain, check
    ``near.access_key(signed.account_id, signed.public_key)`` is FullAccess.
    """
    if max_age_ms is not None and len(nonce) == 32:
        timestamp = int.from_bytes(nonce[:8], "big")
        age = time.time() * 1000 - timestamp
        if age > max_age_ms or age < 0:
            return False
    try:
        public_key = PublicKey.parse(signed.public_key)
        signature = b64.b64decode(signed.signature)
        digest = nep413_hash(message, recipient, nonce, callback_url)
        return public_key.verify(signature, digest)
    except (InvalidKeyError, ValueError):
        return False
