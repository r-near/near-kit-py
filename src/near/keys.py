"""Keys, signing, and account-ID validation.

Key strings use NEAR's standard encodings: ``ed25519:<base58>`` for public
keys (32 bytes) and secret keys (64 bytes: seed then public key), and
``ml-dsa-65:<base58>`` for ML-DSA-65 seeds. Any object satisfying the
:class:`Signer` protocol can sign for a client — key pairs here, or your own
KMS/HSM-backed implementation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

import base58
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from mnemonic import Mnemonic

from .errors import InvalidAccountIdError, InvalidKeyError

__all__ = [
    "ED25519_PREFIX",
    "ML_DSA_65_HASH_PREFIX",
    "ML_DSA_65_PREFIX",
    "Ed25519KeyPair",
    "KeyPairSigner",
    "KeyType",
    "MlDsa65KeyPair",
    "PublicKey",
    "Signer",
    "generate_key",
    "generate_seed_phrase",
    "is_valid_account_id",
    "key_from_seed_phrase",
    "load_credentials",
    "parse_key",
    "validate_account_id",
]

ED25519_PREFIX = "ed25519:"
SECP256K1_PREFIX = "secp256k1:"
ML_DSA_65_PREFIX = "ml-dsa-65:"
ML_DSA_65_HASH_PREFIX = "ml-dsa-65-hash:"

ML_DSA_65_SEED_LENGTH = 32
ML_DSA_65_PUBLIC_KEY_LENGTH = 1952
# nearcore/near-cli credentials may store the 4032-byte expanded secret key;
# pyca/cryptography can only import the 32-byte seed form.
ML_DSA_65_EXPANDED_SECRET_LENGTH = 4032

_ACCOUNT_ID_RE = re.compile(r"^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$")


class KeyType(IntEnum):
    """NEAR key curve identifiers (also the Borsh enum discriminants)."""

    ED25519 = 0
    SECP256K1 = 1
    ML_DSA_65 = 2


@dataclass(frozen=True)
class PublicKey:
    """A NEAR public key: curve type plus raw key bytes."""

    key_type: KeyType
    data: bytes = field(repr=False)

    def __str__(self) -> str:
        prefix = {
            KeyType.ED25519: ED25519_PREFIX,
            KeyType.SECP256K1: SECP256K1_PREFIX,
            KeyType.ML_DSA_65: ML_DSA_65_PREFIX,
        }[self.key_type]
        return prefix + base58.b58encode(self.data).decode()

    def __repr__(self) -> str:
        return f"PublicKey('{self}')"

    @classmethod
    def parse(cls, key_string: str) -> PublicKey:
        """Parse a ``<curve>:<base58>`` public key string."""
        if key_string.startswith(ML_DSA_65_HASH_PREFIX):
            raise InvalidKeyError(
                f"{key_string!r} is an on-chain ML-DSA-65 view handle (a 32-byte hash), "
                "not a full public key; it cannot sign or be added as a key"
            )
        for prefix, key_type, length in (
            (ED25519_PREFIX, KeyType.ED25519, 32),
            (SECP256K1_PREFIX, KeyType.SECP256K1, 64),
            (ML_DSA_65_PREFIX, KeyType.ML_DSA_65, ML_DSA_65_PUBLIC_KEY_LENGTH),
        ):
            if key_string.startswith(prefix):
                data = _b58decode(key_string[len(prefix) :], key_string)
                if len(data) != length:
                    raise InvalidKeyError(
                        f"{prefix.rstrip(':')} public key must be {length} bytes, got {len(data)}"
                    )
                return cls(key_type, data)
        raise InvalidKeyError(f"Unsupported public key type: {key_string!r}")

    def verify(self, signature: bytes, message: bytes) -> bool:
        """Check that ``signature`` over ``message`` was made by this key."""
        if self.key_type == KeyType.ED25519:
            try:
                Ed25519PublicKey.from_public_bytes(self.data).verify(signature, message)
            except InvalidSignature:
                return False
            return True
        if self.key_type == KeyType.ML_DSA_65:
            from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey

            try:
                MLDSA65PublicKey.from_public_bytes(self.data).verify(signature, message)
            except InvalidSignature:
                return False
            return True
        raise InvalidKeyError(f"Verification not supported for {self.key_type.name} keys")


class Ed25519KeyPair:
    """An ed25519 signing key pair."""

    def __init__(self, secret: bytes) -> None:
        """Create from a 32-byte seed or a 64-byte NEAR secret key (seed + public key)."""
        if len(secret) == 64:
            seed = secret[:32]
        elif len(secret) == 32:
            seed = secret
        else:
            raise InvalidKeyError(f"ed25519 secret key must be 32 or 64 bytes, got {len(secret)}")
        self._sk = Ed25519PrivateKey.from_private_bytes(seed)
        pub = self._sk.public_key().public_bytes_raw()
        if len(secret) == 64 and secret[32:] != pub:
            raise InvalidKeyError("ed25519 secret key's embedded public key does not match")
        self.public_key = PublicKey(KeyType.ED25519, pub)
        self.secret_key = ED25519_PREFIX + base58.b58encode(seed + pub).decode()

    def sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)

    @classmethod
    def generate(cls) -> Ed25519KeyPair:
        return cls(os.urandom(32))

    @classmethod
    def from_string(cls, key_string: str) -> Ed25519KeyPair:
        if not key_string.startswith(ED25519_PREFIX):
            raise InvalidKeyError(f"ed25519 key must start with '{ED25519_PREFIX}'")
        return cls(_b58decode(key_string[len(ED25519_PREFIX) :], key_string))

    def __repr__(self) -> str:
        return f"Ed25519KeyPair(public_key={self.public_key})"


class MlDsa65KeyPair:
    """An ML-DSA-65 (FIPS 204, post-quantum) signing key pair.

    Constructed from a 32-byte seed. The 4032-byte expanded secret-key form
    found in some nearcore credentials cannot be imported (pyca/cryptography
    only accepts seeds); regenerate such keys from their seed.
    """

    def __init__(self, seed: bytes) -> None:
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

        if len(seed) == ML_DSA_65_EXPANDED_SECRET_LENGTH:
            raise InvalidKeyError(
                "Expanded 4032-byte ML-DSA-65 secret keys are not supported; "
                "use the 32-byte seed form (ml-dsa-65:<base58 seed>)"
            )
        if len(seed) != ML_DSA_65_SEED_LENGTH:
            raise InvalidKeyError(f"ML-DSA-65 seed must be 32 bytes, got {len(seed)}")
        self._sk = MLDSA65PrivateKey.from_seed_bytes(seed)
        pub = self._sk.public_key().public_bytes_raw()
        self.public_key = PublicKey(KeyType.ML_DSA_65, pub)
        self.secret_key = ML_DSA_65_PREFIX + base58.b58encode(seed).decode()

    def sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)

    @classmethod
    def generate(cls) -> MlDsa65KeyPair:
        return cls(os.urandom(ML_DSA_65_SEED_LENGTH))

    @classmethod
    def from_string(cls, key_string: str) -> MlDsa65KeyPair:
        if key_string.startswith(ML_DSA_65_HASH_PREFIX):
            raise InvalidKeyError(
                "Cannot create an ML-DSA-65 key pair from an 'ml-dsa-65-hash:' view "
                "handle; it is a 32-byte hash, not a signing key"
            )
        if not key_string.startswith(ML_DSA_65_PREFIX):
            raise InvalidKeyError(f"ML-DSA-65 key must start with '{ML_DSA_65_PREFIX}'")
        return cls(_b58decode(key_string[len(ML_DSA_65_PREFIX) :], key_string))

    def __repr__(self) -> str:
        return f"MlDsa65KeyPair(public_key=PublicKey('{ML_DSA_65_PREFIX}...'))"


KeyPair = Ed25519KeyPair | MlDsa65KeyPair


@runtime_checkable
class Signer(Protocol):
    """Anything that can sign on behalf of a NEAR account.

    Implement this to plug in KMS, HSM, or remote signing::

        class KmsSigner:
            account_id = "treasury.near"
            public_key = PublicKey.parse("ed25519:...")

            def sign(self, message: bytes) -> bytes: ...
    """

    @property
    def account_id(self) -> str: ...

    @property
    def public_key(self) -> PublicKey: ...

    def sign(self, message: bytes) -> bytes: ...


@dataclass
class KeyPairSigner:
    """A :class:`Signer` backed by a local key pair."""

    account_id: str
    key_pair: KeyPair

    @property
    def public_key(self) -> PublicKey:
        return self.key_pair.public_key

    def sign(self, message: bytes) -> bytes:
        return self.key_pair.sign(message)


def parse_key(key_string: str) -> KeyPair:
    """Parse a secret key string (``ed25519:...`` or ``ml-dsa-65:...``) to a key pair."""
    if key_string.startswith(ED25519_PREFIX):
        return Ed25519KeyPair.from_string(key_string)
    if key_string.startswith((ML_DSA_65_HASH_PREFIX, ML_DSA_65_PREFIX)):
        return MlDsa65KeyPair.from_string(key_string)
    if key_string.startswith(SECP256K1_PREFIX):
        raise InvalidKeyError("secp256k1 signing keys are not supported (yet)")
    raise InvalidKeyError(f"Unsupported key type: {key_string!r}")


def generate_key() -> Ed25519KeyPair:
    """Generate a new random ed25519 key pair."""
    return Ed25519KeyPair.generate()


# ---------------------------------------------------------------------------
# Seed phrases (BIP-39 + SLIP-0010, NEAR path m/44'/397'/0')
# ---------------------------------------------------------------------------

_NEAR_HD_PATH = "m/44'/397'/0'"
_HARDENED = 0x80000000


def generate_seed_phrase(word_count: int = 12) -> str:
    """Generate a BIP-39 seed phrase (12, 15, 18, 21, or 24 words)."""
    if word_count not in (12, 15, 18, 21, 24):
        raise InvalidKeyError("word_count must be one of 12, 15, 18, 21, 24")
    return Mnemonic("english").generate(strength=word_count * 32 // 3)


def key_from_seed_phrase(phrase: str, path: str = _NEAR_HD_PATH) -> Ed25519KeyPair:
    """Derive the ed25519 key pair for a BIP-39 seed phrase (NEAR CLI/wallet compatible)."""
    normalized = " ".join(word.lower() for word in phrase.strip().split())
    if not Mnemonic("english").check(normalized):
        raise InvalidKeyError("Invalid BIP-39 seed phrase")
    seed = Mnemonic.to_seed(normalized, passphrase="")
    return Ed25519KeyPair(_slip10_derive(path, seed))


def _slip10_derive(path: str, seed: bytes) -> bytes:
    """SLIP-0010 ed25519 derivation (hardened segments only)."""
    if not re.match(r"^m(/\d+')+$", path):
        raise InvalidKeyError(
            f"Invalid derivation path: {path!r}. Must be hardened, e.g. {_NEAR_HD_PATH!r}"
        )
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    key, chain = digest[:32], digest[32:]
    for segment in path.split("/")[1:]:
        index = int(segment.rstrip("'")) + _HARDENED
        data = b"\x00" + key + index.to_bytes(4, "big")
        digest = hmac.new(chain, data, hashlib.sha512).digest()
        key, chain = digest[:32], digest[32:]
    return key


# ---------------------------------------------------------------------------
# Test-seed keys (nearcore deterministic keys, e.g. the Docker sandbox root)
# ---------------------------------------------------------------------------


def key_from_test_seed(seed: str) -> Ed25519KeyPair:
    """Derive nearcore's deterministic test key for a seed string.

    nearcore's ``--test-seed`` (used by the ``nearprotocol/sandbox`` Docker
    image, default seed ``"sandbox"``) forms the ed25519 seed by UTF-8
    encoding the string and right-padding with ASCII spaces to 32 bytes.
    """
    raw = seed.encode()
    if not raw or len(raw) > 32:
        raise InvalidKeyError("test seed must be 1-32 bytes when UTF-8 encoded")
    return Ed25519KeyPair(raw.ljust(32, b" "))


# ---------------------------------------------------------------------------
# NEAR CLI credentials (~/.near-credentials/<network>/<account_id>.json)
# ---------------------------------------------------------------------------


def load_credentials(
    account_id: str,
    network: str,
    credentials_dir: Path | str | None = None,
) -> KeyPairSigner:
    """Load a signer from a NEAR CLI credentials file."""
    base = Path(credentials_dir) if credentials_dir else Path.home() / ".near-credentials"
    path = base / network / f"{account_id}.json"
    if not path.exists():
        raise InvalidKeyError(f"No credentials file at {path}")
    data = json.loads(path.read_text())
    secret = data.get("private_key") or data.get("secret_key")
    if not secret:
        raise InvalidKeyError(f"Credentials file {path} has no private_key/secret_key")
    return KeyPairSigner(account_id=data.get("account_id", account_id), key_pair=parse_key(secret))


# ---------------------------------------------------------------------------
# Account IDs
# ---------------------------------------------------------------------------


def is_valid_account_id(account_id: str) -> bool:
    """Whether ``account_id`` satisfies NEAR's account naming rules."""
    return 2 <= len(account_id) <= 64 and _ACCOUNT_ID_RE.match(account_id) is not None


def validate_account_id(account_id: str) -> str:
    """Return ``account_id`` if valid, else raise :class:`InvalidAccountIdError`."""
    if not is_valid_account_id(account_id):
        raise InvalidAccountIdError(account_id)
    return account_id


def _b58decode(text: str, context: str) -> bytes:
    try:
        return base58.b58decode(text)
    except ValueError as exc:
        raise InvalidKeyError(f"Invalid base58 in key: {context!r}") from exc
