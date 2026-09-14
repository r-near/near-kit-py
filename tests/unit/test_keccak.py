"""Keccak-256 (original padding) test vectors.

The empty-string and "quick brown fox" digests are the published Keccak team
/ Wikipedia values; every vector here (including the rate-boundary inputs)
was additionally cross-checked against ``@noble/hashes`` ``keccak_256``
(v2.4.0) — hashlib cannot serve as an oracle because ``sha3_256`` pads
differently.
"""

import hashlib

import pytest

from near._keccak import keccak256

VECTORS = [
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"hello world", "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"),
    (
        b"The quick brown fox jumps over the lazy dog",
        "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
    ),
    # Two blocks (rate is 136 bytes).
    (b"a" * 200, "96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d"),
    # One byte short of the rate: the 0x01 and 0x80 pad bits land in the same byte.
    (b"\xff" * 135, "f1d6ccc06d572a1e3f4fb6320f8fd3a2e3f1044c45e4f5d863f5a1b6a0ec3b7c"),
    # Exactly one block: padding forces a second, pad-only block.
    (bytes(136), "3a5912a7c5faa06ee4fe906253e339467a9ce87d533c65be3c15cb231cdb25f9"),
]


@pytest.mark.parametrize(("data", "digest"), VECTORS)
def test_known_vectors(data, digest):
    assert keccak256(data).hex() == digest


def test_differs_from_sha3_256():
    # Same permutation, different padding byte: the two must never agree.
    assert keccak256(b"") != hashlib.sha3_256(b"").digest()


def test_digest_length():
    assert len(keccak256(b"x" * 1000)) == 32
