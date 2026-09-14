"""Keccak-256, the pre-standard Keccak used by Ethereum and NEP-616.

``hashlib.sha3_256`` is Keccak-f[1600] with the FIPS-202 padding byte
(``0x06``); the original Keccak pads with ``0x01`` and therefore produces
different digests. NEP-616 deterministic account IDs are defined over the
original, so this small pure-Python sponge is vendored rather than pulling
in a dependency for the handful of hashes a client ever computes.
"""

from __future__ import annotations

__all__ = ["keccak256"]

_MASK = (1 << 64) - 1
_RATE = 136  # bytes: 1600 - 2 * 256 bits, i.e. 17 lanes per block
_DIGEST_SIZE = 32

_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)

# Rho rotation offsets, indexed by lane x + 5*y.
_ROTATIONS = (
    (0, 1, 62, 28, 27),
    (36, 44, 6, 55, 20),
    (3, 10, 43, 25, 39),
    (41, 45, 15, 21, 8),
    (18, 2, 61, 56, 14),
)


def _rotl(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _keccak_f1600(lanes: list[int]) -> list[int]:
    for round_constant in _ROUND_CONSTANTS:
        # theta
        parity = [
            lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20]
            for x in range(5)
        ]
        delta = [parity[(x - 1) % 5] ^ _rotl(parity[(x + 1) % 5], 1) for x in range(5)]
        lanes = [lanes[i] ^ delta[i % 5] for i in range(25)]
        # rho + pi
        moved = [0] * 25
        for x in range(5):
            for y in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(lanes[x + 5 * y], _ROTATIONS[y][x])
        # chi
        lanes = [
            moved[i]
            ^ (
                (~moved[(i % 5 + 1) % 5 + 5 * (i // 5)] & _MASK)
                & moved[(i % 5 + 2) % 5 + 5 * (i // 5)]
            )
            for i in range(25)
        ]
        # iota
        lanes[0] ^= round_constant
    return lanes


def keccak256(data: bytes) -> bytes:
    """Keccak-256 digest (Ethereum flavour, ``0x01`` padding), 32 bytes."""
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\x00" * (-len(padded) % _RATE))
    padded[-1] |= 0x80

    lanes = [0] * 25
    for offset in range(0, len(padded), _RATE):
        block = padded[offset : offset + _RATE]
        for lane in range(_RATE // 8):
            lanes[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        lanes = _keccak_f1600(lanes)

    return b"".join(lane.to_bytes(8, "little") for lane in lanes[: _DIGEST_SIZE // 8])
