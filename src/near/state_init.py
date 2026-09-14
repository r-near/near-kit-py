"""NEP-616 deterministic accounts: account IDs derived from initial state.

A deterministic account's ID is ``"0s" + hex(keccak256(borsh(state_init))[12:])``
— 42 characters, the last 20 bytes of the hash like an Ethereum address, with
a ``0s`` prefix so it can never collide with ``0x`` implicit accounts. Anyone
can create the account by sending a :func:`~near.actions.deterministic_state_init`
action to that ID; the node re-derives the ID and rejects any mismatch, so
the borsh bytes (including the sorted data map) must match nearcore exactly.
"""

from __future__ import annotations

import re

from ._keccak import keccak256
from .wire import DeterministicAccountStateInit

__all__ = ["derive_deterministic_account_id", "is_deterministic_account_id"]

_DETERMINISTIC_ID_RE = re.compile(r"^0s[0-9a-f]{40}$")


def derive_deterministic_account_id(state_init: DeterministicAccountStateInit) -> str:
    """The account ID that ``state_init`` creates (the receiver for the action)."""
    digest = keccak256(state_init.to_borsh())
    return "0s" + digest[12:32].hex()


def is_deterministic_account_id(account_id: str) -> bool:
    """Whether ``account_id`` has the NEP-616 shape (``0s`` + 40 lowercase hex digits)."""
    return _DETERMINISTIC_ID_RE.match(account_id) is not None
