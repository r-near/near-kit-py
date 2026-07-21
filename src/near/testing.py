"""Test helpers for the NEAR sandbox.

Run the official sandbox like a database service::

    docker run -d -p 3030:3030 nearprotocol/sandbox:2.13.1

and connect with the deterministic root key::

    from near import Near
    from near.testing import sandbox_signer

    near = Near("sandbox", signer=sandbox_signer())

The image inits its chain with ``--test-seed`` (default ``"sandbox"``), so
the root account's key is derived from the seed — nothing needs to be
copied out of the container.

Installing near-kit next to pytest also registers a plugin (see
:mod:`near._pytest_plugin`) whose ``near_sandbox`` / ``sandbox_near``
fixtures find or start a sandbox for you. This module must stay importable
without pytest installed, so anything pytest-flavored lives in the plugin.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .keys import KeyPairSigner, key_from_test_seed

if TYPE_CHECKING:
    from .client import Near

__all__ = ["SandboxHandle", "fast_forward", "patch_state", "sandbox_signer"]


def sandbox_signer(account_id: str = "sandbox", seed: str | None = None) -> KeyPairSigner:
    """The deterministic signer for a nearcore sandbox root account.

    By default the ``nearprotocol/sandbox`` image uses account ``sandbox``
    with test seed ``sandbox``; if you override ``NEAR_ROOT_ACCOUNT`` /
    ``NEAR_TEST_SEED`` on the container, pass the matching values here.
    """
    return KeyPairSigner(
        account_id=account_id,
        key_pair=key_from_test_seed(seed if seed is not None else account_id),
    )


@dataclass(frozen=True)
class SandboxHandle:
    """Where a test session's sandbox lives and how to sign as its root.

    Yielded by the ``near_sandbox`` pytest fixture. ``started`` is True only
    when the fixture launched the Docker container itself (it then also
    removes it at session end).
    """

    rpc_url: str
    root_account_id: str
    root_signer: KeyPairSigner
    started: bool


def fast_forward(client: Near, num_blocks: int) -> None:
    """Make the sandbox produce ``num_blocks`` blocks right now.

    Skips the wall-clock wait in time-dependent logic (lockups, expiries,
    vesting). The node applies the RPC asynchronously — it returns before
    the chain has moved — so this helper polls until the final height is at
    least ``num_blocks`` above where it started; reads made afterwards see
    the advanced chain. Sync :class:`~near.Near` only; from an async client
    call ``await client.rpc("sandbox_fast_forward", {"delta_height": n})``
    and poll the block height yourself.
    """
    if num_blocks < 1:
        raise ValueError(f"num_blocks must be >= 1, got {num_blocks}")
    start = _final_height(client)
    client.rpc("sandbox_fast_forward", {"delta_height": num_blocks})
    deadline = time.monotonic() + 30.0 + num_blocks * 0.05
    while time.monotonic() < deadline:
        if _final_height(client) >= start + num_blocks:
            return
        time.sleep(0.05)
    raise TimeoutError(f"sandbox did not advance {num_blocks} blocks in time")


def patch_state(client: Near, records: list[dict[str, Any]]) -> None:
    """Write raw chain state directly, bypassing transactions and fees.

    ``records`` use nearcore's genesis-records JSON shapes. The canonical
    one — create an account (or overwrite an existing one) with a chosen
    balance::

        patch_state(
            client,
            [
                {
                    "Account": {
                        "account_id": "rich.sandbox",
                        "account": {
                            "amount": "123450000000000000000000000",  # yocto
                            "locked": "0",
                            "code_hash": "11111111111111111111111111111111",
                            "storage_usage": 182,
                        },
                    }
                }
            ],
        )

    The sandbox applies patches only when it commits its next block, so a
    read straight after the RPC may still see old state; this helper waits
    for one block before returning. Sync client only; async users can call
    ``client.rpc("sandbox_patch_state", {"records": records})`` and wait a
    block themselves.
    """
    client.rpc("sandbox_patch_state", {"records": records})
    _wait_one_block(client)


def _wait_one_block(client: Near, timeout: float = 10.0) -> None:
    """Poll until the final head moves past its current height."""
    height = _final_height(client)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _final_height(client) > height:
            return
        time.sleep(0.05)
    raise TimeoutError(f"sandbox produced no new block within {timeout:.0f}s")


def _final_height(client: Near) -> int:
    return int(client.rpc("block", {"finality": "final"})["header"]["height"])
