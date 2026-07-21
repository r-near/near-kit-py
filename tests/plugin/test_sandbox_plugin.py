"""Plugin fixtures and sandbox RPC wrappers against a real node.

These live outside tests/integration/ on purpose: that conftest is pinned
to localhost:3030, while the plugin resolves its own sandbox
(``NEAR_SANDBOX_URL``, then localhost:3030, then a Docker container it
starts and later removes itself).
"""

import uuid

import pytest

from near import Amount, add_full_access_key, create_account, generate_key, transfer
from near.testing import fast_forward, patch_state

pytest_plugins = ["pytester"]
pytestmark = pytest.mark.integration


def test_fast_forward_advances_at_least_delta(sandbox_near):
    before = sandbox_near.rpc("block", {"finality": "final"})["header"]["height"]
    fast_forward(sandbox_near, 25)
    after = sandbox_near.rpc("block", {"finality": "final"})["header"]["height"]
    assert after - before >= 25


def test_patch_state_balance_reads_back(sandbox_near):
    # Create a fresh account the normal way, then patch its balance directly.
    account_id = f"patched-{uuid.uuid4().hex[:6]}.sandbox"
    key = generate_key()
    sandbox_near.send_transaction(
        account_id,
        actions=[create_account(), transfer("1 NEAR"), add_full_access_key(key.public_key)],
        wait_until="FINAL",
    )
    account = sandbox_near.account(account_id)
    target = Amount("123.45 NEAR")
    patch_state(
        sandbox_near,
        [
            {
                "Account": {
                    "account_id": account_id,
                    "account": {
                        "amount": str(int(target)),
                        "locked": str(int(account.locked)),
                        "code_hash": account.code_hash,
                        "storage_usage": account.storage_usage,
                    },
                }
            }
        ],
    )
    assert sandbox_near.balance(account_id) == target


def test_plugin_fixtures_end_to_end(pytester, near_sandbox, monkeypatch):
    """A fresh pytest run gets the fixtures via the entry point and reuses our sandbox."""
    # This inner run is where the pytest11 entry point is genuinely exercised:
    # the outer suite blocks it (-p no:near in addopts) so that importing near
    # cannot predate pytest-cov's collector (see the root conftest.py). The
    # pytester run autoloads the entry point for real because its fresh
    # rootdir/ini inherits neither our addopts nor our conftest, and running
    # in-process keeps the fixture code it executes visible to the outer
    # suite's coverage collector.
    monkeypatch.setenv("NEAR_SANDBOX_URL", near_sandbox.rpc_url)
    # Minimal ini so pytest-asyncio (loaded in the inner run too) stays quiet.
    pytester.makeini("[pytest]\nasyncio_default_fixture_loop_scope = function\n")
    pytester.makepyfile(
        """
        def test_uses_shared_sandbox(near_sandbox, sandbox_near):
            assert near_sandbox.root_account_id == "sandbox"
            assert near_sandbox.started is False  # reused, not launched
            assert sandbox_near.account_exists(near_sandbox.root_account_id)
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)
