"""Integration fixtures: connect to a NEAR sandbox at localhost:3030.

Start one with:  docker run -d -p 3030:3030 nearprotocol/sandbox:2.13.1
Override the URL with NEAR_SANDBOX_URL (e.g. to run parallel suites against
containers on different ports). Tests are skipped automatically when no
sandbox is reachable.
"""

import itertools
import os
import uuid
from pathlib import Path

import httpx
import pytest

from near import (
    AsyncNear,
    Near,
    add_full_access_key,
    create_account,
    deploy_contract,
    generate_key,
    transfer,
)
from near.testing import sandbox_signer

SANDBOX_URL = os.environ.get("NEAR_SANDBOX_URL", "http://localhost:3030")
GUESTBOOK_WASM = Path(__file__).parent.parent / "contracts" / "guestbook.wasm"

_account_counter = itertools.count(1)
# Chain state persists across pytest runs, so account names must be unique per run.
_RUN_ID = uuid.uuid4().hex[:6]


def _sandbox_available() -> bool:
    try:
        return httpx.get(f"{SANDBOX_URL}/status", timeout=2.0).status_code == 200
    except httpx.HTTPError:
        return False


def pytest_collection_modifyitems(config, items):
    if _sandbox_available():
        return
    skip = pytest.mark.skip(reason=f"no NEAR sandbox at {SANDBOX_URL}")
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def near():
    client = Near(rpc_url=SANDBOX_URL, signer=sandbox_signer())
    yield client
    client.close()


@pytest.fixture
async def anear():
    client = AsyncNear(rpc_url=SANDBOX_URL, signer=sandbox_signer())
    yield client
    await client.aclose()


@pytest.fixture
def unique_id():
    """A fresh subaccount-name prefix, unique across tests AND pytest runs."""
    return f"t{next(_account_counter)}-{_RUN_ID}"


@pytest.fixture(scope="session")
def run_id():
    return _RUN_ID


@pytest.fixture(scope="session")
def sandbox_url():
    return SANDBOX_URL


@pytest.fixture(scope="session")
def guestbook(near, run_id):
    """Deploy the guestbook contract once per session."""
    account_id = f"gb-{run_id}.{near.signer.account_id}"
    key = generate_key()
    near.send_transaction(
        account_id,
        actions=[
            create_account(),
            transfer("20 NEAR"),
            add_full_access_key(key.public_key),
            deploy_contract(GUESTBOOK_WASM.read_bytes()),
        ],
        wait_until="FINAL",
    )
    return account_id
