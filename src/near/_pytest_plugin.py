"""Pytest plugin: fixtures that find or start a NEAR sandbox.

Registered through the ``pytest11`` entry point, so it activates whenever
near-kit and pytest are installed together — pytest never becomes a runtime
dependency, and :mod:`near.testing` stays importable without it.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
import uuid
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from .client import Near
    from .testing import SandboxHandle

SANDBOX_IMAGE = "nearprotocol/sandbox:2.13.1"
LOCAL_SANDBOX_URL = "http://localhost:3030"
_READY_TIMEOUT = 90.0


def resolve_sandbox_url(env_url: str | None, reachable: Callable[[str], bool]) -> str | None:
    """The first reachable sandbox URL — env override, then localhost.

    ``None`` means nothing answered and the caller must start a sandbox
    itself. Pure by design: tests drive it with a fake ``reachable``.
    """
    for candidate in (env_url, LOCAL_SANDBOX_URL):
        if candidate and reachable(candidate):
            return candidate
    return None


def pick_free_port() -> int:
    """A TCP port that was free a moment ago (the OS picks it)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="session")
def near_sandbox() -> Iterator[SandboxHandle]:
    """A reachable NEAR sandbox for the whole session, started on demand.

    Reuses ``NEAR_SANDBOX_URL`` or ``http://localhost:3030`` when one
    answers; otherwise starts a Docker container on a free port and removes
    it at session end. Skips the requesting tests when neither is possible.
    """
    from .testing import SandboxHandle, sandbox_signer

    url = resolve_sandbox_url(os.environ.get("NEAR_SANDBOX_URL"), _reachable)
    container: str | None = None
    if url is None:
        url, container = _launch_container(pick_free_port())
    handle = SandboxHandle(
        rpc_url=url,
        root_account_id="sandbox",
        root_signer=sandbox_signer(),
        started=container is not None,
    )
    try:
        yield handle
    finally:
        if container is not None:
            _remove_container(container)


@pytest.fixture
def sandbox_near(near_sandbox: SandboxHandle) -> Iterator[Near]:
    """A :class:`~near.Near` client signing as the sandbox root account."""
    from .client import Near

    client = Near(rpc_url=near_sandbox.rpc_url, signer=near_sandbox.root_signer)
    yield client
    client.close()


def _reachable(url: str) -> bool:
    import httpx

    try:
        return httpx.get(f"{url}/status", timeout=2.0).status_code == 200
    except httpx.HTTPError:
        return False


def _launch_container(port: int) -> tuple[str, str]:
    """Start a sandbox container publishing ``port``; (rpc_url, name)."""
    name = f"near-sandbox-{port}-{uuid.uuid4().hex[:8]}"
    run = ["docker", "run", "-d", "--name", name, "-p", f"{port}:3030", SANDBOX_IMAGE]
    try:
        subprocess.run(run, check=True, capture_output=True)  # noqa: S603
    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip(
            "no NEAR sandbox reachable and docker could not start one — run: "
            f"docker run -d -p 3030:3030 {SANDBOX_IMAGE}"
        )
    url = f"http://localhost:{port}"
    try:
        _wait_until_ready(url)
    except TimeoutError:
        _remove_container(name)
        raise
    return url, name


def _wait_until_ready(url: str, timeout: float = _READY_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _reachable(url):
            return
        time.sleep(1.0)
    raise TimeoutError(f"sandbox container at {url} did not become ready within {timeout:.0f}s")


def _remove_container(name: str) -> None:
    cmd = ["docker", "rm", "-f", name]
    subprocess.run(cmd, check=False, capture_output=True)  # noqa: S603
