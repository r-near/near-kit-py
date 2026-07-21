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
# pick_free_port() races anything else grabbing ports between the probe and
# `docker run` binding it (a parallel pytest session, an ephemeral outbound
# connection), so a port-conflict failure retries with a fresh port.
_CREATE_ATTEMPTS = 3
_PORT_CONFLICT_MARKERS = ("port is already allocated", "address already in use")
_SKIP_HINT = f"set NEAR_SANDBOX_URL or run: docker run -d -p 3030:3030 {SANDBOX_IMAGE}"


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
    answers; otherwise starts a Docker container on a loopback-only free
    port and removes it at session end. Skips the requesting tests when
    neither is possible.
    """
    yield from _sandbox_session()


def _sandbox_session() -> Iterator[SandboxHandle]:
    """The ``near_sandbox`` fixture body, callable directly in unit tests.

    The container name is recorded the moment ``docker run`` returns and
    removal lives in the ``finally``, so a Ctrl-C or timeout anywhere in the
    (long) ready-wait still tears the container down instead of leaking it.
    """
    from .testing import SandboxHandle, sandbox_signer

    url = resolve_sandbox_url(os.environ.get("NEAR_SANDBOX_URL"), _reachable)
    container: str | None = None
    try:
        if url is None:
            port, container = _create_container()
            url = f"http://localhost:{port}"
            _wait_until_ready(url)
        yield SandboxHandle(
            rpc_url=url,
            root_account_id="sandbox",
            root_signer=sandbox_signer(),
            started=container is not None,
        )
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
    """Whether ``url`` answers ``/status`` like a NEAR node.

    Requires ``chain_id`` in the JSON body, not just a 200 — otherwise any
    unrelated dev server squatting on localhost:3030 (or a stale
    ``NEAR_SANDBOX_URL``) would masquerade as a sandbox and every test would
    fail with opaque RPC errors instead of starting a real one.
    """
    import httpx

    try:
        response = httpx.get(f"{url}/status", timeout=2.0)
        if response.status_code != 200:
            return False
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return False
    return isinstance(payload, dict) and "chain_id" in payload


def _create_container() -> tuple[int, str]:
    """``docker run`` a detached sandbox container; ``(host_port, name)``.

    Publishes on 127.0.0.1 only, matching the loopback-only port probe (and
    keeping the sandbox off the LAN). ``docker run`` can fail *after*
    creating the named container (e.g. the probed-free port got taken
    meanwhile), so every failure removes the name — a no-op when nothing was
    created — and port conflicts retry with a fresh port instead of
    masquerading as "docker is unavailable". Skips the requesting tests when
    docker is missing or keeps failing, quoting docker's stderr.
    """
    attempts = _CREATE_ATTEMPTS
    while True:
        attempts -= 1
        port = pick_free_port()
        name = f"near-sandbox-{port}-{uuid.uuid4().hex[:8]}"
        run = [
            "docker",
            "run",
            "-d",
            "--rm",  # if the container exits on its own, docker reaps it
            "--name",
            name,
            "-p",
            f"127.0.0.1:{port}:3030",
            SANDBOX_IMAGE,
        ]
        try:
            subprocess.run(run, check=True, capture_output=True)  # noqa: S603
        except FileNotFoundError:
            pytest.skip(f"no NEAR sandbox reachable and docker is not installed — {_SKIP_HINT}")
        except subprocess.CalledProcessError as error:
            _remove_container(name)
            stderr = (error.stderr or b"").decode("utf-8", errors="replace")
            if attempts > 0 and any(m in stderr.lower() for m in _PORT_CONFLICT_MARKERS):
                continue
            detail = _stderr_summary(stderr) or f"exit status {error.returncode}"
            pytest.skip(
                f"no NEAR sandbox reachable and `docker run` failed ({detail}) — {_SKIP_HINT}"
            )
        else:
            return port, name


def _stderr_summary(stderr: str, limit: int = 400) -> str:
    """A failed command's stderr as one line, keeping the tail if long."""
    joined = " ".join(line.strip() for line in stderr.splitlines() if line.strip())
    return joined if len(joined) <= limit else f"...{joined[-limit:]}"


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
