"""Unit tests for near.testing and the pytest-plugin plumbing.

No real sandbox and no docker daemon: the pure parts (URL resolution, port
picking) run as-is, and the container lifecycle runs against monkeypatched
``subprocess`` / probe seams so every path — including the interrupt and
failure ones — is exercised without side effects.
"""

import os
import socket
import subprocess
from types import SimpleNamespace
from typing import cast

import httpx
import pytest

import near._pytest_plugin as plugin
from near._pytest_plugin import LOCAL_SANDBOX_URL, pick_free_port, resolve_sandbox_url
from near.client import Near
from near.testing import fast_forward

ENV_URL = "http://sandbox.internal:3033"


class TestResolveSandboxUrl:
    def test_env_url_wins_when_reachable(self):
        probed: list[str] = []

        def probe(url: str) -> bool:
            probed.append(url)
            return True

        assert resolve_sandbox_url(ENV_URL, probe) == ENV_URL
        assert probed == [ENV_URL]  # short-circuits before localhost

    def test_unreachable_env_url_falls_back_to_localhost(self):
        assert (
            resolve_sandbox_url(ENV_URL, lambda url: url == LOCAL_SANDBOX_URL) == LOCAL_SANDBOX_URL
        )

    def test_without_env_url_only_localhost_is_probed(self):
        probed: list[str] = []

        def probe(url: str) -> bool:
            probed.append(url)
            return True

        assert resolve_sandbox_url(None, probe) == LOCAL_SANDBOX_URL
        assert probed == [LOCAL_SANDBOX_URL]

    def test_nothing_reachable_means_start_one(self):
        assert resolve_sandbox_url(ENV_URL, lambda _: False) is None

    def test_reads_env_var_the_way_the_fixture_does(self, monkeypatch):
        monkeypatch.setenv("NEAR_SANDBOX_URL", ENV_URL)
        assert resolve_sandbox_url(os.environ.get("NEAR_SANDBOX_URL"), lambda _: True) == ENV_URL


def test_pick_free_port_is_bindable():
    port = pick_free_port()
    assert 0 < port < 65536
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))  # still free: bind succeeds


class TestReachable:
    """_reachable must mean "a NEAR node", not "anything answering 200"."""

    def _respond(self, monkeypatch, status_code, json):
        response = SimpleNamespace(status_code=status_code, json=json)
        monkeypatch.setattr(httpx, "get", lambda url, timeout: response)

    def test_near_status_json_is_reachable(self, monkeypatch):
        self._respond(monkeypatch, 200, lambda: {"chain_id": "sandbox", "sync_info": {}})
        assert plugin._reachable("http://x") is True

    def test_non_json_200_is_not_a_sandbox(self, monkeypatch):
        def not_json():
            raise ValueError("not json")

        self._respond(monkeypatch, 200, not_json)
        assert plugin._reachable("http://x") is False

    def test_json_without_chain_id_is_not_a_sandbox(self, monkeypatch):
        self._respond(monkeypatch, 200, lambda: {"ok": True})
        assert plugin._reachable("http://x") is False

    def test_non_dict_json_is_not_a_sandbox(self, monkeypatch):
        self._respond(monkeypatch, 200, lambda: "chain_id")
        assert plugin._reachable("http://x") is False

    def test_non_200_is_not_a_sandbox(self, monkeypatch):
        self._respond(monkeypatch, 503, lambda: {"chain_id": "sandbox"})
        assert plugin._reachable("http://x") is False

    def test_connection_error_is_not_reachable(self, monkeypatch):
        def refuse(url, timeout):
            raise httpx.ConnectError("connection refused")

        monkeypatch.setattr(httpx, "get", refuse)
        assert plugin._reachable("http://x") is False


class TestCreateContainer:
    """docker-run outcomes: success, port-conflict retry, failure, no docker."""

    def _arm(self, monkeypatch, outcomes):
        """Fake subprocess.run popping one scripted outcome per call."""
        run_cmds: list[list[str]] = []
        removed: list[str] = []

        def fake_run(cmd, *, check, capture_output):
            run_cmds.append(cmd)
            outcome = outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        monkeypatch.setattr(plugin.subprocess, "run", fake_run)
        monkeypatch.setattr(plugin, "_remove_container", removed.append)
        return run_cmds, removed

    @staticmethod
    def _name_in(cmd):
        return cmd[cmd.index("--name") + 1]

    @staticmethod
    def _conflict(cmd):
        stderr = b"docker: Bind for 127.0.0.1:1 failed: port is already allocated."
        return subprocess.CalledProcessError(125, cmd, stderr=stderr)

    def test_success_publishes_loopback_only_with_rm(self, monkeypatch):
        run_cmds, removed = self._arm(monkeypatch, [None])
        port, name = plugin._create_container()
        (cmd,) = run_cmds
        assert name == self._name_in(cmd)
        assert name.startswith(f"near-sandbox-{port}-")
        assert "--rm" in cmd
        assert f"127.0.0.1:{port}:3030" in cmd  # matches the loopback-only probe
        assert removed == []

    def test_port_conflict_removes_container_and_retries_fresh_port(self, monkeypatch):
        outcomes = [self._conflict(["docker"]), None]
        run_cmds, removed = self._arm(monkeypatch, outcomes)
        _, name = plugin._create_container()
        assert len(run_cmds) == 2
        assert removed == [self._name_in(run_cmds[0])]  # loser cleaned up
        assert name == self._name_in(run_cmds[1])  # a fresh name (and port pick)

    def test_port_conflict_every_attempt_skips_with_the_reason(self, monkeypatch):
        outcomes = [self._conflict(["docker"]) for _ in range(plugin._CREATE_ATTEMPTS)]
        run_cmds, removed = self._arm(monkeypatch, outcomes)
        with pytest.raises(pytest.skip.Exception, match="port is already allocated"):
            plugin._create_container()
        assert len(run_cmds) == plugin._CREATE_ATTEMPTS
        assert removed == [self._name_in(cmd) for cmd in run_cmds]  # nothing leaks

    def test_other_docker_failure_removes_container_and_skips_with_stderr(self, monkeypatch):
        error = subprocess.CalledProcessError(
            125, ["docker"], stderr=b"docker: no matching manifest for linux/arm64/v8."
        )
        run_cmds, removed = self._arm(monkeypatch, [error])
        with pytest.raises(pytest.skip.Exception, match="no matching manifest"):
            plugin._create_container()
        assert len(run_cmds) == 1  # not a port conflict: no retry
        assert removed == [self._name_in(run_cmds[0])]

    def test_docker_failure_without_stderr_reports_exit_status(self, monkeypatch):
        _, removed = self._arm(monkeypatch, [subprocess.CalledProcessError(127, ["docker"])])
        with pytest.raises(pytest.skip.Exception, match="exit status 127"):
            plugin._create_container()
        assert len(removed) == 1

    def test_missing_docker_skips(self, monkeypatch):
        _, removed = self._arm(monkeypatch, [FileNotFoundError("docker")])
        with pytest.raises(pytest.skip.Exception, match="docker is not installed"):
            plugin._create_container()
        assert removed == []


class TestSandboxSessionLifecycle:
    """The fixture body must remove a launched container on every exit path."""

    def _arm(self, monkeypatch, wait=lambda url: None):
        monkeypatch.delenv("NEAR_SANDBOX_URL", raising=False)
        monkeypatch.setattr(plugin, "_reachable", lambda url: False)
        monkeypatch.setattr(plugin, "_create_container", lambda: (3999, "sandbox-under-test"))
        monkeypatch.setattr(plugin, "_wait_until_ready", wait)
        removed: list[str] = []
        monkeypatch.setattr(plugin, "_remove_container", removed.append)
        return removed

    def test_started_container_removed_at_teardown(self, monkeypatch):
        removed = self._arm(monkeypatch)
        session = plugin._sandbox_session()
        handle = next(session)
        assert handle.rpc_url == "http://localhost:3999"
        assert handle.started is True
        assert removed == []  # alive while tests run
        session.close()
        assert removed == ["sandbox-under-test"]

    def test_interrupt_during_ready_wait_removes_container(self, monkeypatch):
        def interrupted(url):
            raise KeyboardInterrupt

        removed = self._arm(monkeypatch, wait=interrupted)
        with pytest.raises(KeyboardInterrupt):
            next(plugin._sandbox_session())
        assert removed == ["sandbox-under-test"]

    def test_ready_timeout_removes_container(self, monkeypatch):
        def never_ready(url):
            raise TimeoutError("not ready")

        removed = self._arm(monkeypatch, wait=never_ready)
        with pytest.raises(TimeoutError):
            next(plugin._sandbox_session())
        assert removed == ["sandbox-under-test"]

    def test_reused_sandbox_is_never_launched_or_removed(self, monkeypatch):
        removed = self._arm(monkeypatch)
        monkeypatch.setattr(plugin, "_reachable", lambda url: url == LOCAL_SANDBOX_URL)

        def boom():
            raise AssertionError("must not launch when one is reachable")

        monkeypatch.setattr(plugin, "_create_container", boom)
        session = plugin._sandbox_session()
        handle = next(session)
        assert handle.rpc_url == LOCAL_SANDBOX_URL
        assert handle.started is False
        session.close()
        assert removed == []


def test_fast_forward_rejects_nonpositive_delta():
    # Validation fires before the client is touched.
    with pytest.raises(ValueError, match="num_blocks must be >= 1"):
        fast_forward(cast("Near", object()), 0)
