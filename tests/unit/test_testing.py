"""Unit tests for near.testing and the pytest-plugin plumbing.

Pure parts only — no sandbox, no docker, no mocks: the URL resolution is a
pure function driven by a fake reachability probe.
"""

import os
import socket
from typing import cast

import pytest

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


def test_fast_forward_rejects_nonpositive_delta():
    # Validation fires before the client is touched.
    with pytest.raises(ValueError, match="num_blocks must be >= 1"):
        fast_forward(cast("Near", object()), 0)
