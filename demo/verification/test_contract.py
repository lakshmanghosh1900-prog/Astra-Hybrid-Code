"""Immutable image-side contract for the explicitly scoped arithmetic demo."""

import os
import runpy
import socket
from pathlib import Path

import pytest


@pytest.mark.parametrize("a,b,expected", [(2, 3, 5), (-2, 3, 1), (0, 0, 0), (9, -3, 6)])
def test_real_workspace_function(a: int, b: int, expected: int) -> None:
    namespace = runpy.run_path("/workspace/demo_math.py")
    assert namespace["add"](a, b) == expected


def test_sandbox_is_not_the_worker_host() -> None:
    getuid = getattr(os, "getuid", None)
    assert callable(getuid) and getuid() == 10001
    assert not Path("/var/run/docker.sock").exists()
    assert not Path("/repositories/repo").exists()


def test_root_filesystem_is_read_only() -> None:
    with pytest.raises(OSError):
        Path("/app/should-not-write").write_text("forbidden", encoding="utf-8")


def test_network_is_disabled() -> None:
    with pytest.raises(OSError):
        socket.create_connection(("1.1.1.1", 443), timeout=1)
