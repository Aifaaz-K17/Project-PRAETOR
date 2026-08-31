"""Tests for INV-14 (no live targets, ever)."""

import socket

import pytest

from conftest import NetworkBlockedError


def test_INV_14_connecting_to_a_real_host_is_blocked() -> None:
    """Any attempt to connect to a non-loopback address during a test must
    fail loudly. Uses a raw IP literal (not a hostname) so the test itself
    never triggers a DNS lookup — the block happens at connect() time.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s, pytest.raises(
        NetworkBlockedError
    ):
        s.connect(("93.184.216.34", 80))  # a real, non-loopback address


def test_INV_14_socket_objects_can_still_be_created() -> None:
    """The block targets connect()/connect_ex(), not socket() itself —
    constructing a socket must keep working, since asyncio's own event
    loop needs to do that internally (e.g. Windows ProactorEventLoop's
    self-pipe, which is loopback-only and unrelated to INV-14's concern)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        assert s is not None


def test_INV_14_loopback_connections_are_not_blocked_by_this_fixture() -> None:
    """Connecting to 127.0.0.1 must not be rejected by the fixture itself
    (it may still fail with a plain ConnectionRefusedError if nothing is
    listening — that's a different, expected error, not NetworkBlockedError)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        try:
            s.connect(("127.0.0.1", 1))  # port 1 - essentially guaranteed closed
        except NetworkBlockedError:
            raise AssertionError("loopback connections must not be blocked by INV-14")
        except OSError:
            pass  # refused/timed out — fine, proves it reached real connect()


def test_INV_14_socket_module_still_importable() -> None:
    """Code that only imports socket for constants (e.g. socket.AF_INET)
    must keep working."""
    assert socket.AF_INET is not None
