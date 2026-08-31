"""Tests for INV-14 (no live targets, ever)."""

import socket

import pytest

from conftest import NetworkBlockedError


def test_INV_14_network_is_blocked() -> None:
    """Any attempt to open a real socket during a test must fail loudly.

    This is the whole point of the autouse `block_network` fixture in
    conftest.py: an accidental real network call in a test or demo is a
    violation of INV-14, and it must be impossible, not merely discouraged.
    """
    with pytest.raises(NetworkBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def test_INV_14_socket_module_still_importable() -> None:
    """The block patches socket.socket, not the whole module — code that
    only imports socket for constants (e.g. socket.AF_INET) must keep
    working, since firewall code will need those constants later without
    ever needing to open a real connection."""
    assert socket.AF_INET is not None
