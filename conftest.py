"""Repo-wide pytest configuration.

INV-14 (No live targets, ever): CI runs offline, and no test — now or in any
future phase — may perform real network I/O. Attack payloads only ever
touch sandbox/. Rather than trust every future test author to remember
that, this fixture makes outbound network connections impossible for every
test in the suite, automatically.
"""

import socket
from typing import Any

import pytest

# asyncio's own event loop needs real loopback sockets internally — on
# Windows, ProactorEventLoop's self-pipe (used purely for internal wakeup
# notifications, never for actual network traffic) is implemented with
# socket.socketpair(), which is built out of a real connect() to 127.0.0.1
# under the hood. An earlier version of this fixture blocked
# socket.socket() itself and broke every async test on Windows for exactly
# this reason (confirmed while writing Phase 1's async tests) — the fix is
# to block only connections to non-loopback destinations, which is also a
# more accurate reading of INV-14 ("no live targets") than blocking all
# socket use.
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "0.0.0.0", ""}


class NetworkBlockedError(RuntimeError):
    """Raised instead of letting any test open a real network connection
    (INV-14)."""


def _is_loopback_address(address: Any) -> bool:
    if isinstance(address, tuple) and len(address) >= 1:
        return address[0] in _LOOPBACK_HOSTS
    return False


def _make_guarded(method_name: str, original: Any) -> Any:
    def guarded(self: socket.socket, address: Any, *args: Any, **kwargs: Any) -> Any:
        if not _is_loopback_address(address):
            raise NetworkBlockedError(
                f"socket.{method_name}({address!r}) blocked — network access "
                "to non-loopback addresses is disabled during tests (INV-14: "
                "no live targets, ever). If a test needs network-shaped "
                "behavior, mock it — do not disable this fixture."
            )
        return original(self, address, *args, **kwargs)

    return guarded


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    for method_name in ("connect", "connect_ex"):
        original = getattr(socket.socket, method_name)
        monkeypatch.setattr(
            socket.socket, method_name, _make_guarded(method_name, original)
        )
