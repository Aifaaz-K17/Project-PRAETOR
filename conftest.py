"""Repo-wide pytest configuration.

INV-14 (No live targets, ever): CI runs offline, and no test — now or in any
future phase — may perform real network I/O. Attack payloads only ever
touch sandbox/. Rather than trust every future test author to remember
that, this fixture makes network access impossible at the socket layer, for
every test in the suite, automatically.
"""

import socket

import pytest


class NetworkBlockedError(RuntimeError):
    """Raised instead of letting any test open a real socket (INV-14)."""


def _blocked_socket(*_args: object, **_kwargs: object) -> None:
    raise NetworkBlockedError(
        "Network access is disabled during tests (INV-14: no live targets, "
        "ever). If a test needs network-shaped behavior, mock it — do not "
        "disable this fixture."
    )


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    # Patching the socket.socket *class* (not just connect/send) blocks every
    # code path that needs a real network primitive, including ones a
    # library builds internally without calling connect() directly.
    monkeypatch.setattr(socket, "socket", _blocked_socket)
