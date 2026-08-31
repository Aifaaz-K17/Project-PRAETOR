"""Tests for firewall/context.py — principal binding (INV-05)."""

import asyncio
import threading

import pytest

from firewall.context import (
    Principal,
    PrincipalNotBoundError,
    bind_principal,
    get_current_principal,
)


def test_no_principal_bound_raises_fail_closed() -> None:
    """Asking for the principal outside any bound session must raise, not
    return a default — a default would be a silent privilege decision
    (INV-01 spirit applied to context)."""
    with pytest.raises(PrincipalNotBoundError):
        get_current_principal()


def test_bind_principal_makes_it_current() -> None:
    principal = Principal(session_id="s1", identity="user-1", role="analyst")
    with bind_principal(principal):
        assert get_current_principal() == principal


def test_principal_unbound_after_with_block_exits() -> None:
    principal = Principal(session_id="s1", identity="user-1", role="analyst")
    with bind_principal(principal):
        pass
    with pytest.raises(PrincipalNotBoundError):
        get_current_principal()


def test_nested_bind_restores_outer_principal_on_exit() -> None:
    outer = Principal(session_id="outer", identity="outer-user", role="analyst")
    inner = Principal(session_id="inner", identity="inner-user", role="admin")
    with bind_principal(outer):
        assert get_current_principal() == outer
        with bind_principal(inner):
            assert get_current_principal() == inner
        assert get_current_principal() == outer


def test_INV_05_principal_is_isolated_across_threads() -> None:
    """Two threads binding different principals must never see each
    other's — contextvars, not a shared global, is what guarantees this."""
    results: dict[str, Principal | Exception] = {}

    def worker(name: str, role: str) -> None:
        try:
            principal = Principal(session_id=name, identity=name, role=role)
            with bind_principal(principal):
                # Give the other thread a chance to interleave.
                threading.Event().wait(0.01)
                results[name] = get_current_principal()
        except Exception as exc:  # noqa: BLE001
            results[name] = exc

    t1 = threading.Thread(target=worker, args=("thread-a", "role-a"))
    t2 = threading.Thread(target=worker, args=("thread-b", "role-b"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert results["thread-a"] == Principal(
        session_id="thread-a", identity="thread-a", role="role-a"
    )
    assert results["thread-b"] == Principal(
        session_id="thread-b", identity="thread-b", role="role-b"
    )


def test_INV_05_principal_is_isolated_across_asyncio_tasks() -> None:
    """Two concurrently-gathered asyncio tasks binding different principals
    must never see each other's, even though they interleave on one
    thread."""

    async def worker(name: str, role: str) -> Principal:
        principal = Principal(session_id=name, identity=name, role=role)
        with bind_principal(principal):
            await asyncio.sleep(0.01)
            return get_current_principal()

    async def run_both() -> tuple[Principal, Principal]:
        return await asyncio.gather(
            worker("task-a", "role-a"),
            worker("task-b", "role-b"),
        )

    result_a, result_b = asyncio.run(run_both())
    assert result_a == Principal(session_id="task-a", identity="task-a", role="role-a")
    assert result_b == Principal(session_id="task-b", identity="task-b", role="role-b")
