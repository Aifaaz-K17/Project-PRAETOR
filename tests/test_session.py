"""Tests for firewall/session.py — Phase 4."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

from firewall.session import SessionStore


def test_unknown_session_has_empty_history() -> None:
    store = SessionStore()
    assert store.get_history("never-seen") == ()


def test_unknown_session_has_empty_declared_tools() -> None:
    store = SessionStore()
    assert store.get_declared_tools("never-seen") == frozenset()


def test_record_call_appends_to_history() -> None:
    store = SessionStore()
    now = datetime.now(UTC)
    store.record_call("s1", "compose_draft", now)
    store.record_call("s1", "send_email", now + timedelta(seconds=1))

    history = store.get_history("s1")
    assert [tool for tool, _ in history] == ["compose_draft", "send_email"]


def test_record_call_lazily_creates_a_session() -> None:
    """declare_session is optional — the interceptor's real usage never
    calls it, since PolicyEngine only ever calls record_call after an
    ALLOW decision."""
    store = SessionStore()
    store.record_call("never-declared", "read_file", datetime.now(UTC))
    assert len(store.get_history("never-declared")) == 1


def test_declare_session_sets_declared_tools() -> None:
    store = SessionStore()
    store.declare_session(
        "s1",
        identity="u1",
        role="analyst",
        declared_tools=frozenset({"read_file", "search_web"}),
    )
    assert store.get_declared_tools("s1") == frozenset({"read_file", "search_web"})


def test_history_is_append_only_not_replayable() -> None:
    """Each call to record_call produces a brand new immutable snapshot —
    a reference to an old snapshot (taken via get_history) must not change
    when more calls are recorded afterward, proving there's no shared
    mutable list being rewritten underneath it."""
    store = SessionStore()
    now = datetime.now(UTC)
    store.record_call("s1", "compose_draft", now)
    first_snapshot = store.get_history("s1")

    store.record_call("s1", "send_email", now + timedelta(seconds=1))
    second_snapshot = store.get_history("s1")

    assert first_snapshot == (("compose_draft", now),)
    assert second_snapshot == (
        ("compose_draft", now),
        ("send_email", now + timedelta(seconds=1)),
    )
    assert first_snapshot != second_snapshot  # the old snapshot was never mutated


def test_different_sessions_do_not_share_history() -> None:
    store = SessionStore()
    now = datetime.now(UTC)
    store.record_call("s1", "compose_draft", now)
    store.record_call("s2", "read_file", now)

    assert [t for t, _ in store.get_history("s1")] == ["compose_draft"]
    assert [t for t, _ in store.get_history("s2")] == ["read_file"]


def test_ttl_expiry_uses_injected_clock() -> None:
    """INV-13: no live wall-clock dependence — TTL is checked entirely
    against an injected clock, so this test never needs a real sleep."""
    current_time = datetime(2026, 1, 1, tzinfo=UTC)

    def fake_clock() -> datetime:
        return current_time

    store = SessionStore(ttl_seconds=60.0, clock=fake_clock)
    store.record_call("s1", "read_file", current_time)
    assert len(store.get_history("s1")) == 1

    current_time = current_time + timedelta(seconds=30)  # still within TTL
    assert len(store.get_history("s1")) == 1

    current_time = current_time + timedelta(seconds=60)  # now past TTL
    assert store.get_history("s1") == ()


def test_evict_expired_removes_only_stale_sessions() -> None:
    current_time = datetime(2026, 1, 1, tzinfo=UTC)

    def fake_clock() -> datetime:
        return current_time

    store = SessionStore(ttl_seconds=60.0, clock=fake_clock)
    store.record_call("stale", "read_file", current_time)

    current_time = current_time + timedelta(seconds=120)
    store.record_call("fresh", "read_file", current_time)

    evicted = store.evict_expired()
    assert evicted == 1
    assert store.get_history("stale") == ()
    assert len(store.get_history("fresh")) == 1


def test_INV_13_concurrent_calls_in_the_same_session_are_all_recorded() -> None:
    """Thread-safety: many threads recording calls into the SAME session
    concurrently must never lose an update (a naive read-modify-write on
    a shared list without a lock could drop entries under contention)."""
    store = SessionStore()
    now = datetime.now(UTC)
    call_count = 200
    thread_count = 8

    def worker(thread_index: int) -> None:
        for i in range(call_count):
            store.record_call("shared-session", f"tool-{thread_index}-{i}", now)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    history = store.get_history("shared-session")
    assert len(history) == call_count * thread_count
    # every recorded tool name is unique, so no update was lost or duplicated
    assert len({tool for tool, _ in history}) == call_count * thread_count


def test_concurrent_calls_across_different_sessions_do_not_block_each_other() -> None:
    """Per-session locking (not one global lock): recording into many
    different sessions concurrently must all complete correctly."""
    store = SessionStore()
    now = datetime.now(UTC)
    session_count = 50

    def worker(session_index: int) -> None:
        store.record_call(f"session-{session_index}", "read_file", now)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(session_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for i in range(session_count):
        assert len(store.get_history(f"session-{i}")) == 1


def test_declare_session_resets_history_if_called_again() -> None:
    """declare_session is a real (re-)initialization, not a merge — this
    is documented behavior, not accidental: re-declaring a session id
    starts its history over."""
    store = SessionStore()
    store.record_call("s1", "read_file", datetime.now(UTC))
    assert len(store.get_history("s1")) == 1

    store.declare_session("s1", identity="u1", role="analyst")
    assert store.get_history("s1") == ()
