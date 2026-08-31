"""Session state — Phase 4.

`SessionStore` is the real session history Phase 3's `sequence`/`rate`
policy rules were always designed for (`firewall/policy_engine.py`'s
`SessionHistoryEntry` type predates this module by design — see ADR
0012). Wiring a `SessionStore` into `PolicyEngine` (see
`PolicyEngine.__init__`'s `session_store` parameter) is what upgrades
those two rule types from "fully implemented and tested against
constructed history" to "actually exercisable through the live
interceptor" — closing a gap `LIMITATIONS.md` has documented since Phase
3.

Thread-safe and async-safe: one `threading.Lock` per session, not one
global lock, so unrelated sessions never contend with each other. State
transitions are append-only — `record_call` can only ever add a new entry
to the end of a session's history, never rewrite or remove one, so replay
(rewinding a session's history to an earlier point) is structurally
impossible, not just discouraged.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

SessionHistoryEntry = tuple[str, datetime]  # (tool_name, called_at_utc)


@dataclass(frozen=True)
class _SessionRecord:
    """Internal, immutable snapshot of one session's state at a point in
    time. `record_call` never mutates one of these in place — it builds a
    new `_SessionRecord` with one more history entry and the store swaps
    the stored reference under that session's lock. Old snapshots are
    simply discarded, never kept around to be replayed against.
    """

    session_id: str
    identity: str
    role: str
    created_at: datetime
    last_active_at: datetime
    declared_tools: frozenset[str]
    history: tuple[SessionHistoryEntry, ...]


class SessionStore:
    """A thread-safe, in-memory session store.

    Not persisted across process restarts — that's a deliberate scope
    boundary for this phase (see LIMITATIONS.md), not an oversight: the
    audit log (`firewall/logger.py`) is the durable record, and a fresh
    process starting with no session history is the fail-closed-correct
    starting state (INV-01) for any sequence/rate rule, not a bug.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = 3600.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._ttl = timedelta(seconds=ttl_seconds)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._store_lock = threading.Lock()  # protects the dict itself
        self._sessions: dict[str, _SessionRecord] = {}
        self._session_locks: dict[str, threading.Lock] = {}

    def _lock_for(self, session_id: str) -> threading.Lock:
        with self._store_lock:
            lock = self._session_locks.get(session_id)
            if lock is None:
                lock = threading.Lock()
                self._session_locks[session_id] = lock
            return lock

    def _is_expired(self, record: _SessionRecord, now: datetime) -> bool:
        return now - record.last_active_at > self._ttl

    def declare_session(
        self,
        session_id: str,
        *,
        identity: str,
        role: str,
        declared_tools: frozenset[str] = frozenset(),
    ) -> None:
        """Explicitly register a session, optionally declaring the tool
        set it's expected to use (consulted by
        `firewall.anomaly.detect_tool_outside_declared_set` — an empty
        set means "not declared", not "no tools allowed", the same
        opt-in-by-declaration pattern `parameter_schema` rules use).
        Calling this isn't required — `record_call` lazily creates a
        minimal session on first use — but doing it at real session
        creation (alongside `firewall.context.bind_principal`) is how a
        caller gets the declared-toolset anomaly check for free.
        """
        now = self._clock()
        with self._lock_for(session_id):
            self._sessions[session_id] = _SessionRecord(
                session_id=session_id,
                identity=identity,
                role=role,
                created_at=now,
                last_active_at=now,
                declared_tools=declared_tools,
                history=(),
            )

    def record_call(self, session_id: str, tool_name: str, called_at: datetime) -> None:
        """Append one call to a session's history. Lazily creates the
        session (with an empty declared-tools set) if `declare_session`
        was never called for it — the interceptor only calls this after a
        call was actually ALLOWED (see `PolicyEngine.evaluate`), so a
        denied or needs-approval call never becomes part of the history a
        later `sequence` rule checks against.
        """
        with self._lock_for(session_id):
            existing = self._sessions.get(session_id)
            if existing is None:
                existing = _SessionRecord(
                    session_id=session_id,
                    identity="",
                    role="",
                    created_at=called_at,
                    last_active_at=called_at,
                    declared_tools=frozenset(),
                    history=(),
                )
            self._sessions[session_id] = _SessionRecord(
                session_id=existing.session_id,
                identity=existing.identity,
                role=existing.role,
                created_at=existing.created_at,
                last_active_at=called_at,
                declared_tools=existing.declared_tools,
                history=(*existing.history, (tool_name, called_at)),
            )

    def get_history(self, session_id: str) -> tuple[SessionHistoryEntry, ...]:
        """Returns an immutable snapshot of everything recorded so far for
        this session — `()` for a session that doesn't exist (yet, or was
        evicted), which is exactly the fail-closed-correct "nothing is
        known to have happened" answer a `sequence`/`rate` rule needs.
        """
        with self._lock_for(session_id):
            record = self._sessions.get(session_id)
            if record is None or self._is_expired(record, self._clock()):
                return ()
            return record.history

    def get_declared_tools(self, session_id: str) -> frozenset[str]:
        with self._lock_for(session_id):
            record = self._sessions.get(session_id)
            if record is None or self._is_expired(record, self._clock()):
                return frozenset()
            return record.declared_tools

    def evict_expired(self) -> int:
        """Remove every session whose `last_active_at` is older than the
        TTL. Not called automatically on every operation (that would mean
        every read/write pays an O(n) scan) — call this periodically (a
        background task, or once per some number of calls) in a real
        deployment. Returns the number of sessions evicted."""
        now = self._clock()
        with self._store_lock:
            expired_ids = [
                session_id
                for session_id, record in self._sessions.items()
                if self._is_expired(record, now)
            ]
            for session_id in expired_ids:
                del self._sessions[session_id]
                self._session_locks.pop(session_id, None)
            return len(expired_ids)
