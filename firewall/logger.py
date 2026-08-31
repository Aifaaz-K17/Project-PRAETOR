"""Tamper-evident audit trail — Phase 4 (INV-10, INV-11).

One row per call, written to SQLite in WAL mode (`journal_mode=WAL` — lets
a future dashboard read the log while the firewall keeps writing to it).
Shadow logging: `AuditLogger.log_call` doesn't discriminate by outcome —
every decision (ALLOW, DENY, NEEDS_APPROVAL) gets a row, not just denials.

Hash chain (INV-10): each row's `entry_hash` commits to everything about
that row plus the previous row's `entry_hash`, so `scripts/verify_chain.py`
can detect any row that was edited or deleted after the fact — changing
one row breaks its own hash, and every row after it, since each one's
input includes the previous row's hash.

Redaction (INV-11): every argument value is passed through `redact_value`
before it's written — secret-shaped strings are replaced outright, and
anything else too long is truncated with a SHA-256 of the full value
attached, never the full value itself.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Self

from sqlalchemy import Column, Integer, String, Text, create_engine, event, select
from sqlalchemy.orm import declarative_base, sessionmaker

from firewall.interceptor import CallRecord, Decision

# ---------------------------------------------------------------------------
# Redaction (INV-11)
# ---------------------------------------------------------------------------

DEFAULT_MAX_VALUE_LENGTH = 200

# Fixed, developer-authored patterns (not user/policy-authored — stdlib
# `re` is fine here, unlike firewall/policy_engine.py's `regex` package,
# which exists specifically for policy-authored patterns that need a
# runtime timeout, INV-09).
_SECRET_KEYWORD_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|token|auth(?:orization)?)\b"
)
_KEY_VALUE_SEPARATOR_RE = re.compile(r"[:=]\s*\S")
_LONG_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_CLOUD_KEY_RE = re.compile(
    r"\b(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,})\b"
)


def _looks_like_a_secret(value: str) -> bool:
    """Best-effort, like the ReDoS linter in firewall/policy_engine.py —
    not a claim of catching every possible secret shape."""
    if (
        _CLOUD_KEY_RE.search(value)
        or _JWT_RE.search(value)
        or _LONG_BASE64_RE.search(value)
    ):
        return True
    # A bare word like "password" in ordinary prose ("reset your password")
    # must not trigger this — requiring an adjacent `:`/`=` narrows it to
    # the shape of an actual assignment (".env"-style `API_KEY=sk-...` or
    # `password: hunter2`), which is what INV-11 actually cares about.
    return bool(
        _SECRET_KEYWORD_RE.search(value) and _KEY_VALUE_SEPARATOR_RE.search(value)
    )


def _redact_string(value: str, *, max_length: int) -> str:
    full_hash = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    if _looks_like_a_secret(value):
        return f"[REDACTED: possible secret, sha256={full_hash}]"
    if len(value) > max_length:
        return f"{value[:max_length]}...[truncated from {len(value)} chars, sha256={full_hash}]"
    return value


def redact_value(value: Any, *, max_length: int = DEFAULT_MAX_VALUE_LENGTH) -> Any:
    """Recursively redact a value before it's written to the audit log.
    Never call str() on a non-string and check *that* — a dict or list
    containing a secret must have the secret redacted at its own leaf, not
    have the whole structure's str() representation truncated (which could
    still leak the secret if it happened to land before the cutoff)."""
    if isinstance(value, str):
        return _redact_string(value, max_length=max_length)
    if isinstance(value, dict):
        return {k: redact_value(v, max_length=max_length) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(v, max_length=max_length) for v in value]
    return value


# ---------------------------------------------------------------------------
# Canonical JSON + the hash chain (INV-10)
# ---------------------------------------------------------------------------

GENESIS_HASH = "0" * 64  # sentinel prev_hash for the very first row ever written


def canonical_json(data: dict[str, Any] | list[Any]) -> str:
    """Stable serialization for hashing: sorted keys, no incidental
    whitespace, so the same logical value always hashes the same way
    regardless of dict insertion order."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_entry_hash(row_without_hash_fields: dict[str, Any], prev_hash: str) -> str:
    """entry_hash = sha256(canonical_json(row_without_hash) + prev_hash).
    `row_without_hash_fields` must not contain `prev_hash` or `entry_hash`
    — both are chain bookkeeping, not part of what this row is asserting
    happened, and `prev_hash` is deliberately appended raw afterward
    rather than folded into the JSON, so the formula is exactly what it
    says: canonical row content, then the chain link, hashed together.
    """
    payload = canonical_json(row_without_hash_fields).encode(
        "utf-8"
    ) + prev_hash.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# SQLAlchemy schema
# ---------------------------------------------------------------------------

Base = declarative_base()


class AuditLogRow(Base):  # type: ignore[valid-type,misc]
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    call_id = Column(String, nullable=False, unique=True)
    session_id = Column(String, nullable=False)
    identity = Column(String, nullable=False)
    role = Column(String, nullable=False)
    tool_name = Column(String, nullable=False)
    redacted_args_json = Column(Text, nullable=False)
    outcome = Column(String, nullable=False)
    # A JSON array, not a single value: Decision today only ever carries
    # one deciding rule_id (Phase 3's conflict resolution picks exactly
    # one winner), so this is currently always `[]` or a single-element
    # list — modeled as a list so a richer future Decision (e.g. Phase 4's
    # anomaly detector attaching its own findings) doesn't need a schema
    # migration to record more than one.
    matched_rule_ids_json = Column(Text, nullable=False)
    reason = Column(Text, nullable=False)
    policy_set_hash = Column(String, nullable=False)
    latency_ns = Column(Integer, nullable=False)
    timestamp_utc = Column(String, nullable=False)
    prev_hash = Column(String(64), nullable=False)
    entry_hash = Column(String(64), nullable=False, unique=True)


def _make_engine(db_path: str | Path):  # type: ignore[no-untyped-def]
    engine = create_engine(f"sqlite:///{db_path}", future=True)

    @event.listens_for(engine, "connect")
    def _set_wal_mode(dbapi_connection: Any, connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    return engine


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LoggedEntry:
    """What `AuditLogger.log_call` hands back — mainly useful in tests and
    for a caller that wants to print/display the hash it just wrote."""

    call_id: str
    entry_hash: str
    prev_hash: str


class AuditLogger:
    """Writes one row per call, shadow-logging every outcome. Thread-safe:
    the hash chain must be strictly sequential (row N's prev_hash is row
    N-1's entry_hash), so writes are serialized under one lock — the audit
    log is not a hot path the way policy evaluation is, so this is not a
    throughput concern.

    Also a context manager: `close()`/`__exit__` disposes the underlying
    SQLAlchemy engine. On Windows in particular, an undisposed engine can
    keep the SQLite file handle open after the last logical use, which
    blocks deleting or renaming the file (a real issue caught while
    smoke-testing this module against a pytest `tmp_path`) — always use
    `with AuditLogger(...) as logger:` or call `close()` explicitly when
    you're done with one.
    """

    def __init__(self, db_path: str | Path, *, policy_set_hash: str) -> None:
        self._policy_set_hash = policy_set_hash
        self._engine = _make_engine(db_path)
        Base.metadata.create_all(self._engine)
        self._session_factory = sessionmaker(bind=self._engine, future=True)
        self._lock = threading.Lock()
        self._prev_hash = self._load_last_entry_hash()

    def _load_last_entry_hash(self) -> str:
        with self._session_factory() as session:
            last = session.execute(
                select(AuditLogRow.entry_hash).order_by(AuditLogRow.id.desc()).limit(1)
            ).scalar_one_or_none()
            return last if last is not None else GENESIS_HASH

    def log_call(
        self,
        *,
        call: CallRecord,
        decision: Decision,
        latency_ns: int,
        max_value_length: int = DEFAULT_MAX_VALUE_LENGTH,
    ) -> LoggedEntry:
        redacted_args = redact_value(call.canonical_args, max_length=max_value_length)
        matched_rule_ids = [decision.rule_id] if decision.rule_id else []

        row_fields = {
            "call_id": call.call_id,
            "session_id": call.session_id,
            "identity": call.identity,
            "role": call.role,
            "tool_name": call.tool_name,
            "redacted_args": redacted_args,
            "outcome": decision.outcome.value,
            "matched_rule_ids": matched_rule_ids,
            "reason": decision.reason,
            "policy_set_hash": self._policy_set_hash,
            "latency_ns": latency_ns,
            "timestamp_utc": call.timestamp_utc.isoformat(),
        }

        with self._lock:
            prev_hash = self._prev_hash
            entry_hash = compute_entry_hash(row_fields, prev_hash)

            with self._session_factory() as session:
                session.add(
                    AuditLogRow(
                        call_id=row_fields["call_id"],
                        session_id=row_fields["session_id"],
                        identity=row_fields["identity"],
                        role=row_fields["role"],
                        tool_name=row_fields["tool_name"],
                        redacted_args_json=canonical_json(redacted_args),
                        outcome=row_fields["outcome"],
                        matched_rule_ids_json=canonical_json(matched_rule_ids),
                        reason=row_fields["reason"],
                        policy_set_hash=row_fields["policy_set_hash"],
                        latency_ns=latency_ns,
                        timestamp_utc=row_fields["timestamp_utc"],
                        prev_hash=prev_hash,
                        entry_hash=entry_hash,
                    )
                )
                session.commit()

            self._prev_hash = entry_hash

        return LoggedEntry(
            call_id=call.call_id, entry_hash=entry_hash, prev_hash=prev_hash
        )

    def close(self) -> None:
        self._engine.dispose()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
