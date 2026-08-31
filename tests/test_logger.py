"""Tests for firewall/logger.py — Phase 4 (INV-10 tamper-evident audit,
INV-11 log hygiene). Prior to this file, both properties were only ever
smoke-tested ad hoc during development, not asserted by a real pytest
test — this closes that gap.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from firewall.interceptor import CallRecord, Decision, Outcome
from firewall.logger import (
    GENESIS_HASH,
    AuditLogger,
    AuditLogRow,
    compute_entry_hash,
    redact_value,
    verify_chain,
)


def make_call(
    *,
    call_id: str = "c1",
    tool_name: str = "read_file",
    role: str = "analyst",
    args: dict | None = None,
    session_id: str = "s1",
    identity: str = "u1",
) -> CallRecord:
    args = args if args is not None else {}
    return CallRecord(
        call_id=call_id,
        tool_name=tool_name,
        raw_args=args,
        canonical_args=dict(args),
        session_id=session_id,
        identity=identity,
        role=role,
        timestamp_utc=datetime.now(UTC),
        timestamp_monotonic_ns=0,
        sequence_index=0,
    )


def make_decision(
    *, outcome: Outcome = Outcome.ALLOW, rule_id: str | None = "r1"
) -> Decision:
    return Decision(outcome=outcome, reason="test reason", rule_id=rule_id)


# ---------------------------------------------------------------------------
# Redaction (INV-11) — a planted fake secret must never reach the DB
# ---------------------------------------------------------------------------


def test_INV_11_redact_value_replaces_api_key_shaped_string() -> None:
    planted = "sk-THISISAFAKETESTKEYNOTREAL1234567890"
    redacted = redact_value(planted)
    assert planted not in redacted
    assert "REDACTED" in redacted


def test_INV_11_redact_value_replaces_key_equals_value_pattern() -> None:
    planted = "API_KEY=hunter2superreal"
    redacted = redact_value(planted)
    assert "hunter2superreal" not in redacted
    assert "REDACTED" in redacted


def test_INV_11_redact_value_leaves_ordinary_prose_mentioning_password_alone() -> None:
    """A bare word like "password" with no adjacent `:`/`=` must not
    trigger redaction — this is what lets a legitimate note like "please
    reset your password" survive into the log unredacted."""
    text = "please reset your password before Friday"
    assert redact_value(text) == text


def test_INV_11_redact_value_recurses_into_nested_dict_and_list() -> None:
    planted = "sk-THISISAFAKETESTKEYNOTREAL1234567890"
    value = {"outer": {"inner": [planted, "harmless"]}}
    redacted = redact_value(value)
    assert planted not in str(redacted)
    assert redacted["outer"]["inner"][1] == "harmless"


def test_INV_11_audit_logger_never_persists_a_planted_secret(tmp_path: Path) -> None:
    """End-to-end: a fake secret passed as a call argument must never
    appear anywhere in the audit database's on-disk content."""
    planted_secret = (
        "sk-THISISAFAKETESTKEYNOTREAL1234567890"  # pragma: allowlist secret
    )
    db_path = tmp_path / "audit.db"

    with AuditLogger(db_path, policy_set_hash="hash1") as logger:
        logger.log_call(
            call=make_call(args={"note": f"transfer memo: {planted_secret}"}),
            decision=make_decision(),
            latency_ns=1000,
        )

    raw_db_bytes = db_path.read_bytes()
    assert planted_secret.encode("utf-8") not in raw_db_bytes


def test_INV_11_long_value_truncated_with_hash_not_dropped_silently() -> None:
    # Plain repeated words, not a base64-shaped run — this exercises the
    # "too long" truncation path specifically, distinct from the
    # secret-shaped-value redaction path covered above.
    long_value = "word " * 100
    redacted = redact_value(long_value, max_length=200)
    assert redacted.startswith(long_value[:200])
    assert "truncated from 500 chars" in redacted
    assert "sha256=" in redacted


# ---------------------------------------------------------------------------
# Hash chain (INV-10) — writing, linking, and tamper detection
# ---------------------------------------------------------------------------


def test_first_row_chains_from_the_genesis_hash(tmp_path: Path) -> None:
    with AuditLogger(tmp_path / "audit.db", policy_set_hash="hash1") as logger:
        entry = logger.log_call(
            call=make_call(), decision=make_decision(), latency_ns=1000
        )
    assert entry.prev_hash == GENESIS_HASH


def test_second_row_chains_from_the_first_rows_entry_hash(tmp_path: Path) -> None:
    with AuditLogger(tmp_path / "audit.db", policy_set_hash="hash1") as logger:
        first = logger.log_call(
            call=make_call(call_id="c1"), decision=make_decision(), latency_ns=1000
        )
        second = logger.log_call(
            call=make_call(call_id="c2"), decision=make_decision(), latency_ns=1000
        )
    assert second.prev_hash == first.entry_hash
    assert second.entry_hash != first.entry_hash


def test_reopening_an_existing_log_continues_the_same_chain(tmp_path: Path) -> None:
    """A fresh AuditLogger instance pointed at an existing database must
    pick up the chain where it left off, not restart from GENESIS_HASH —
    otherwise every process restart would silently break INV-10."""
    db_path = tmp_path / "audit.db"
    with AuditLogger(db_path, policy_set_hash="hash1") as logger:
        first = logger.log_call(
            call=make_call(call_id="c1"), decision=make_decision(), latency_ns=1000
        )

    with AuditLogger(db_path, policy_set_hash="hash1") as logger:
        second = logger.log_call(
            call=make_call(call_id="c2"), decision=make_decision(), latency_ns=1000
        )

    assert second.prev_hash == first.entry_hash


def test_INV_10_verify_chain_passes_on_an_untampered_log(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    with AuditLogger(db_path, policy_set_hash="hash1") as logger:
        for i in range(5):
            logger.log_call(
                call=make_call(call_id=f"c{i}"),
                decision=make_decision(),
                latency_ns=1000,
            )

    result = verify_chain(db_path)
    assert result.ok is True
    assert result.rows_checked == 5
    assert result.first_break is None


def test_INV_10_verify_chain_reports_missing_database_as_a_failure(
    tmp_path: Path,
) -> None:
    result = verify_chain(tmp_path / "does-not-exist.db")
    assert result.ok is False
    assert result.rows_checked == 0
    assert "not found" in result.first_break


def test_INV_10_verify_chain_detects_a_row_edited_after_the_fact(
    tmp_path: Path,
) -> None:
    """The core tamper-evidence claim: directly editing a row's content in
    the database (bypassing AuditLogger entirely, simulating an attacker
    or a rogue admin with raw DB access) must be detected — the row's
    entry_hash no longer matches its (now-changed) content."""
    db_path = tmp_path / "audit.db"
    with AuditLogger(db_path, policy_set_hash="hash1") as logger:
        for i in range(3):
            logger.log_call(
                call=make_call(call_id=f"c{i}"),
                decision=make_decision(),
                latency_ns=1000,
            )

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(f"sqlite:///{db_path}", future=True)
    try:
        session_factory = sessionmaker(bind=engine, future=True)
        with session_factory() as session:
            row = session.execute(
                select(AuditLogRow).where(AuditLogRow.call_id == "c1")
            ).scalar_one()
            row.outcome = "DENY"  # tamper: ALLOW (as written) -> DENY
            session.commit()
    finally:
        engine.dispose()

    result = verify_chain(db_path)
    assert result.ok is False
    assert "c1" in result.first_break
    assert "entry_hash mismatch" in result.first_break


def test_INV_10_verify_chain_detects_a_deleted_row(tmp_path: Path) -> None:
    """Deleting a row breaks the chain from the deleted row's successor
    onward, because that successor's prev_hash no longer matches anything
    still present."""
    db_path = tmp_path / "audit.db"
    with AuditLogger(db_path, policy_set_hash="hash1") as logger:
        for i in range(3):
            logger.log_call(
                call=make_call(call_id=f"c{i}"),
                decision=make_decision(),
                latency_ns=1000,
            )

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(f"sqlite:///{db_path}", future=True)
    try:
        session_factory = sessionmaker(bind=engine, future=True)
        with session_factory() as session:
            row = session.execute(
                select(AuditLogRow).where(AuditLogRow.call_id == "c1")
            ).scalar_one()
            session.delete(row)
            session.commit()
    finally:
        engine.dispose()

    result = verify_chain(db_path)
    assert result.ok is False
    assert "prev_hash mismatch" in result.first_break


def test_INV_10_verify_chain_reports_only_the_first_break(tmp_path: Path) -> None:
    """Tampering with an early row invalidates every row after it too —
    verify_chain must stop at the first one, not report all of them, so
    the human reading the output can see where the actual tampering
    happened rather than a wall of downstream noise."""
    db_path = tmp_path / "audit.db"
    with AuditLogger(db_path, policy_set_hash="hash1") as logger:
        for i in range(5):
            logger.log_call(
                call=make_call(call_id=f"c{i}"),
                decision=make_decision(),
                latency_ns=1000,
            )

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(f"sqlite:///{db_path}", future=True)
    try:
        session_factory = sessionmaker(bind=engine, future=True)
        with session_factory() as session:
            row = session.execute(
                select(AuditLogRow).where(AuditLogRow.call_id == "c0")
            ).scalar_one()
            row.reason = "tampered"
            session.commit()
    finally:
        engine.dispose()

    result = verify_chain(db_path)
    assert result.ok is False
    assert result.rows_checked == 1
    assert "c0" in result.first_break


def test_compute_entry_hash_is_deterministic_regardless_of_dict_key_order() -> None:
    """INV-13: the same logical row content must always hash the same
    way, independent of incidental dict-construction order."""
    a = {"call_id": "c1", "tool_name": "read_file", "outcome": "ALLOW"}
    b = {"outcome": "ALLOW", "call_id": "c1", "tool_name": "read_file"}
    assert compute_entry_hash(a, GENESIS_HASH) == compute_entry_hash(b, GENESIS_HASH)


# ---------------------------------------------------------------------------
# WAL mode (a real audit database, not an assertion about a mock)
# ---------------------------------------------------------------------------


def test_audit_database_is_created_in_wal_journal_mode(tmp_path: Path) -> None:
    """WAL mode lets a future dashboard read the log while the firewall
    keeps writing to it — confirmed here against the real on-disk pragma,
    not just that we called the right SQLAlchemy API."""
    db_path = tmp_path / "audit.db"
    with AuditLogger(db_path, policy_set_hash="hash1") as logger:
        logger.log_call(call=make_call(), decision=make_decision(), latency_ns=1000)

    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        conn.close()
    assert mode.lower() == "wal"
