---
tags: [architecture, session, audit-log, phase-4]
status: implemented
---

# Session State & Audit Trail

`firewall/session.py` (`SessionStore`) + `firewall/logger.py`
(`AuditLogger`) — Phase 4. Two separate in-process components,
both wired into `PolicyEngine.evaluate()` optionally, both closing gaps
[[policy-engine]] had left open since Phase 3.

**`SessionStore`** is real per-session call history: one
`threading.Lock` per session (not one global lock), append-only
`_SessionRecord` snapshots (a new record replaces the old one under the
session's lock — no in-place mutation, so replaying history to an earlier
point is structurally impossible), TTL eviction via an injectable clock
(INV-13 — no bare wall-clock dependence). `PolicyEngine` records a call
into history only after it was actually ALLOWED — a DENYed or
NEEDS_APPROVAL attempt never counts as "this happened" for a later
`sequence`/`rate` rule, or for [[anomaly-detection]]'s detectors. This is
what upgrades `sequence`/`rate` rules from "fully implemented against
constructed history" (Phase 3) to "actually exercisable through the live
interceptor."

Not persisted across process restarts — the audit log below is the
durable record; a fresh process starting with empty session history is
the fail-closed-correct starting state (INV-01), not an oversight.

**`AuditLogger`** writes one row per call to WAL-mode SQLite via
SQLAlchemy, shadow-logging every outcome (ALLOW, DENY, NEEDS_APPROVAL
alike — INV-10/INV-11's "shadow logging," not just denials). Each row's
`entry_hash` is a SHA-256 over the row's canonical-JSON content plus the
*previous* row's `entry_hash` (INV-10) — `firewall.logger.verify_chain`
(walked from `scripts/verify_chain.py`) re-derives every row's hash in
insertion order and reports the first row where either the content hash
or the `prev_hash` link doesn't match, which catches an edit, a deletion,
or a reorder. `redact_value` (INV-11) runs on every argument value before
it's written — secret-shaped strings (API-key patterns, `KEY=value`
pairs) are replaced outright; anything else too long is truncated with a
SHA-256 of the full value attached, never the full value itself.
`scripts/query_logs.py` is a read-only CLI over the same schema, safe by
construction since it only ever reads already-redacted rows.

## Depends on
- [[interception-layer]] — `CallRecord`/`Decision` are what both components consume and record.
- [[policy-engine]] — `PolicyEngine.evaluate()` is the only caller of either component today.

## Used by
- [[policy-engine]] — `sequence`/`rate` rule history, and every decision's shadow log entry.
- [[anomaly-detection]] — `SessionStore.get_history`/`get_declared_tools` are three of its four detectors' real inputs.

## Key decisions
- [[0012-rbac-composition-with-allowlist-rules]] — the RBAC-bypass bug this integration testing surfaced, not a `SessionStore`/`AuditLogger` design decision itself, but found because of this wiring.
