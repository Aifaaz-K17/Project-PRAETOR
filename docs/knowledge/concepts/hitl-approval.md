---
tags: [architecture, hitl, security, phase-5]
status: implemented
---

# HITL Approval

`firewall/hitl.py` — Phase 5 (INV-12). Resolves a `NEEDS_APPROVAL`
`Decision` (returned by [[policy-engine]]'s conflict resolution, e.g. an
`intern` drafting an email or emailing an external partner domain) into
a final `ALLOW`/`DENY` via a blocking terminal `y/n` prompt, out-of-band
from the agent (ADR 0005's primary mechanism). Without this module wired
in, `NEEDS_APPROVAL` is left as-is and treated the same as `DENY` at the
[[interception-layer]] — that was every caller's behavior through
Phase 4, and stays the default for any caller that doesn't opt in.

Four pieces:
- **`sanitize_for_display`** — strips every C0 control character
  (removes CR/LF and the ESC byte that starts an ANSI escape sequence),
  truncates with a marker, quotes the result. Everything shown to a
  human approver — tool name, session, identity, role, every argument —
  goes through this first.
- **`HitlChannel`** (`Protocol`) / **`CliApprovalChannel`** — the real
  channel: prints a sanitized rendering, then blocks for an answer via a
  reader-thread-plus-`queue.Queue(timeout=...)` pattern (portable across
  platforms, unlike `select.select()` on Windows console stdin). No
  answer within the timeout is `TIMED_OUT`, not a hang. A per-instance
  lock serializes concurrent `request_approval` calls — found and fixed
  2026-09-01: without it, two concurrent NEEDS_APPROVAL calls against a
  shared channel could interleave prompts and race for the human's next
  typed line, misattributing an answer to the wrong request (T-19 in
  `docs/THREAT_MODEL.md`). See [[0016-phase5-security-review-findings]].
- **`HitlApprover`** — the orchestrator. Tracks consumed `call_id`s
  under a lock (INV-12: single-use — a repeat resolution attempt for the
  same `call_id` is refused, not re-prompted or reused); maps
  `APPROVED`/`DENIED`/`TIMED_OUT` to a final `Decision` tagged
  `hitl:approved`/`hitl:denied`/`hitl:timed_out`; fails closed
  (`HITL_ERROR`) if the channel itself raises. Also records an approved
  call into an optional `session_store`, mirroring `PolicyEngine`'s own
  ALLOW-only recording rule — found and fixed 2026-09-01: without this,
  an approved call was invisible to session history, wrongly denying the
  very next `sequence`-gated call the approval was meant to unblock. See
  [[0016-phase5-security-review-findings]].
- **A second audit row, never an edit to the first** — if given an
  `AuditLogger`, `HitlApprover` logs the resolution as a new row with
  `call_id` suffixed `:hitl` and a fresh timestamp. INV-10's hash chain
  makes editing an already-written row structurally unsafe (it would
  break every row's hash after it), so "what policy said" and "what
  actually happened" are two rows, not one mutated row.

Wired in via `firewall.interceptor.HitlResolver` — a `Protocol`
(structural typing, mirroring `Evaluator`) defined in `interceptor.py`
itself, not imported from here, breaking what would otherwise be a
circular import. `_evaluate_call` consults it inside the same
fail-closed try/except every other decision goes through, so total
mediation (INV-02) covers the approval step too.

**Honest scope limits (see `LIMITATIONS.md` and
[[0015-hitl-resolution-mechanics]]):** a timed-out `readline()`'s reader
thread is never cancelled (Python can't safely interrupt one) — it stays
blocked until a line eventually arrives or the process exits, discarded
either way; `_consumed_call_ids` grows for the life of a `HitlApprover`
instance, unbounded, the same accepted tradeoff `SessionStore` already
carries; `scripts/query_logs.py` doesn't yet have a convenience filter
that shows both rows (the original + the `:hitl` follow-up) for one
logical call together.

## Depends on
- [[interception-layer]] — `HitlResolver` is defined there; this module implements it structurally.
- [[session-state-and-audit-trail]] — `AuditLogger.log_call` is what the second audit row is written through.

## Used by
- [[action-firewall]] — The approval step for any NEEDS_APPROVAL decision.

## Key decisions
- [[0005-hitl-approval-mechanism]] — Why a blocking terminal prompt, not Slack/webhook/dashboard.
- [[0015-hitl-resolution-mechanics]] — Where resolution happens, the cross-platform timeout mechanism, why the audit trail is a second row.
- [[0016-phase5-security-review-findings]] — Concurrent-approval race fix, session-history recording fix, and a fourth live RBAC-composition bypass (`domain-send-email-partner-needs-approval`) closed the same day Phase 5 shipped.
