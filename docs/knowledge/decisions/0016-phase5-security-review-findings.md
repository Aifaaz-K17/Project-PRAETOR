---
tags: [decision, security, hitl, code-review]
status: accepted
date: 2026-09-01
---

# 0016 — Phase 5 Completion Security Review: Three More Real Bugs

## Status
Accepted.

## Context
Following the same working agreement as [[0014-phase4-security-review-findings]]
— a deliberate bug/vulnerability/weakness pass before treating a phase as
truly done — this pass targeted `firewall/hitl.py` and its interceptor
wiring, since Phase 5 had just shipped and had not yet had an adversarial
look. Each finding below was independently reproduced against the real
code (not asserted from reading alone) before being fixed.

## Decision

### Finding 1 — concurrent approval requests race for the human's answer
`CliApprovalChannel.request_approval` had no synchronization. Two
NEEDS_APPROVAL calls resolved concurrently against a *shared* channel
(a real, already-tested shape —
`test_parallel_async_calls_within_same_principal_are_each_intercepted`
in `tests/test_interceptor.py` proves parallel calls happen) would print
two interleaved "APPROVAL REQUIRED" prompts to the same terminal and
race for whichever reader thread the OS delivered the human's next typed
line to. Reproduced directly: with a shared `input_stream` holding one
`"y\n"` line, two concurrent `request_approval` calls resulted in one
getting `APPROVED` and the other `DENIED (no input)` — nondeterministic,
and with no guarantee the approval landed on the request the human
actually meant to answer. Framed as a new threat-model row, T-19 (a
human approver being tricked into approving the wrong action), not
folded into T-14/T-15 which cover injection and replay/timeout
specifically, not concurrency.

**Fix:** a `threading.Lock` inside `CliApprovalChannel`, held for the
entire `request_approval` call. A second concurrent request now waits
its turn — its own prompt isn't even shown, and its timeout clock
doesn't start, until the first request's full prompt-then-answer cycle
is done. Reproduced-fixed: the same two-concurrent-requests scenario,
using a stream that hands out answers one at a time under its own lock
(simulating a real terminal, not `StringIO`'s instant-EOF-on-second-read
artifact), now gives each request its own correctly-attributed answer.
Test: `test_INV_12_concurrent_approvals_are_serialized_not_interleaved`.

### Finding 2 — a HITL-approved call was never recorded into session history
`PolicyEngine.evaluate` records a call into `SessionStore` only when its
*own* return value is ALLOW. But when `evaluate` returns
`NEEDS_APPROVAL`, HITL resolution happens strictly afterward, inside the
interceptor's `_evaluate_call`, calling `HitlApprover.resolve_approval`
— which `PolicyEngine` has no way to observe. Reproduced end-to-end: an
`intern`'s `compose_draft` was approved and genuinely executed
(`"drafted"` returned), but `store.get_history(...)` stayed empty
afterward, and the very next `send_email` call was wrongly **DENIED** by
`sequence-send-email-requires-draft` — breaking the exact
draft-then-send workflow HITL approval exists to unblock. This is the
more severe of the two findings: it doesn't open a bypass, it silently
*breaks a legitimate, human-approved action's downstream effect*, which
is its own kind of correctness-as-security failure (a control that
doesn't do what its own design says it does).

**Fix:** `HitlApprover` gained an optional `session_store` field,
mirroring `PolicyEngine`'s own field exactly. After resolving to ALLOW
(and only then — a denied/timed-out call is never recorded, matching
`PolicyEngine`'s existing rule), `HitlApprover.resolve_approval` calls
`session_store.record_call(...)` itself. Verified end-to-end against the
real `PolicyEngine` + real `policies/` directory + real
`GuardedToolRegistry`, not just in isolated `HitlApprover` unit tests.
Tests: `test_INV_08_hitl_approver_records_an_approved_call_into_session_history`,
`test_INV_08_real_policy_engine_records_hitl_approved_call_into_session_history`.

### Finding 3 — `domain-send-email-partner-needs-approval` became a live RBAC-composition gap
[[0014-phase4-security-review-findings]] found and fixed two live
instances of the ADR 0012 bug class, and *also* found this rule already
had the same unrestricted shape — but at the time, Phase 5's HITL
evaluator didn't exist, so NEEDS_APPROVAL was unconditionally treated as
DENY at the interceptor level regardless of role, making the gap
theoretical. ADR 0014 explicitly deferred fixing it: "tracked, not
fixed, since fixing it now means guessing at not-yet-built Phase 5
semantics." Phase 5 landed the same day. Reproduced live: an `intern`
with **zero** `send_email` RBAC grant of any kind — not even a
`requires_approval` one — could, once it had a `compose_draft` in
session history (itself reachable via a legitimate, approved draft),
reach a **real human approval prompt** for emailing an external partner
domain, something RBAC categorically never intended to allow for that
role.

**Fix:** the same mechanism as every prior instance — populate `roles`
on `domain-send-email-partner-needs-approval` to match
`rbac-send-email-analysts`. Also widened the structural guard test
(`test_INV_05_no_unrestricted_allowlist_rule_can_bypass_an_rbac_rule`)
to stop exempting `requires_approval`-shaped rules — that exemption's
reasoning ("NEEDS_APPROVAL can't win outright pre-Phase-5") no longer
holds now that Phase 5 can genuinely turn NEEDS_APPROVAL into ALLOW.
Tests: `test_INV_05_policy_domain_send_email_partner_roles_compose_with_rbac`
(isolated), `test_INV_05_real_policy_engine_intern_cannot_reach_partner_approval_via_hitl`
(end-to-end through the real HITL stack, asserting the channel is never
even asked).

## Consequences
**Positive:**
- Closes a real human-approver-confusion race (Finding 1), a real
  correctness break in the flagship HITL-unblocks-sequence workflow
  (Finding 2), and a real RBAC-restriction bypass that had sat dormant
  as a documented theoretical risk until this exact day (Finding 3).
- The structural guard from ADR 0014 now covers the case it was
  deliberately narrowed to exclude, closing the loop that ADR predicted
  would need closing once Phase 5 shipped.
- No regressions: `pytest -v` stayed at 100% pass throughout (363
  passed, 1 skipped by the end), re-verified after each individual fix.

**Negative / honest scope limits:**
- Finding 1's fix serializes approvals *per `CliApprovalChannel`
  instance*. Two separate `CliApprovalChannel` instances that happen to
  both wrap the same real `sys.stdin`/`sys.stdout` (an unusual
  construction — normal usage shares one instance) would not be
  serialized against each other. Not fixed here — a global cross-instance
  lock for a construction pattern nothing in this project actually uses
  would be speculative engineering; tracked in `LIMITATIONS.md`.
- Serialization means a second concurrent approval request can wait an
  unbounded amount of time behind a first one before its own prompt is
  even shown or its timeout clock starts. For a single human operator
  answering one at a time (this project's actual usage shape), that's
  the correct behavior, not a cost — but it's worth naming precisely.
- Finding 3's fix, like every prior instance of this bug class, is
  opt-in per rule. The widened structural guard catches a *fifth*
  instance of the unrestricted-allowlist-vs-rbac shape, but a genuinely
  new bypass mechanism this review didn't anticipate would not be
  caught by it.

## Alternatives considered
- **For Finding 1: lock only around the prompt's stdout write, not the
  whole read-answer cycle.** Rejected: that would stop prompts from
  visually interleaving but would NOT stop the answer-misattribution
  race — two reader threads could still both be blocked on the same
  `readline()` concurrently, racing for whichever the OS delivers to.
  The lock has to cover the full round trip to actually fix the
  underlying race, not just its visible symptom.
- **For Finding 2: have `PolicyEngine` poll or subscribe to HITL
  outcomes somehow**, instead of giving `HitlApprover` its own
  `session_store` reference. Rejected: `HitlApprover` already resolves
  strictly after `PolicyEngine.evaluate` returns, with no shared call
  stack — there's no clean hook for `PolicyEngine` to observe a later,
  independent resolution without inventing a callback/event mechanism
  for what a single extra constructor parameter, mirroring a field
  `PolicyEngine` already has, solves directly.

## Related
- [[hitl-approval]]
- [[0015-hitl-resolution-mechanics]]
- [[0014-phase4-security-review-findings]]
- [[0012-rbac-composition-with-allowlist-rules]]
- [[session-state-and-audit-trail]]
