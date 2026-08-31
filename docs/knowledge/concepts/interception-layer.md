---
tags: [architecture, interception, langchain]
status: implemented
---

# Interception Layer

`firewall/interceptor.py` + `firewall/context.py` (Phase 1, `4d5c5bf`+).
`GuardedToolRegistry` is the real enforcement point (INV-02): it wraps a
LangChain tool at registration time, and every execution path
(`invoke`/`ainvoke`/`run`/`arun`/`batch`/`abatch`) funnels through one
chokepoint, `_evaluate_call`, before the tool runs. `@firewall_guard` is
developer sugar for guarding a single plain function the same way.
`firewall/context.py` binds the calling principal (session ID, identity,
role) via `contextvars`, never from tool arguments (INV-05).

Captures a `CallRecord` per call (call ID, tool name, raw + canonical args,
principal, timestamps, sequence index) and hands it to an `Evaluator`
(`Protocol`) — a seam Phase 3's policy engine will implement. Fails closed
on any exception (INV-01) and evaluates against a pre-evaluation deep copy
so a policy hook can't affect what actually executes (INV-07).

**Known residual (documented, not hidden):** a direct reference to the
*original*, undecorated tool/function bypasses mediation entirely — see
[[0007-interceptor-enforcement-point]] and `docs/THREAT_MODEL.md` R-1.

**Phase 5 addition:** `_evaluate_call` optionally consults a
`HitlResolver` — a `Protocol` (same structural-typing pattern as
`Evaluator`) satisfied by [[hitl-approval]]'s `HitlApprover` — whenever
`evaluator.evaluate()` returns `NEEDS_APPROVAL`. This runs inside the
same fail-closed try/except and at the same single chokepoint, so total
mediation (INV-02) covers the approval step too: no execution path can
reach a NEEDS_APPROVAL-gated tool's real execution without going through
approval resolution when one is configured. `interceptor.py` never
imports `firewall.hitl` (the `Protocol` is defined here, not there) —
see [[0015-hitl-resolution-mechanics]] for why.

## Depends on
- [[action-firewall]] — Conceptual blueprint.

## Used by
- [[canonicalization]] — Normalizes `CallRecord.raw_args` before the policy engine sees them.
- [[policy-engine]] — Receives `CallRecord`s via the `Evaluator` seam.
- [[hitl-approval]] — Implements the `HitlResolver` seam defined here, structurally, without this module ever importing it.

## Key decisions
- [[0006-agent-framework-choice]]
- [[0007-interceptor-enforcement-point]] — Wrap-at-registration, input normalization, fail-closed/TOCTOU-safe chokepoint design.
- [[0015-hitl-resolution-mechanics]] — Why HitlResolver is a Protocol defined here (avoids a circular import with firewall.hitl) and why HITL resolution runs inside the same chokepoint/try-except as policy evaluation.
