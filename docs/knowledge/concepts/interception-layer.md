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

## Depends on
- [[action-firewall]] — Conceptual blueprint.

## Used by
- [[canonicalization]] — Normalizes `CallRecord.raw_args` before the policy engine sees them.
- [[policy-engine]] — Will receive `CallRecord`s via the `Evaluator` seam (Phase 3).

## Key decisions
- [[0006-agent-framework-choice]]
- [[0007-interceptor-enforcement-point]] — Wrap-at-registration, input normalization, fail-closed/TOCTOU-safe chokepoint design.
