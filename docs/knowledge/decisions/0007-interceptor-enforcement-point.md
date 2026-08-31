---
tags: [decision, interception, mediation]
status: accepted
date: 2026-08-31
---

# 0007 — Interceptor Enforcement Point and Call-Normalization Contract

## Status
Accepted.

> Numbering note: the master build prompt suggested ADR 0007 for Phase 2's
> canonicalization decision. This Phase 1 decision claims 0007 instead,
> since it lands first chronologically and the vault numbers ADRs
> sequentially — Phase 2's canonicalization ADR becomes 0008, Phase 3's
> become 0009/0010, Phase 4's becomes 0011.

## Context
INV-02 (total mediation) requires that no reachable execution path to a
guarded tool bypasses the interceptor — sync, async, `.invoke()`,
`.ainvoke()`, `.run()`, batched, or retried. LangChain's `BaseTool` exposes
several of these as independent methods (confirmed against the installed
langchain-core 1.5.4: `invoke`, `ainvoke`, `run`, `arun`, `batch`, `abatch`),
each with a slightly different accepted input shape (a plain dict, a bare
string for a single-argument tool, or a `ToolCall` dict carrying `name`/
`args`/`id`). Phase 3's policy engine doesn't exist yet, so Phase 1 also
needs a stable seam to hand calls to *something* that decides ALLOW/DENY
without knowing what that something will eventually be.

## Decision
1. **Wrap at registration, not by decorating individual methods.**
   `GuardedToolRegistry.register(tool)` returns a `GuardedTool` object whose
   `invoke`/`ainvoke`/`run`/`arun`/`batch`/`abatch` are all thin adapters
   that normalize their input and call one shared chokepoint,
   `_evaluate_call`, before ever touching the original tool. `batch`/
   `abatch` are implemented as explicit loops over `invoke`/`ainvoke` rather
   than inherited from `Runnable`, so mediation doesn't depend on trusting
   an inherited default that could silently change across a langchain-core
   upgrade. `@firewall_guard` is a separate, smaller decorator offering the
   same mediation for a single plain function — developer sugar, not the
   enforcement point.
2. **Normalize every input shape into a plain args dict before evaluation.**
   `_normalize_tool_input` turns a dict, a bare string (for single-argument
   tools), or a `ToolCall` dict into one consistent `dict[str, Any]`, so
   `CallRecord.raw_args` always has the same shape regardless of how the
   agent/LLM chose to call the tool. Phase 3's policy rules only need to
   handle one shape.
3. **Evaluator is a `Protocol`, not a base class.** `Evaluator.evaluate(call:
   CallRecord) -> Decision` is structural typing — Phase 3's real policy
   engine, and every test double in `tests/_evaluators.py`, only need to
   implement that one method. Nothing in the interceptor imports or depends
   on Phase 3 code, so Phase 1 could be fully tested before Phase 3 exists.
4. **Fail-closed and TOCTOU-safe by construction, in one function.**
   `_evaluate_call` is the single place that resolves the principal, builds
   the `CallRecord`, and calls `evaluator.evaluate()` — all under one
   `try/except Exception` (INV-01), and using two independent
   `copy.deepcopy()` calls taken *before* evaluation so a policy hook that
   mutates the args it's handed cannot affect what actually executes
   (INV-07). Putting this in one function (used by both sync and async
   paths) means there's exactly one place that can get fail-closed/TOCTOU
   wrong, not one per execution path.

## Consequences
**Positive:**
- Every execution path is provably covered by one test file
  (`test_INV_02_bypass_audit`), because they all fall through to the same
  three-line chokepoint.
- Phase 3 can start writing the real policy engine against `Evaluator`
  without touching `firewall/interceptor.py` at all.
- The normalization step means Phase 2/3 code never needs to special-case
  "what if the agent called with a bare string."

**Negative / tradeoffs:**
- `GuardedTool` duplicates `BaseTool`'s method surface rather than
  subclassing it — chosen deliberately (subclassing a Pydantic-based
  `BaseTool` to override every execution method reliably is fragile across
  langchain-core versions), but it means a new LangChain execution method
  added upstream in the future would need a matching addition here, not
  something inherited automatically. Documented as a maintenance note for
  future phases.
- **Residual bypass (already tracked as R-1 in `docs/THREAT_MODEL.md`):**
  code holding a reference to the *original* tool/function object — the one
  passed into `.register()` or `firewall_guard(...)`, before wrapping —
  executes completely unmediated. Both
  `test_INV_02_direct_reference_bypasses_registry` and
  `test_firewall_guard_decorator_direct_reference_bypass` demonstrate this
  honestly rather than claiming it doesn't exist. Production mitigation
  (documented, not built): ship tools behind a module boundary that only
  ever exports the guarded object.

## Alternatives considered
- **Subclass `BaseTool` per guarded tool** (e.g. dynamically generate a
  subclass overriding `_run`/`_arun`). Rejected: `BaseTool` is a Pydantic
  model with its own metaclass machinery; dynamic subclassing to intercept
  every method reliably is more fragile than explicit composition, for no
  real benefit at this scale (~5 tools per ADR 0004).
- **Monkeypatch the tool object's methods in place** rather than returning
  a new wrapper. Rejected: mutates a shared object other code might hold a
  reference to, which is a worse version of the exact residual bypass this
  design already has to document — better to have one clearly-named
  residual than two.

## Related
- [[interception-layer]]
- [[0006-agent-framework-choice]]
