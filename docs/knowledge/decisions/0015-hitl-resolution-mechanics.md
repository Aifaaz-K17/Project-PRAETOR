---
tags: [decision, hitl, interception-layer, security]
status: accepted
date: 2026-09-01
---

# 0015 — HITL Resolution Mechanics: Structural Seam, Cross-Platform Timeout, Second Audit Row

## Status
Accepted.

## Context
[[0005-hitl-approval-mechanism]] decided *what* Phase 5 builds — a
blocking terminal `y/n` prompt. It was written in early planning, before
`firewall/interceptor.py`'s total-mediation chokepoint, `firewall/
policy_engine.py`'s conflict resolution, or `firewall/logger.py`'s
hash-chained audit log existed, so it couldn't specify *how* HITL
resolution fits into that architecture. Three concrete problems needed
real answers:

1. **Where does resolution happen?** `evaluate_call` (Phase 3) can
   return `NEEDS_APPROVAL`, but nothing before Phase 5 turned that into
   an actual ALLOW or DENY — `Decision.allowed` just treats it as
   not-allowed. Resolving it needs to happen somewhere every execution
   path (`invoke`/`ainvoke`/`run`/`arun`/`batch`/`abatch`,
   `firewall_guard`-wrapped functions) goes through, or INV-02's total
   mediation wouldn't cover the approval step itself.
2. **How do you time out a blocking read, portably?** `input()`/
   `readline()` has no built-in timeout. `select.select()` on `sys.stdin`
   — the usual Unix answer — doesn't reliably work for Windows console
   input, and this project's dev environment is Windows.
3. **How does the eventual human answer get into the tamper-evident
   audit log** (`firewall/logger.py`, INV-10) **without breaking the hash
   chain?** The chain's whole point is that an existing row can never be
   edited after the fact — editing one breaks every row's hash after it.
   A NEEDS_APPROVAL decision may already have been logged (e.g. by
   `PolicyEngine.evaluate()`'s shadow logging) before a human ever
   answers.

## Decision

### 1. `HitlResolver` as a `Protocol` defined in `interceptor.py`, not imported from `hitl.py`
Mirrors `Evaluator`'s existing pattern exactly. `firewall/hitl.py` needs
`CallRecord`/`Decision`/`Outcome` from `firewall/interceptor.py`; if
`interceptor.py` also imported `HitlApprover` from `firewall/hitl.py`,
that would be a circular import. Defining the seam as a structural
`Protocol` (`resolve_approval(call, decision) -> Decision`) inside
`interceptor.py` lets `_evaluate_call` type-check against it without
ever importing `firewall.hitl` — `firewall/hitl.py`'s `HitlApprover`
satisfies the protocol just by having the right method, the same way
`PolicyEngine` satisfies `Evaluator` today.

`_evaluate_call` calls `hitl_resolver.resolve_approval(record, decision)`
**inside its existing single try/except**, only when
`decision.outcome == NEEDS_APPROVAL`, and only when a resolver was
actually wired in (`hitl_resolver: HitlResolver | None = None`,
threaded through `GuardedTool`/`GuardedToolRegistry`/`firewall_guard`
the same way `evaluator` already is). This means: every execution path
that reaches `_evaluate_call` at all — which INV-02's own bypass-audit
test already proves is every path a `GuardedTool` exposes — also reaches
HITL resolution when one is configured, and a crashing/hanging resolver
fails closed to DENY (INV-01) exactly like a crashing `Evaluator`
already does, for the same reason: same function, same try/except.
Without a resolver configured (the default, and every Phase 1-4 caller's
existing behavior), NEEDS_APPROVAL is left exactly as Phase 3 always
left it.

### 2. A reader thread plus a bounded `queue.Queue` for the timeout
`CliApprovalChannel.request_approval` starts a daemon thread that calls
`input_stream.readline()` and puts the result on a `queue.Queue`; the
main thread waits with `queue.get(timeout=timeout_seconds)`. On a
`queue.Empty`, the result is `TIMED_OUT` — INV-12's "timeout -> DENY" —
without ever blocking the caller past `timeout_seconds`.

The reader thread itself is **not** cancelled on timeout — Python has no
safe, portable way to interrupt a thread blocked inside a C-level
`readline()` call. It stays blocked on the input stream until either a
line eventually arrives (discarded — nothing reads the queue again after
`get()` returns once) or the process exits (it's a daemon thread, so it
never blocks process shutdown). This is a real, accepted tradeoff for a
CLI approval tool, not hidden — see `LIMITATIONS.md`.

### 3. The HITL outcome is a SECOND audit row, never an edit to the first
`HitlApprover._log_resolution` calls `AuditLogger.log_call` again with a
`CallRecord` that's a `dataclasses.replace()` of the original, with
`call_id` suffixed `:hitl` (e.g. `abc-123:hitl`) and a fresh
`timestamp_utc`. `AuditLogRow.call_id` is `unique=True`, so this couldn't
reuse the original `call_id` even if editing the row were otherwise
possible — which it structurally isn't, since INV-10's hash chain means
changing an already-written row's content breaks its own `entry_hash`
and every row's `prev_hash` after it. Two rows for one logical call is
the correct shape here, not a workaround: the first row (written by
whatever logged the policy decision) documents "what policy said"; the
second documents "what actually happened once a human answered" —
`scripts/query_logs.py --tool <name>` shows both, in order, and
`verify_chain.py` still verifies the whole chain including both.

## Consequences
**Positive:**
- Total mediation (INV-02) extends to the approval step: no execution
  path can reach a NEEDS_APPROVAL-gated tool's real execution without
  going through `hitl_resolver.resolve_approval` when one is configured.
- Fail-closed (INV-01) is uniform: a crashing evaluator and a
  crashing/misbehaving HITL channel produce the same shape of DENY
  (`FIREWALL_ERROR`/`HITL_ERROR`), through the same code path.
- The audit trail stays honest under INV-10's actual constraints (never
  edit a written row) instead of fighting them.
- Zero new circular-import risk, zero new dependency — the `Protocol`
  pattern this decision reuses was already proven correct by
  `Evaluator`/`PolicyEngine`.

**Negative / honest scope limits:**
- The abandoned reader thread per timed-out approval is a real, if
  low-cost, resource characteristic: a long-running process (not this
  project's demo-script usage pattern) that racks up many timed-out
  approvals accumulates blocked daemon threads until process exit. Not a
  memory leak in the traditional sense (each thread's stack is bounded
  and daemon threads don't block shutdown), but worth naming precisely
  rather than saying "no cost."
- `HitlApprover`'s single-use `_consumed_call_ids` set grows for the
  life of the `HitlApprover` instance — the same accepted, documented
  tradeoff `firewall/session.py`'s `SessionStore` already carries
  (unbounded without periodic eviction), scoped here to only
  NEEDS_APPROVAL calls specifically, which is a much smaller set than
  every call.
- The two-row audit shape means a naive `SELECT ... WHERE call_id = X`
  query only finds the *first* row for a HITL-gated call — a caller
  needs to know to also check for `X:hitl`. `scripts/query_logs.py`
  isn't yet updated with a "show both rows for this call" convenience
  filter; tracked in `LIMITATIONS.md`, not built here (out of Phase 5's
  minimum scope, a reasonable Phase 6/7 polish item).

## Alternatives considered
- **Resolve NEEDS_APPROVAL inside `PolicyEngine.evaluate()` itself**,
  since that's already where session recording, audit shadow-logging,
  and (Phase 4) anomaly detection happen. Rejected: `PolicyEngine` is
  one `Evaluator` implementation, not the only possible one (the
  `Evaluator` protocol exists precisely so other implementations are
  possible) — putting HITL resolution there would mean a custom
  `Evaluator` that returns `NEEDS_APPROVAL` without going through
  `PolicyEngine` gets no approval mechanism at all, silently falling
  back to "treated as DENY." Putting it in the interceptor's own
  chokepoint makes it apply uniformly to any `Evaluator`.
- **`asyncio`-based timeout** (`asyncio.wait_for` around an
  `asyncio`-native stdin reader) instead of a thread + queue. Rejected:
  `_evaluate_call` and `CliApprovalChannel.request_approval` need to work
  from both `_mediate_sync` (no event loop) and `_mediate_async` (inside
  one) — a thread-based blocking wait works identically from either
  context; an asyncio-native implementation would need two different
  code paths, one of which (the sync one) still needs some non-asyncio
  timeout mechanism anyway.
- **Overwrite/update the original NEEDS_APPROVAL row in place** once a
  human answers, instead of a second row. Rejected outright, not just as
  a style preference — INV-10's hash chain makes it structurally unsafe:
  `verify_chain.py` would report the row as tampered, because from the
  chain's perspective an edited row is indistinguishable from an
  attacker's edit. The two-row design is the only shape compatible with
  the append-only hash chain this project already committed to in
  Phase 4.

## Related
- [[0005-hitl-approval-mechanism]]
- [[interception-layer]]
- [[session-state-and-audit-trail]]
- [[0009-policy-conflict-resolution]]
