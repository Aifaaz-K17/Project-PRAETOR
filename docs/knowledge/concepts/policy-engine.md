---
tags: [architecture, policy, rule-engine]
status: implemented
---

# Policy Engine

`firewall/policy_schema.py` + `firewall/policy_engine.py` (Phase 3).
Pydantic v2 schema for six rule types (`parameter_bounds`, `path_scope`,
`domain_allowlist`, `sequence`, `rbac`, `rate`), loaded once at startup
via `load_policy_set()` into a frozen, SHA-256-hashed `LoadedPolicySet`
(INV-03). `evaluate_call(call, loaded, session_history)` is a pure
function (INV-13) implementing conflict resolution — DENY beats
NEEDS_APPROVAL beats ALLOW beats `default_action` (ships as DENY,
INV-08) — see [[0009-policy-conflict-resolution]]. `PolicyEngine` is the
thin adapter satisfying `firewall.interceptor.Evaluator`.

Regex-bearing rules (`parameter_bounds.pattern`) are compiled with the
third-party `regex` package (real per-call timeout, unlike stdlib `re`),
statically linted for obvious ReDoS shapes at load time, and bounded by a
runtime timeout that denies the call if exceeded (INV-09) — see
[[0010-policy-integrity-and-loading]].

23 rules ship across `policies/*.yaml` (path traversal, domain allowlists,
transfer bounds, RBAC scoping, one sequence gate, five rate limits), each
with at least one isolated test in `tests/test_policy_engine.py`. A
60+-entry `tests/fixtures/benign_calls.yaml` corpus exists for Phase 7's
false-positive-rate metric.

**Known Phase 3 scope limit** (see LIMITATIONS.md): `sequence` and `rate`
rules need real session call history, which `PolicyEngine.evaluate()`
currently always supplies as empty — Phase 4's `firewall/session.py` will
wire up the real session store. The rule logic itself is fully
implemented and tested directly against constructed history.

## Depends on
- [[interception-layer]] — Receives tool calls from the wrapper.
- [[canonicalization]] — Every path/host/email match calls `canonical_*` directly inside the rule matcher, never on raw arguments (INV-06).

## Used by
- [[action-firewall]] — Primary decision engine.

## Key decisions
- [[0003-policy-engine-deployment-mode]]
- [[0004-tool-scale-scope]]
- [[0005-hitl-approval-mechanism]]
- [[0009-policy-conflict-resolution]] — DENY > NEEDS_APPROVAL > ALLOW > default; why gate-shaped rules are `action: deny`.
- [[0010-policy-integrity-and-loading]] — Load-once hashing, frozen structures, ReDoS linting + runtime timeout.
