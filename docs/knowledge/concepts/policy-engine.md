---
tags: [architecture, policy, rule-engine]
status: implemented
---

# Policy Engine

`firewall/policy_schema.py` + `firewall/policy_engine.py` (Phase 3).
Pydantic v2 schema for seven rule types (`parameter_bounds`, `path_scope`,
`domain_allowlist`, `sequence`, `rbac`, `rate`, `parameter_schema`), loaded
once at startup via `load_policy_set()` into a frozen, SHA-256-hashed
`LoadedPolicySet` (INV-03). `evaluate_call(call, loaded, session_history)`
is a pure function (INV-13) implementing conflict resolution — DENY beats
NEEDS_APPROVAL beats ALLOW beats `default_action` (ships as DENY,
INV-08) — see [[0009-policy-conflict-resolution]]. `PolicyEngine` is the
thin adapter satisfying `firewall.interceptor.Evaluator`.

Regex-bearing rules (`parameter_bounds.pattern`) are compiled with the
third-party `regex` package (real per-call timeout, unlike stdlib `re`),
statically linted for obvious ReDoS shapes at load time, and bounded by a
runtime timeout that denies the call if exceeded (INV-09) — see
[[0010-policy-integrity-and-loading]]. `parameter_bounds` text checks
(`max_length`/`pattern`) run against `canonical_text()`-normalized values,
never raw text (INV-06) — a real bug found by code review and fixed.

Before any rule votes, `_check_unknown_parameters` enforces INV-08's
"unknown parameter → DENY": a `parameter_schema` rule declares a tool's
complete accepted parameter set, and any call carrying an undeclared
argument is denied outright, opt-in per tool — see
[[0011-unknown-parameter-enforcement]].

29 rules ship across `policies/*.yaml` (path traversal, domain allowlists,
transfer bounds, RBAC scoping, one sequence gate, five rate limits, five
parameter schemas), each with at least one isolated test in
`tests/test_policy_engine.py`. A 70-entry `tests/fixtures/benign_calls.yaml`
corpus exists for Phase 7's false-positive-rate metric.

**Known Phase 3 scope limit** (see LIMITATIONS.md): `sequence` and `rate`
rules need real session call history, which `PolicyEngine.evaluate()`
currently always supplies as empty — Phase 4's `firewall/session.py` will
wire up the real session store. The rule logic itself is fully
implemented and tested directly against constructed history.

## Depends on
- [[interception-layer]] — Receives tool calls from the wrapper.
- [[canonicalization]] — Every path/host/email/text match calls `canonical_*` directly inside the rule matcher, never on raw arguments (INV-06).

## Used by
- [[action-firewall]] — Primary decision engine.

## Key decisions
- [[0003-policy-engine-deployment-mode]]
- [[0004-tool-scale-scope]]
- [[0005-hitl-approval-mechanism]]
- [[0009-policy-conflict-resolution]] — DENY > NEEDS_APPROVAL > ALLOW > default; why gate-shaped rules are `action: deny`.
- [[0010-policy-integrity-and-loading]] — Load-once hashing, frozen structures, ReDoS linting + runtime timeout.
- [[0011-unknown-parameter-enforcement]] — `parameter_schema` rule type; opt-in per tool, and why a blanket check was rejected.
