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
`min`/`max` numeric checks coerce a numeric-looking `str` (the shape a
real LLM tool-call can emit) via `_coerce_numeric` before comparing, and
fail closed on anything else unparseable — a real bypass (`amount:
"999999"` sailing past a `max: 1000` rule) found and fixed in
[[0014-phase4-security-review-findings]].

Before any rule votes, `_check_unknown_parameters` enforces INV-08's
"unknown parameter → DENY": a `parameter_schema` rule declares a tool's
complete accepted parameter set, and any call carrying an undeclared
argument is denied outright, opt-in per tool — see
[[0011-unknown-parameter-enforcement]].

`path_scope` and `domain_allowlist` rules carry an optional `roles` field
(empty = unrestricted, the default). This exists because these rules are
independent ALLOW votes under conflict resolution — an unrestricted one
does not narrow a co-located `rbac` rule's role restriction on the same
tool, it silently outvotes it. This was a real bug (an intern could read
any in-scope file / email the corp domain despite no RBAC grant), found
via testing in Phase 4 and fixed by setting `roles` on the two affected
shipped rules to match their sibling `rbac` rule — see
[[0012-rbac-composition-with-allowlist-rules]] for the full incident and
why the fix is opt-in rather than automatic.

29 rules ship across `policies/*.yaml` (path traversal, domain allowlists,
transfer bounds, RBAC scoping, one sequence gate, five rate limits, five
parameter schemas), each with at least one isolated test in
`tests/test_policy_engine.py`. A 70-entry `tests/fixtures/benign_calls.yaml`
corpus exists for Phase 7's false-positive-rate metric.

**Phase 3 scope limit, closed in Phase 4:** `sequence` and `rate` rules
need real session call history; `PolicyEngine.evaluate()` used to always
supply it as empty. [[session-state-and-audit-trail]]'s `SessionStore`
now backs it — `PolicyEngine` records each ALLOWed call and reads real
prior-call history back into `evaluate_call` on every subsequent call in
the same session. The same `PolicyEngine.evaluate()` also optionally
shadow-logs every decision via `AuditLogger` and, if
`enable_anomaly_detection=True`, runs
[[anomaly-detection]]'s four detectors after `evaluate_call` and folds
any findings into the returned `Decision` — a second, separate
deterministic layer, not a change to conflict resolution itself.

## Depends on
- [[interception-layer]] — Receives tool calls from the wrapper.
- [[canonicalization]] — Every path/host/email/text match calls `canonical_*` directly inside the rule matcher, never on raw arguments (INV-06).
- [[session-state-and-audit-trail]] — Real session history for `sequence`/`rate` rules; shadow logging of every decision.

## Used by
- [[action-firewall]] — Primary decision engine.
- [[anomaly-detection]] — Runs after and folds into `evaluate_call`'s `Decision`.

## Key decisions
- [[0003-policy-engine-deployment-mode]]
- [[0004-tool-scale-scope]]
- [[0005-hitl-approval-mechanism]]
- [[0009-policy-conflict-resolution]] — DENY > NEEDS_APPROVAL > ALLOW > default; why gate-shaped rules are `action: deny`.
- [[0010-policy-integrity-and-loading]] — Load-once hashing, frozen structures, ReDoS linting + runtime timeout.
- [[0011-unknown-parameter-enforcement]] — `parameter_schema` rule type; opt-in per tool, and why a blanket check was rejected.
- [[0012-rbac-composition-with-allowlist-rules]] — RBAC-bypass bug via unconditional path_scope/domain_allowlist ALLOW votes; `roles` field fix.
- [[0013-rule-based-anomaly-detection]] — Second deterministic layer catching multi-call context, not single-call rule violations.
- [[0014-phase4-security-review-findings]] — numeric-string bypass fix for `min`/`max` bounds; two more RBAC-composition-bypass instances found and fixed; a structural guard test against a fourth.
