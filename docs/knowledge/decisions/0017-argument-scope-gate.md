---
tags: [decision, security, policy-engine, rbac]
status: accepted
date: 2026-09-01
---

# 0017 — The Argument-Scope Gate: RBAC's Blanket ALLOW Cannot Bypass path_scope/domain_allowlist

## Status
Accepted.

## Context
Found while building Phase 6's attack-scenario demos — the first code in
this project to run a real, malicious-shaped call through the *combined*
real `policies/` directory with an RBAC-eligible role, rather than an
isolated single rule (`_load_single_real_rule`) or a synthetic corpus
entry. Every existing test up to this point isolated one rule at a time;
none combined "a role with a genuine RBAC grant" with "an out-of-scope
argument value" against the full policy set.

Reproduced directly, three times, against the real policy set:

- `analyst` reading `read_file` with `path: "../requirements.txt"` —
  escaping `sandbox/` entirely — resolved **ALLOW** via
  `rbac-read-file-analysts`. `path-read-file-sandbox`'s containment
  check was never consulted.
- `analyst` sending `send_email` to `attacker@evil.com`, once the
  sequence gate was satisfied by a completely ordinary prior
  `compose_draft` — resolved **ALLOW** via `rbac-send-email-analysts`.
  `domain-send-email-corp`'s allowlist was never consulted.
- `intern` sending `search_web` to an arbitrary non-allowlisted host —
  resolved **ALLOW** via `rbac-search-web-everyone`. `domain-search-web-
  reference-sites`'s allowlist was never consulted.

**Root cause:** `_matches_rbac` votes ALLOW purely on `call.role in
rule.roles` — it never examines any argument. Conflict resolution (ADR
0009) treats every matching ALLOW vote as independently sufficient (by
design — this is what lets `domain-search-web-reference-sites` list
three alternative allowed domains that compose as OR). That design is
correct for genuinely independent grants, but wrong here: `rbac`'s
blanket, argument-blind ALLOW and `path_scope`/`domain_allowlist`'s
argument-scoped ALLOW were never meant to be alternatives — `rbac` is
supposed to answer "may this role touch this tool at all" and
`path_scope`/`domain_allowlist` "specifically where/to whom within that
tool" — an AND relationship the OR-based conflict-resolution model
never actually enforced.

[[0012-rbac-composition-with-allowlist-rules]],
[[0014-phase4-security-review-findings]], and
[[0016-phase5-security-review-findings]] fixed four real instances of a
*related but different* bug: an unrestricted `path_scope`/
`domain_allowlist` rule's own ALLOW vote reaching a role RBAC never
granted at all. Those fixes (an opt-in `roles` field) remain correct and
necessary, but they never addressed — because the two bug classes look
almost identical but aren't — that `rbac`'s vote is *also* independently
sufficient, for roles it *does* grant, regardless of argument. Adding
`roles` to every `path_scope`/`domain_allowlist` rule would not have
fixed this: the bypass runs entirely through `rbac`'s vote, which
`path_scope`/`domain_allowlist`'s own `roles` field has no power over.

## Decision
A new structural gate, `_check_argument_scope`, run once upfront in
`evaluate_call` — the same timing as `_check_unknown_parameters`, before
any rule votes at all. For every `(tool, parameter)` pair that has at
least one `path_scope`/`domain_allowlist` rule declared anywhere in the
loaded policy set: if the call supplies a value for that parameter, the
value must be in scope for **at least one** such rule, checked
role-blind (`_path_value_in_scope`/`_domain_value_in_scope` — new
helpers, factored out of `_matches_path_scope`/`_matches_domain_allowlist`,
which keep applying the `roles` gate for their own per-rule vote
unchanged). If no declared rule finds the value in scope, the call is
denied outright (`rule_id="argument-scope-gate"`), before `rbac` or any
other rule ever votes.

**Not a per-rule fix, deliberately.** The natural-looking alternative —
convert `path_scope`/`domain_allowlist` to `action: deny`, matching when
*out* of scope, the same pattern `parameter_bounds`/`sequence`/`rate`
already use correctly — was considered and rejected (see "Alternatives
considered"): it breaks the OR-composition across multiple rules for the
same `(tool, parameter)`, which this policy set genuinely relies on
(`domain-send-email-corp`'s plain ALLOW and `domain-send-email-partner-
needs-approval`'s NEEDS_APPROVAL are two independent tiers over the same
`to` parameter, each checking only its own narrow domain list). A
structural gate checked *before* voting, rather than a change to how
individual rules vote, preserves that composition while still closing
the bypass.

**Role-blind by design.** The gate answers "is this argument even
possibly legitimate for this tool at all" — not "who may use it." Role
eligibility is still fully enforced, unchanged, by `rbac`'s vote and by
each `path_scope`/`domain_allowlist` rule's own `roles` field in the
normal per-rule vote that runs afterward. This split — a role-blind
structural gate plus unchanged role-aware per-rule voting — is what let
the fix land with **zero test regressions**: every existing isolated
single-rule test only ever loaded one scope rule at a time (so the gate
degenerates to that rule's own value check, same outcome, same
`.outcome` assertions the tests already made — most didn't assert on
`rule_id`), and legitimate calls still resolve through exactly the same
rule as before (confirmed directly: `read_file` still resolves via
`path-read-file-sandbox`, `send_email` to the corp domain still via
`domain-send-email-corp`, not via the gate).

## Consequences
**Positive:**
- Closes a severe, previously-live bypass affecting the first two rows
  of the threat model (T-1 path traversal, T-3 exfiltration) for *any*
  role with ordinary RBAC access to the affected tools — which, for
  `read_file`/`send_email`/`search_web`, is most roles.
- Zero regressions: 363 pre-existing tests passed unchanged; the fix is
  additive (a new pre-check), not a rewrite of existing matching logic.
- Preserves the two-tier domain-allowlist composition
  (`domain-send-email-corp` + `domain-send-email-partner-needs-approval`)
  exactly as authored — verified directly, not assumed.
- Surfaces a real methodological gap for future phases: every prior test
  suite isolated one rule at a time; this bug was only found by testing
  a role-eligible call against the *combined* policy set, the kind of
  integration testing Phase 6's demo work is specifically for. Worth
  naming explicitly rather than treating as luck.

**Negative / honest scope limits:**
- The gate only covers `path_scope`/`domain_allowlist` vs. any other
  ALLOW-type rule (chiefly `rbac`). It does not generalize to a
  hypothetical future rule type with the same "blanket, argument-blind
  ALLOW" shape `rbac` has — a new rule type would need its own
  consideration of this exact failure mode.
- `_check_argument_scope`'s reason string doesn't say *which* declared
  rule(s) it checked against, only that none matched — a minor
  debuggability gap versus per-rule DENY reasons elsewhere in this
  engine; not fixed here since the existing `rule_id="argument-scope-gate"`
  plus the reason's `(tool, parameter)` naming is enough to diagnose in
  practice.
- This is the fifth real bug in this general area
  (ADR 0012/0014/0016 fixed four instances of the *other* direction);
  the honest pattern here is that RBAC-composition semantics have been a
  persistently under-tested corner of this engine, not that this is
  necessarily the last one — see `LIMITATIONS.md`.

## Alternatives considered
- **Convert `path_scope`/`domain_allowlist` to `action: deny`** (matching
  when out of scope). Rejected: breaks OR-composition across multiple
  rules for the same `(tool, parameter)` — verified concretely by
  reasoning through the corp/partner domain split: two independently
  deny-shaped rules, each checking only its own narrow list, would each
  incorrectly flag the OTHER'S allowed domain as "not in MY list" and
  vote DENY, since DENY-shaped rules don't naturally aggregate into a
  union the way multiple ALLOW votes do.
- **Change conflict resolution globally** so ALLOW votes require
  unanimity across all matching ALLOW-type rules, not just one. Rejected
  for the same reason [[0012-rbac-composition-with-allowlist-rules]]
  rejected it: this is a global semantics change with a much larger
  blast radius than the actual bug, and would break rules that
  intentionally rely on OR-composition today (e.g. three independently
  allowed `search_web` reference domains).
- **Remove `rbac` rules' blanket-vote shape entirely**, requiring every
  `rbac` rule to also somehow reference the arguments a co-located
  `path_scope`/`domain_allowlist` rule cares about. Rejected: `rbac` is
  deliberately argument-blind by design (it answers a role question, not
  an argument question) — coupling it to argument shape would blur two
  cleanly separated concerns for no benefit the structural gate doesn't
  already provide more simply.

## Related
- [[policy-engine]]
- [[0009-policy-conflict-resolution]]
- [[0012-rbac-composition-with-allowlist-rules]]
- [[0014-phase4-security-review-findings]]
- [[0016-phase5-security-review-findings]]
