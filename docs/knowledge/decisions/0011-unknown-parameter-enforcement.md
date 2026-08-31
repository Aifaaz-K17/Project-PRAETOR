---
tags: [decision, policy-engine, security]
status: accepted
date: 2026-08-31
---

# 0011 — Unknown-Parameter Enforcement (INV-08)

## Status
Accepted.

> Numbering note: continues the sequential renumbering from
> [[0007-interceptor-enforcement-point]] through
> [[0010-policy-integrity-and-loading]]. Phase 4's first ADR becomes 0012.

## Context
CLAUDE.md's INV-08 states plainly: "Unknown parameter → DENY... Never an
implicit allow." A 7-angle adversarial code review (2026-08-31) found this
wasn't actually true of the implementation: `evaluate_call` only ever
evaluates rules that name a specific parameter (`path_scope.parameter`,
`domain_allowlist.parameter`, `parameter_bounds.parameter`) — any argument
a call carries that no rule happens to inspect passes through completely
unexamined. Concretely: `transfer_funds` is governed by rules on `amount`
and `note`; a call carrying an unanticipated third argument (e.g. a
`destination_account` field a real transfer tool would need) would sail
through untouched as long as `amount`/`note` stayed within bounds.

## Decision
A new rule type, `parameter_schema`, declares the complete set of
parameter names a tool's calls may legitimately carry:

```yaml
- type: parameter_schema
  id: schema-transfer-funds
  tool: transfer_funds
  action: allow  # unused by this rule type, present for schema uniformity
  known_parameters: ["amount", "note"]
```

`firewall.policy_engine._check_unknown_parameters` runs once, upfront, in
`evaluate_call` — before the normal per-rule ALLOW/DENY/NEEDS_APPROVAL
voting loop, not as one more vote in it. For each call: gather every
`parameter_schema` rule matching the call's tool (`tool == call.tool_name`
or `tool == "*"`), union their `known_parameters`, and deny the whole call
outright if any argument key isn't in that set.

**Enforcement is opt-in per tool, not a blanket global requirement.** A
tool with zero `parameter_schema` rules in the loaded policy set is not
subject to this check at all. This is a deliberate scoping decision, not
an oversight — see "Alternatives considered" for why a true blanket check
was rejected. All five tools this project ships policies for
(`policies/parameter_schema.yaml`) declare one, so in practice every real
demo tool is covered.

## Consequences
**Positive:**
- Closes the literal gap in INV-08: an attacker steering the agent to
  pass an extra, unconstrained argument can no longer bypass every other
  rule just because no one wrote a rule naming that specific parameter.
- Composes cleanly with existing rules: declaring a schema doesn't
  replace or interact with `parameter_bounds`/`path_scope`/etc. — a
  `known` parameter can still be independently constrained or denied by
  any other rule type. The schema check only answers "is this parameter
  supposed to exist at all," never "is its value acceptable."
- Self-documenting: `policies/parameter_schema.yaml` is a complete,
  explicit list of every tool's accepted arguments in one place, useful
  for a viva walkthrough and for a future Phase 6 demo-tool author to
  check they've covered every field.

**Negative / tradeoffs:**
- Opt-in-per-tool means the invariant is only as strong as policy
  authors' discipline about declaring a schema for every new tool. A
  tool added later without a `parameter_schema` rule silently reverts to
  the old (weaker) behavior rather than failing loudly. Mitigated
  partially by `test_all_shipped_rules_have_at_least_one_test`'s
  structural guard (catches a schema rule added with no test, not a
  schema rule that's missing entirely) — a stronger guard (e.g. a test
  asserting every tool named anywhere in `policies/*.yaml` has a
  `parameter_schema` rule) is a reasonable follow-up, not built here.
- `action`/`requires_approval` exist on `parameter_schema` rules purely
  for schema uniformity with the other five rule types and are ignored by
  the engine — a policy author could set `requires_approval: true` on one
  and it would silently do nothing. Not validated against (would need
  either a rule-type-specific validator or a separate base class without
  `action` — judged not worth the added schema complexity for one
  cosmetic footgun, but noted honestly here rather than silently).

## Alternatives considered
- **Derive "known parameters" from existing constraint rules** (union of
  every `path_scope`/`domain_allowlist`/`parameter_bounds` rule's
  `parameter` field for a tool, no new rule type needed). Rejected after
  checking it against the real benign-calls corpus: `send_email`'s `body`
  and `compose_draft`'s `subject`/`body` have no constraint rule (nothing
  needs to bound them), so they'd be flagged "unknown" and the corpus's
  own legitimate calls would start failing. Conflates two different
  questions — "does this parameter need a value constraint" and "is this
  parameter allowed to exist" — that need to be answerable independently.
- **A true blanket check** (every tool, no opt-out, empty schema by
  default). Rejected: breaks every existing test that builds a small
  synthetic rule set to isolate one piece of conflict-resolution logic
  (e.g. `test_deny_wins_over_allow`, which uses a two-rule set on a
  placeholder tool named `"x"` specifically to test resolution order in
  isolation, not this feature) — those tests would all start failing on
  "unknown parameter" before ever reaching the logic they exist to test.
  Opt-in-per-tool gets the real security property for every tool that
  matters (the five shipped demo tools) without demanding every future
  unit test declare a schema it isn't testing.

## Related
- [[policy-engine]]
- [[0009-policy-conflict-resolution]]
- [[0010-policy-integrity-and-loading]]
