---
tags: [decision, policy-engine, security]
status: accepted
date: 2026-08-31
---

# 0009 — Policy Conflict Resolution

## Status
Accepted.

> Numbering note: the master build prompt suggested 0008 for this
> decision. It's 0009 because Phase 2's canonicalization ADR claimed 0008
> first — see [[0008-canonicalization-before-matching]]'s numbering note.
> Phase 3's second ADR (policy integrity) is 0010; Phase 4's becomes 0011.

## Context
A call can match more than one rule at once — e.g. an RBAC rule granting
`finance` access to `transfer_funds`, and a `parameter_bounds` rule
denying transfers over 1000, both apply to the same call if the amount is
large. Something has to decide which wins, deterministically (INV-13), and
that rule has to be documented precisely — CLAUDE.md flags "which rule
wins?" as a guaranteed viva question.

## Decision
Among every rule whose `tool` matches the call:

1. **Any `DENY` wins**, unconditionally.
2. Otherwise, **any `NEEDS_APPROVAL`** (an `action: allow` rule with
   `requires_approval: true`) wins.
3. Otherwise, **any plain `ALLOW`** wins.
4. **No rule matched at all** → the policy set's `default_action`, which
   every file in this repo sets to `deny` (INV-08).

Implemented in `firewall.policy_engine.evaluate_call` as three independent
"first match wins" slots (`matched_deny`, `matched_needs_approval`,
`matched_allow`) filled while iterating the rule list once, then resolved
in that fixed DENY > NEEDS_APPROVAL > ALLOW order after the loop — not,
for example, "first matching rule in file order wins", which would make
the outcome depend on incidental file/rule ordering rather than on rule
*semantics*.

This is also *why* [[0008-canonicalization-before-matching|Phase 2]]'s
convention of writing allowlist-shaped rules (`path_scope`,
`domain_allowlist`, `rbac`) as `action: allow`, and gate-shaped rules
(`parameter_bounds`, `sequence`, `rate`) as `action: deny`, actually
matters and isn't just a style preference: a gate rule needs to be able to
override a broader `allow` rule elsewhere, and only a `DENY`-shaped rule
can do that under this resolution order. A rule that only ever "voted
ALLOW when its own condition was satisfied" could never block a call that
some *other*, unrelated rule already allowed.

## Consequences
**Positive:**
- The resolution order is a total, deterministic function of which rules
  matched — never dependent on file load order, rule list order, or which
  rule happens to be checked first. Proven by
  `tests/test_policy_engine.py::test_INV_13_evaluate_call_is_pure_and_repeatable`
  (a Hypothesis property test across 1000 random calls) and directly by
  the conflict-resolution unit tests (`test_deny_wins_over_allow`,
  `test_needs_approval_wins_over_allow`, `test_deny_wins_over_needs_approval`).
- Composability: a broad RBAC grant and a narrow bound-check rule can be
  authored completely independently, in different files, by different
  people, and still compose correctly — the bound-check always wins when
  it fires, regardless of how permissive the RBAC rule is.

**Negative / tradeoffs:**
- A policy author who forgets this ordering and writes a gate condition as
  `action: allow` (voting allow only when the value is *within* bounds,
  instead of denying when it's *outside* them) will silently fail to
  override a broader allow rule elsewhere — the schema can't catch this
  mistake, since both are syntactically valid `action: allow` rules with
  different intent. Mitigated by `POLICY_GUIDE.md`'s explicit "which way
  should `action` point?" section and worked example, not by validation.
- `NEEDS_APPROVAL` sitting strictly between `ALLOW` and `DENY` means a
  single `requires_approval` rule can "downgrade" what would otherwise be
  a clean `ALLOW` from a different rule, even if that wasn't the more
  specific or more recently-added rule — this is intentional (approval
  requirements should be hard to accidentally bypass by adding a broader
  allow rule elsewhere), but worth stating explicitly since it's not the
  only reasonable design.

## Alternatives considered
- **First-matching-rule-in-file-order wins.** Rejected: makes the outcome
  depend on the order files happen to be loaded in (`sorted()` over
  filenames, per `load_policy_set`) and where a rule was inserted within
  a file — a purely incidental detail that shouldn't affect a security
  decision, and that would silently change behavior if someone reordered
  rules for readability.
- **Most-specific-rule wins** (e.g. a rule naming an exact tool beats a
  `tool: "*"` wildcard rule). Rejected for Phase 3: meaningfully more
  complex to define precisely and test (what counts as "more specific"
  across six different rule shapes?) for a benefit that DENY-always-wins
  already delivers for the cases that matter (a narrow bound always
  overrides a broad grant, specificity or not).

## Related
- [[policy-engine]]
- [[0008-canonicalization-before-matching]]
- [[0010-policy-integrity-and-loading]]
