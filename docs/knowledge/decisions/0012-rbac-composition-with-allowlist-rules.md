---
tags: [decision, policy-engine, security, rbac]
status: accepted
date: 2026-08-31
---

# 0012 — RBAC Must Compose With, Not Be Bypassable By, Allowlist Rules

## Status
Accepted.

> Numbering note: continues the sequential renumbering from
> [[0011-unknown-parameter-enforcement]]. This is Phase 4's first ADR;
> the next new one is 0013.

## Context
Found via manual testing while wiring up `SessionStore`/`AuditLogger`
integration in Phase 4 (not by the earlier 7-angle code review, which
missed it). `policies/path_scope.yaml`'s `path-read-file-sandbox` rule and
`policies/domain_allowlist.yaml`'s `domain-send-email-corp` rule were both
written as unconditional `action: allow` grants — matching *any* role, as
long as the path/domain was in scope.

Per [[0009-policy-conflict-resolution]], conflict resolution treats every
matching ALLOW-type rule's vote as independently sufficient — DENY beats
NEEDS_APPROVAL beats ALLOW beats `default_action`, but among multiple
ALLOW votes there is no AND: any one of them is enough. This means an
unconditional `path_scope`/`domain_allowlist` ALLOW does not *narrow* an
`rbac` rule's role restriction on the same tool — it sits beside it as an
independent grant, and the RBAC rule's restriction is simply outvoted.

Concretely: `rbac-read-file-analysts` restricts `read_file` to
`analyst`/`finance`/`admin`. But `path-read-file-sandbox` (unconditional)
also voted ALLOW for *any* role, including `intern`. An `intern` call
inside `sandbox/` was DENIED by the RBAC rule and simultaneously ALLOWED
by the path_scope rule — and ALLOW wins that tie. The same bug existed for
`send_email` to the corp domain via `domain-send-email-corp` vs.
`rbac-send-email-analysts`. In effect, RBAC provided no real restriction
at all for either tool: an intern with zero legitimate grant could read
any in-scope file or email the corp domain (once any other gate, like
`compose_draft`'s sequence rule, was separately satisfied).

Verified NOT vulnerable: `transfer_funds` (no `path_scope`/
`domain_allowlist` rule exists for it — RBAC is the only ALLOW vote).
Verified NOT actually exploitable in practice, despite carrying the same
unconditional-ALLOW shape: `compose_draft`'s
`path-compose-draft-attachment-sandbox` rule, because
`rbac-compose-draft-...`-adjacent `requires_approval` on the intern path
means NEEDS_APPROVAL is already in play for that tool, and
NEEDS_APPROVAL beats a plain ALLOW in conflict resolution — so the extra
unconditional ALLOW vote never changed the outcome for that specific tool
today. This is coincidental to that tool's current rule shape, not a
structural protection — see "Consequences" below.

## Decision
`PathScopeRule` and `DomainAllowlistRule` (`firewall/policy_schema.py`)
gain an optional field:

```python
roles: tuple[str, ...] = Field(default_factory=tuple)
```

Empty tuple (the default) means unrestricted by role — unchanged
behavior, consistent with this project's existing opt-in-scoping pattern
(`parameter_schema`'s per-tool opt-in, `SessionStore.declared_tools`'
empty-means-unrestricted default). When non-empty,
`_matches_path_scope`/`_matches_domain_allowlist`
(`firewall/policy_engine.py`) reject the match outright if
`call.role not in rule.roles`, before doing any path/domain comparison:

```python
if rule.roles and call.role not in rule.roles:
    return False
```

The two actually-vulnerable shipped rules are updated to declare
`roles: ["analyst", "finance", "admin"]`, matching the roles their
sibling `rbac` rule already permits:

- `policies/path_scope.yaml` → `path-read-file-sandbox`
- `policies/domain_allowlist.yaml` → `domain-send-email-corp`

This makes the allowlist rule's own vote agree with RBAC's restriction
instead of independently overriding it. Verified directly: `intern` now
DENIED for both `read_file` (in-scope path) and `send_email` (to the corp
domain); `analyst` still ALLOWED for both. Regression tests:
`test_INV_05_policy_path_scope_roles_compose_with_rbac_not_bypass_it` and
`test_INV_05_policy_domain_allowlist_roles_compose_with_rbac_not_bypass_it`
in `tests/test_policy_engine.py`.

## Consequences
**Positive:**
- Closes a real authorization bypass: RBAC restrictions on `read_file`
  and `send_email`-to-corp now actually hold, instead of being silently
  overridden by an unrelated allowlist rule's independent ALLOW vote.
- The fix is structural (a field + a guard clause), not a one-off patch
  to the two vulnerable rules alone — any future `path_scope` or
  `domain_allowlist` rule can opt into the same protection by setting
  `roles`, without engine changes.
- No change to unrestricted-by-design rules (e.g.
  `path-compose-draft-attachment-sandbox`,
  `domain-search-web-reference-sites`) — `roles` defaults to empty, so
  they keep matching any role exactly as before. Confirmed by the full
  test suite passing with no other test needing changes.

**Negative / tradeoffs:**
- **Opt-in, not automatic.** This does not fix the general class of bug —
  it fixes the two rules known today to overlap with an `rbac` rule on
  the same tool. A future policy author who adds a new `path_scope` or
  `domain_allowlist` rule for a tool that already has an `rbac` rule, and
  forgets to set `roles` to match, reintroduces exactly this bug, and
  nothing in the engine or the test suite would catch it automatically.
  Considered and rejected: automatically deriving `roles` from any
  co-located `rbac` rule for the same tool at load time — rejected
  because it would make an allowlist rule's effective permission set
  depend on load-order-independent but easily-overlooked cross-file state
  (which `rbac.yaml` rule exists, whether it was renamed, whether it's
  even in the same file), turning a bug findable-in-one-file into one
  findable only by reading two files together. A structural guard (e.g. a
  test that walks every tool with both an `rbac` rule and an unrestricted
  `path_scope`/`domain_allowlist` rule and flags the overlap) is a
  reasonable follow-up, not built here — see `LIMITATIONS.md`.
  **Update 2026-09-01:** this risk was not hypothetical — a deliberate
  review pass found this exact pattern already present on two more
  shipped rules (`path-compose-draft-attachment-sandbox`,
  `domain-search-web-reference-sites`), fixed the same way, and the
  named structural guard test was built. See
  [[0014-phase4-security-review-findings]].
- `compose_draft`'s coincidental safety (NEEDS_APPROVAL outranking the
  unconditional ALLOW) is not something to rely on if that rule's
  `requires_approval` flag is ever removed or its RBAC rule changed —
  flagged explicitly here so a future editor doesn't read "it currently
  works" as "it's protected by design."

## Alternatives considered
- **Make ALLOW votes AND instead of OR when multiple ALLOW-type rules
  match the same tool.** Rejected: this is a global conflict-resolution
  semantics change ([[0009-policy-conflict-resolution]]), not a
  role-scoping change — it would silently alter every other policy set
  that intentionally relies on independent ALLOW rules composing as OR
  (e.g. `domain-search-web-reference-sites` listing three independent
  domains is *not* meant to require all three), which is a much larger
  blast radius for a fix that only two rules actually needed.
  [[0009-policy-conflict-resolution]]'s reasoning for the current design
  is sound; the bug was in two rule *authorings*, not in conflict
  resolution itself.
- **Remove `path_scope`/`domain_allowlist` as an ALLOW-shaped rule type
  entirely, force everything through `rbac` plus a DENY-shaped bound.**
  Rejected as a much larger schema redesign than the bug warrants — see
  [[0009-policy-conflict-resolution]]'s existing design note on why
  allowlist-shaped rules are deliberately ALLOW-shaped (DENY-by-default
  already handles the "not in scope" case; forcing everything into a
  deny-shaped bound would require inverting every path/domain check).

## Related
- [[policy-engine]]
- [[0009-policy-conflict-resolution]]
- [[0011-unknown-parameter-enforcement]]
