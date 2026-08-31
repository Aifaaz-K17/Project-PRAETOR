---
tags: [decision, security, policy-engine, rbac, code-review]
status: accepted
date: 2026-09-01
---

# 0014 — Phase 4 Completion Security Review: Three Real Bugs, One Structural Guard

## Status
Accepted.

## Context
Before moving to Phase 5, the user asked for a deliberate bug/vulnerability/
weakness review pass over the codebase (not just "tests are green") —
see the working-agreement recorded for this project's memory. This ADR
documents what that pass actually found on Phase 3/4 code, each
independently reproduced against the real `policies/` directory before
being called a bug (the same discipline the Phase 3 code-review-fix pass
used).

## Decision

### Finding 1 — numeric-string type confusion bypassed `min`/`max` bounds
`_matches_parameter_bounds` (`firewall/policy_engine.py`) only ever
compared `rule.min`/`rule.max` against a value that was already a native
`int`/`float`:

```python
if rule.min is not None and isinstance(value, (int, float)) and not isinstance(value, bool) and value < rule.min:
    return True
```

A value of any other shape — critically, a numeric-looking `str` such as
`"amount": "999999"` — silently never matched, meaning the whole rule
never fired. Reproduced directly: `transfer_funds` with
`{"amount": "999999", "note": "..."}` and `role="finance"` was **ALLOWED**
by `rbac-transfer-finance-and-admin`, even though the same amount as a
native int (`999999`) is correctly **DENIED** by
`bounds-transfer-max-amount` (`max: 1000`).

This is a realistic, not a contrived, input shape: `CallRecord.raw_args`
comes straight from parsing an LLM's tool-call JSON (see
`demo_agent/hello_world.py`'s `tool_call["args"]`), before the tool's own
Pydantic argument schema ever runs — that coercion happens only after the
firewall's decision, inside the guarded tool's own `.invoke()`. A model
emitting a number as a quoted JSON string is a known, common shape of
tool-calling drift, not an edge case.

**Fix:** a new `_coerce_numeric` helper. A native `int`/`float` (never
`bool`) is used as-is; a numeric-looking `str` is parsed with `float()`;
anything else — an unparseable string, a `bool`, a list, a dict — returns
`None`, and the caller treats `None` as a bounds violation (fail closed),
never as "no bound applies." Regression tests:
`test_INV_01_policy_bounds_string_typed_amount_still_enforced`,
`test_INV_01_policy_bounds_uncoercible_amount_fails_closed`,
`test_INV_01_real_policy_set_denies_string_typed_over_cap_transfer`.

### Finding 2 & 3 — two more instances of the ADR 0012 bug class
[[0012-rbac-composition-with-allowlist-rules]] fixed
`path-read-file-sandbox` and `domain-send-email-corp`, and explicitly
named the risk of the fix being "opt-in, not automatic" — a future rule
of the same unrestricted shape could reintroduce the bug. This review
found that risk had already materialized twice, on rules ADR 0012 itself
did not touch:

- **`path-compose-draft-attachment-sandbox`** (`policies/path_scope.yaml`):
  unrestricted (`action: allow`, no `roles`). Reproduced: a `"guest"` role
  — with **zero** `compose_draft` RBAC grant of any kind, plain or
  approval-gated — was **ALLOWED** to compose a draft with an in-scope
  attachment, because this rule's own vote didn't check role at all.
- **`domain-search-web-reference-sites`** (`policies/domain_allowlist.yaml`):
  same shape. `rbac-search-web-everyone`'s "everyone" is still a specific,
  enumerated list (`intern`/`analyst`/`finance`/`admin`) — RBAC is a
  closed allowlist (INV-08), not an open one. Reproduced: a role string
  that isn't in that list at all (`"not-a-real-role"`) was **ALLOWED** to
  search the web, because this rule's vote also didn't check role.

**Fix:** the same mechanism ADR 0012 already built — populate `roles` on
both rules, matching their sibling `rbac` rule(s)' granted roles (leaving
`intern` out of `path-compose-draft-attachment-sandbox`'s list
deliberately, so NEEDS_APPROVAL still wins for that role rather than
losing its approval path). Regression tests:
`test_INV_05_policy_path_scope_compose_draft_roles_compose_with_rbac`,
`test_INV_05_real_policy_set_compose_draft_guest_role_no_longer_bypasses_rbac`,
`test_INV_05_real_policy_set_search_web_unrecognized_role_no_longer_bypasses_rbac`.

### The structural guard ADR 0012 named as a follow-up, now built
ADR 0012's "Consequences" section named exactly this: "A structural guard
(e.g. a test that walks every tool with both an `rbac` rule and an
unrestricted `path_scope`/`domain_allowlist` rule and flags the overlap)
is a reasonable follow-up, not built here." `firewall/policy_engine.py`
gained no new code for this — it's a single test,
`test_INV_05_no_unrestricted_allowlist_rule_can_bypass_an_rbac_rule` in
`tests/test_policy_engine.py`: walks every `path_scope`/`domain_allowlist`
rule in the real, loaded `policies/` directory, and fails if one is
unrestricted (`action: allow`, no `requires_approval`, empty `roles`)
while any `rbac` rule exists for the same tool. Verified against a
synthetic reconstruction of the pre-fix `path-compose-draft-attachment-
sandbox` shape that it does in fact flag that exact pattern, not just
pass trivially on the now-fixed real files.

Deliberately does **not** flag a `requires_approval`-shaped unrestricted
allowlist rule (e.g. `domain-send-email-partner-needs-approval`) — that
vote can't "win outright" against an RBAC restriction the way a plain
ALLOW can (NEEDS_APPROVAL still outranks a bare ALLOW in conflict
resolution — ADR 0009), and until Phase 5's HITL evaluator exists,
NEEDS_APPROVAL is treated the same as DENY at the interceptor level
regardless. This is named explicitly as a known, narrower residual: a
`requires_approval`-shaped unrestricted rule still grants a role no
`rbac` rule ever named a path to human approval, once Phase 5 exists —
tracked in `LIMITATIONS.md`, not fixed here, since fixing it now would
mean guessing at Phase 5's not-yet-built approval semantics.

### A non-finding, corrected in the same pass
`firewall/session.py`'s `SessionStore.declare_session` unconditionally
resets a session's call history. An earlier step in this same review
misread that as contradicting the module's "append-only" docstring
language and started fixing it — before finding
`tests/test_declare_session_resets_history_if_called_again` in
`tests/test_session.py`, which documents this as deliberate: the
"append-only" claim scopes specifically to `record_call` ("`record_call`
can only ever add... never rewrite or remove"), not to
`SessionStore` as a whole, and `declare_session` is only ever called by
trusted server-side code at real session creation — the same trust
boundary as `firewall.context.bind_principal` (INV-05), never
agent-reachable. The change was reverted; a one-line docstring
clarification was kept, pointing at the existing test. Recorded here
because "checked, found already correct and tested" is real review
output too, not just the bugs that were real.

## Consequences
**Positive:**
- Closes a real financial-bound bypass (Finding 1) and two real
  RBAC-restriction bypasses (Findings 2–3) with reproducible-before-fix,
  passing-after-fix regression tests for each.
- The structural guard (not just three point-fixes) means a fourth
  instance of the same allowlist-vs-rbac pattern fails CI immediately
  instead of waiting for the next manual review pass to notice it.
- No behavior change for any of this project's existing passing tests —
  `pytest -v` stayed at 100% pass (325 passed, 1 skipped) throughout,
  confirmed after each individual fix, not just at the end.

**Negative / honest scope limits:**
- Finding 1's fix is specific to `parameter_bounds`' `min`/`max` fields.
  It does not address type confusion in `max_length`/`pattern` checks
  (already safe — both call `str(value)` unconditionally, so any type
  produces *some* comparable text) or in other rule types entirely
  (`path_scope`, `domain_allowlist` already require `isinstance(value,
  str)` and simply don't match otherwise — fail-closed-correct, not a
  parallel gap).
- The structural guard (Findings 2–3's follow-up) only covers
  `path_scope`/`domain_allowlist` vs. `rbac`. It does not check for an
  analogous composition gap against `sequence` or `rate` rules, which
  this review did not find evidence of but also did not exhaustively
  rule out.
- This was one review pass at a fixed effort level, not an exhaustive
  audit — see `LIMITATIONS.md`'s existing scoping language for Phase 3's
  code-review-fix pass, which applies equally here: findings are real and
  independently reproduced, but absence of further findings is not a
  claim of completeness.

## Alternatives considered
- **For Finding 1: reject any non-`int`/`float` value for a `min`/`max`
  rule outright, without attempting string coercion.** Rejected: this
  would treat the extremely plausible "amount as a JSON string" shape the
  same as a genuinely malformed value, denying legitimate calls a
  well-behaved LLM or a JSON-based tool-calling client would routinely
  produce. Coercing the plausible shape and failing closed only on the
  genuinely unparseable one is the more precise fix.
- **For Findings 2–3: derive `roles` automatically from any co-located
  `rbac` rule at load time**, closing the class of bug structurally
  instead of per-rule. Rejected for the same reason ADR 0012 rejected it
  originally: it would make an allowlist rule's effective permissions
  depend on easily-overlooked cross-file state. The structural *test*
  guard achieves the safety net without that coupling.

## Related
- [[policy-engine]]
- [[0009-policy-conflict-resolution]]
- [[0012-rbac-composition-with-allowlist-rules]]
- [[session-state-and-audit-trail]]
