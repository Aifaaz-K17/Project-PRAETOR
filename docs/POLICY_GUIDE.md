# Policy Authoring Guide

How to read and write rules under `policies/*.yaml`. Written for capable
beginners — if a term here is unfamiliar, it's explained the first time it
appears.

---

## The shape of a policy file

```yaml
default_action: deny

rules:
  - type: rbac
    id: rbac-transfer-finance-and-admin
    tool: transfer_funds
    action: allow
    roles: ["finance", "admin"]
    description: Only the finance and admin roles may move money at all.
```

Every file under `policies/` is loaded, validated, and merged into one set
at startup by `firewall.policy_engine.load_policy_set()` — never reloaded
while the process runs (INV-03). A file that doesn't validate is a
**startup failure**, not a warning: run `python scripts/verify_policies.py`
after editing anything here, before running the demo or the test suite.

`default_action` is what happens when **no rule matches at all**. Every
file in this repo sets it to `deny` (INV-08), and if two files disagree,
loading fails outright rather than picking one silently.

Every rule shares these fields:

| Field | Meaning |
|---|---|
| `type` | One of the six rule types below. |
| `id` | Unique across every policy file — used in `Decision.rule_id`, so you can trace exactly which rule produced an outcome. |
| `tool` | The tool this rule applies to, or `"*"` for every tool. |
| `action` | `allow` or `deny` — see "Which way should `action` point?" below. |
| `requires_approval` | Optional, default `false`. Only valid on `action: allow` rules — see "Approval-gated rules". |
| `description` | Optional, but write one — it's what a reviewer (or you, in six weeks) reads to understand *why* the rule exists. |

---

## The six rule types

### `path_scope` — is this path inside an allowed directory?

```yaml
- type: path_scope
  id: path-read-file-sandbox
  tool: read_file
  action: allow
  parameter: path
  allowed_roots: ["sandbox"]
```

Matches when `args[parameter]`, canonicalized via
`firewall.canonicalize.canonical_path` (real filesystem resolution —
symlinks resolved, `..` normalized against the actual filesystem, never
string matching — see ADR 0008), resolves to somewhere inside one of
`allowed_roots`. A path that resolves outside all of them, or that fails
canonicalization outright (a NUL byte, a UNC path, a percent-encoding
trick), simply doesn't match — it never gets an explicit "deny", it just
never gets an "allow" either, and falls through to `default_action`.

### `domain_allowlist` — is this host or email address on the list?

```yaml
- type: domain_allowlist
  id: domain-send-email-corp
  tool: send_email
  action: allow
  parameter: to
  allowed_domains: ["corp.example.com"]
```

Matches when `args[parameter]` — a bare hostname, **or** an email address
(the engine tries `canonical_host` first, then falls back to extracting
the domain from `canonical_email` if that fails) — is exactly one of
`allowed_domains`, or a proper subdomain of one (`mail.corp.example.com`
matches `corp.example.com`; `notcorp.example.com` and
`corp.example.com.attacker.net` never do — label-boundary matching, ADR
0008).

### `parameter_bounds` — does a value violate a limit?

```yaml
- type: parameter_bounds
  id: bounds-transfer-max-amount
  tool: transfer_funds
  action: deny
  parameter: amount
  max: 1000
```

Set at least one of `min`, `max`, `max_length`, or `pattern`. Matches when
the parameter **violates** the bound: below `min`, above `max`, longer
than `max_length`, or matching `pattern` (a regex — see "Writing a
`pattern`" below). This is the one rule type that's naturally
`action: deny` — see the next section for why.

### `rbac` — is the caller's role allowed?

```yaml
- type: rbac
  id: rbac-transfer-finance-and-admin
  tool: transfer_funds
  action: allow
  roles: ["finance", "admin"]
```

Matches when the calling principal's `role` — bound via `contextvars` at
session creation, **never** read from the call's own arguments (INV-05) —
is in `roles`.

### `sequence` — did the right thing happen first?

```yaml
- type: sequence
  id: sequence-send-email-requires-draft
  tool: send_email
  action: deny
  requires_prior_tools: ["compose_draft"]
```

Matches (and so blocks) when **any** tool named in `requires_prior_tools`
has *not* yet appeared earlier in the session's call history. This is a
gate, not an allowlist — see "Which way should `action` point?".

> **Phase 3 scope note:** the live interceptor currently evaluates every
> call against an *empty* session history (Phase 4's `firewall/session.py`
> — the real session store — doesn't exist yet). That means a
> `sequence` rule denies every call to its gated tool right now, even a
> genuinely legitimate one, until Phase 4 wires up real history tracking.
> The rule logic itself is fully implemented and tested directly (see
> `tests/test_policy_engine.py`) — see `LIMITATIONS.md`.

### `rate` — too many calls, too fast?

```yaml
- type: rate
  id: rate-transfer-funds
  tool: transfer_funds
  action: deny
  max_calls: 3
  window_seconds: 60
```

Matches when this call would push the count of same-tool calls within the
last `window_seconds` to or past `max_calls`. Same Phase 3 scope note as
`sequence` applies — needs real session history.

---

## Which way should `action` point?

This is the single most important thing to get right when writing a new
rule, and it's easy to get backwards.

**Allowlist-shaped rules** (`path_scope`, `domain_allowlist`, `rbac`) are
written `action: allow`, matching when the call **is** within scope.
`default_action: deny` handles everything else — you never write an
explicit "deny if not in scope" rule for these.

**Gate-shaped rules** (`parameter_bounds`, `sequence`, `rate`) are written
`action: deny`, matching when the call **violates** a bound. This is
deliberate, not arbitrary: it's what lets a narrow deny rule override a
broader allow rule elsewhere. Conflict resolution (ADR 0009) always lets
DENY win over ALLOW — a rule that only ever "voted allow when satisfied"
could never override an unrelated allow rule the same way. Concretely: an
RBAC rule grants `finance` broad access to `transfer_funds`; a
`parameter_bounds` deny rule for amounts over 1000 still blocks a
large transfer from that same role, because DENY wins regardless of what
else matched.

If you're not sure which way a new rule should point, ask: "is this rule
*granting* access to something narrow, or *blocking* something that would
otherwise be allowed by a broader rule?" Granting → `allow`. Blocking →
`deny`.

---

## Conflict resolution — which rule wins?

Every rule whose `tool` matches the call is checked. Among everything that
matches:

1. **Any `DENY` wins**, full stop.
2. Otherwise, **any `NEEDS_APPROVAL`** (an `allow` rule with
   `requires_approval: true`) wins.
3. Otherwise, **any plain `ALLOW`** wins.
4. **Nothing matched** → `default_action` (ships as `deny` everywhere in
   this repo).

See ADR 0009 for the full reasoning and why this order (not some other
order) was chosen.

---

## Approval-gated rules

Add `requires_approval: true` to an `action: allow` rule to mean "this is
allowed, but a human needs to sign off first":

```yaml
- type: domain_allowlist
  id: domain-send-email-partner-needs-approval
  tool: send_email
  action: allow
  requires_approval: true
  parameter: to
  allowed_domains: ["partner.example.org"]
```

It's a schema error to set `requires_approval: true` on an `action: deny`
rule — a deny rule already blocks the call outright, so there's nothing
left to ask a human about.

> **Phase 5 note:** `NEEDS_APPROVAL` is a real, distinct outcome
> (`firewall.interceptor.Outcome.NEEDS_APPROVAL`), but the actual blocking
> human-approval flow (`firewall/hitl.py`) doesn't exist until Phase 5.
> Until then, `NEEDS_APPROVAL` behaves the same as `DENY` at the
> interceptor level — fail-closed in the absence of a real approval
> mechanism, not a claim that approval is implemented.

---

## Writing a `pattern`

`parameter_bounds.pattern` is a regex, compiled with the third-party
`regex` package (not the standard library's `re` — `regex` supports a real
per-call timeout, which `re` does not, and INV-09 requires one). Two
safety layers apply:

1. **Static linting at load time.** Obvious catastrophic-backtracking
   shapes — nested quantifiers like `(a+)+`, or overlapping alternation
   like `(a|aa)+` — are rejected the moment the policy file loads, with a
   clear error naming the offending rule. This is best-effort, not
   exhaustive (detecting every possible ReDoS shape is undecidable in
   general).
2. **A runtime timeout (0.5s).** If a pattern somehow still hangs during a
   real evaluation, that specific call is denied — never a hang, and never
   silently treated as "no match" (which could let through exactly the
   call the pattern existed to catch).

Prefer simple, anchored-where-possible patterns over cleverness. Test any
new pattern against both a string that should match and one that
shouldn't (see the parametrized tests in `tests/test_policy_engine.py` for
the pattern of how existing rules are tested).

---

## Adding a new rule: checklist

1. Pick the right file under `policies/` (or create a new one — any
   `*.yaml`/`*.yml` file under `policies/` is loaded).
2. Give it a unique `id` — `verify_policies.py` and the Pydantic schema
   both reject duplicates.
3. Decide `action` using "Which way should `action` point?" above.
4. Run `python scripts/verify_policies.py` — it must print `OK` and the
   correct rule count.
5. Add at least one test in `tests/test_policy_engine.py`: one call that
   should trigger the rule, one that shouldn't (see
   `test_all_shipped_rules_have_at_least_one_test`, which fails CI if a
   rule id is added with no matching test anywhere in that file).
6. If the rule represents a genuinely new *kind* of legitimate call (not
   just a variant of an existing one), consider adding an entry to
   `tests/fixtures/benign_calls.yaml` too, so Phase 7's false-positive-rate
   measurement stays representative.
7. Run the full gate: `ruff check . && black --check . && mypy firewall/ && pytest -v`.

---

## Why is `policies/` never something a tool can read or write?

Because `policies/` sits outside every `path_scope` rule's
`allowed_roots` — `tests/test_policy_engine.py::
test_INV_03_policies_dir_is_outside_every_tools_allowed_root` checks this
structurally every time the test suite runs, and also proves a realistic
traversal attempt from inside the sandbox can't reach it. If policy files
were agent-readable or -writable, an attacker who controls what the agent
reads could just rewrite the rules that are supposed to constrain it —
see `CLAUDE.md` INV-03.
