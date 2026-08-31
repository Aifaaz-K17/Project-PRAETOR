---
tags: [decision, policy-engine, security]
status: accepted
date: 2026-08-31
---

# 0010 — Policy Integrity, Loading, and Bounded Evaluation

## Status
Accepted.

> Numbering note: see [[0009-policy-conflict-resolution]] — this is
> Phase 3's second ADR, following the sequential renumbering started in
> Phase 1.

## Context
INV-03 requires policies to be loaded once at startup into frozen
structures, hashed so any decision is reproducible against an exact rule
set, with `policies/` unreachable from any agent-accessible tool. INV-09
requires bounded evaluation — regex patterns compiled at load with
complexity linting and a per-evaluation timeout, and caps on argument
size, string length, and nesting depth. Both are "how do we know the
policy engine itself can't be turned into an attack surface" concerns,
distinct from what any individual rule decides.

## Decision

### Loading (INV-03)
`load_policy_set(policy_dir)` reads every `*.yaml`/`*.yml` file under
`policy_dir` in **sorted filename order** (deterministic), parses each
with `yaml.safe_load` only (never `yaml.load` — CLAUDE.md §3), validates
against the Pydantic schema (a `ValidationError` is wrapped into
`PolicyLoadError` naming the exact file and field), and merges every
file's rules into one `PolicySet`. A `SHA-256` hash is computed
incrementally over each file's name and raw bytes, in that same sorted
order, giving one `policy_set_hash` for the whole loaded set — stable
across re-loads of unchanged content
(`test_load_policy_set_hash_is_deterministic_and_order_independent`), and
changing the instant any file's content changes
(`test_load_policy_set_hash_changes_when_content_changes`). This hash is
what a future audit log (Phase 4) will stamp on every decision row, so any
past decision can be checked against the exact rule set that produced it.

`PolicySet` and every rule model use Pydantic's `frozen=True` — an
accidental mutation after load raises immediately rather than silently
changing behavior mid-process.

`policies/` staying outside every tool's reachable filesystem scope is
verified structurally, not just asserted: every shipped `path_scope`
rule's `allowed_roots` is checked against the real, resolved
`policies/` directory path
(`test_INV_03_policies_dir_is_outside_every_tools_allowed_root`), and a
concrete traversal attempt from inside the sandbox is confirmed to fail
via `canonical_path`.

### Bounded evaluation (INV-09)
Four caps, checked against `call.canonical_args` before any rule runs
(`_check_bounds`, in `firewall/policy_engine.py`):
`MAX_ARG_COUNT = 50`, `MAX_STRING_LENGTH = 65536`,
`MAX_NESTING_DEPTH = 10`, `MAX_RULE_COUNT = 500` (checked once, at load).
A violation is an immediate `Decision.deny` tagged `POLICY_ERROR` — never
a partial evaluation of some rules against oversized input.

Regex patterns (`parameter_bounds.pattern`) are compiled with the
third-party `regex` package, not the standard library's `re` — verified
during this phase that `re.search()` has no way to bound its own runtime
at all (a genuine catastrophic-backtracking pattern, `(a|aa)+$` against
36 `a`s, was confirmed to hang indefinitely — killed after 10s in this
session), while `regex.search(pattern, string, timeout=...)` correctly
raises `TimeoutError` on the same input in under the requested bound.
Two independent layers apply, deliberately not just one:

1. **Load-time linting** (`_lint_pattern_for_redos`) rejects obvious
   nested-quantifier (`(a+)+`) and overlapping-alternation (`(a|aa)+`)
   shapes the moment a policy file loads — before any real call ever
   reaches them. Explicitly documented as best-effort, not exhaustive:
   detecting every possible ReDoS shape is undecidable in general.
2. **A runtime timeout** (`REGEX_TIMEOUT_SECONDS = 0.5`, in
   `_matches_parameter_bounds`) is the actual hard guarantee. Tested
   *independently* of the linter — `test_INV_09_runtime_regex_timeout_denies_rather_than_hangs`
   hand-compiles a catastrophic pattern with `regex.compile()` directly,
   bypassing `_compile_pattern`'s linting on purpose, to prove the timeout
   path works even for a pattern the static linter didn't catch.

A timeout during evaluation denies the **whole call**, not just the one
rule that timed out — treating a timed-out rule as "didn't match" could
silently allow exactly the call that rule existed to catch.

## Consequences
**Positive:**
- Both the load-time and run-time ReDoS defenses are tested against a
  pattern independently *verified in this session* to actually hang
  Python's standard `re` module — not a pattern assumed to be dangerous.
- `scripts/verify_policies.py` gives the team a one-command way to check
  every claim in this ADR before running a demo: rule count, default
  action, compiled-pattern count, and the exact hash.

**Negative / tradeoffs:**
- `MAX_RULE_COUNT = 500` and the other caps are round numbers chosen for
  headroom over this project's actual scale (~25 rules, ADR 0004's ~5
  tools), not derived from a load-tested threshold — TODO(verify) if
  Phase 7's evaluation work ever needs to characterize real limits.
- The load-time linter's two regex patterns
  (`_NESTED_QUANTIFIER_RE`, `_OVERLAPPING_ALTERNATION_RE`) are themselves
  simple, fixed patterns rather than a general ReDoS static-analysis tool
  — they catch the textbook shapes named in CLAUDE.md's Phase 3 spec and
  no more. Documented as best-effort in both the code and
  `POLICY_GUIDE.md`, not oversold as complete.

## Alternatives considered
- **A separate subprocess per regex evaluation**, killed on timeout.
  Rejected: far higher overhead per call for a check that happens on
  every single tool invocation, for no benefit over `regex`'s built-in
  timeout parameter once that was confirmed to actually work.
- **Signal-based timeout** (`signal.alarm`). Rejected: doesn't work on
  Windows, and this project's CI and at least one dev machine are
  Windows-based — `regex`'s own timeout mechanism is cross-platform.

## Related
- [[policy-engine]]
- [[0009-policy-conflict-resolution]]
- [[canonicalization]]
