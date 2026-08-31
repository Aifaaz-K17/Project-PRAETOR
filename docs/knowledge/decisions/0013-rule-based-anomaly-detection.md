---
tags: [decision, anomaly-detection, policy-engine, security]
status: accepted
date: 2026-09-01
---

# 0013 — Rule-Based Anomaly Detection as a Second, Separate Deterministic Layer

## Status
Accepted.

## Context
`CLAUDE.md`'s Phase 4 scope calls for anomaly detection alongside session
state and the audit trail. Policy rules ([[policy-engine]]) decide whether
one call, in isolation, is within the rules a human author wrote for it.
That leaves a real gap: a call can be individually within policy while its
*surrounding context* — how many calls, which tools, in what order, how
"random" an argument looks — matches a known attack shape. `read_file`
followed by `send_email` is a textbook read-then-exfiltrate pattern even
if both calls, taken alone, are perfectly in-scope.

INV-04 ("zero LLM in the decision path") is non-negotiable, so this had to
be built the same way the policy engine is: pure functions over fixed
thresholds and pattern lists, no model call, no embedding, no fuzzy
scoring. The risk to avoid was blurring this into "the policy engine, but
with vibes" — a second layer that quietly reintroduces probabilistic
judgment under a different name.

## Decision
`firewall/anomaly.py` is a new module, deliberately separate from
`firewall/policy_engine.py`, exposing four independent pure detectors:

1. **`detect_call_volume_spike`** — more than `CALL_VOLUME_MAX_CALLS`
   (20) calls of *any* kind in one session within
   `CALL_VOLUME_WINDOW_SECONDS` (10s). Deliberately a total-volume check
   across every tool, not per-tool — policy's `rate` rule type already
   covers per-tool limits; this catches overall burstiness a per-tool cap
   wouldn't (5 calls each to 4 different tools inside one second).
2. **`detect_tool_outside_declared_set`** — fires only for a session that
   opted in via `SessionStore.declare_session(..., declared_tools=...)`;
   silent (not "deny everything") for a session that never declared one,
   matching the same opt-in pattern `parameter_schema` rules already use.
3. **`detect_high_risk_sequence`** — a curated list of three
   `(prior_tool, current_tool)` pairs (`read_file → send_email`,
   `read_file → compose_draft`, `search_web → transfer_funds`) that are
   each individually benign but suspicious in combination.
4. **`detect_argument_entropy_spike`** — Shannon entropy over any string
   argument ≥20 characters; ≥4.5 bits/char (typical English prose runs
   ~3.5–4.2, encoded/obfuscated payloads typically ~5.5–6) flags, doesn't
   escalate or halt.

Each finding carries an `AnomalyAction` — `FLAG` (recorded, outcome
unchanged), `ESCALATE` (outcome raised to at least `NEEDS_APPROVAL`), or
`HALT` (outcome raised to `DENY`) — mirroring conflict resolution's own
DENY > NEEDS_APPROVAL > ALLOW precedence
([[0009-policy-conflict-resolution]]). `apply_anomaly_findings` folds
every finding's reason into the audit trail regardless of severity (even
a FLAG-only finding must be visible — INV-10/INV-11) but can only ever
raise the outcome `evaluate_call` already computed, never lower it — a
finding cannot undo a policy DENY.

Wired into `PolicyEngine` as an opt-in constructor flag
(`enable_anomaly_detection: bool = False`), run *after* `evaluate_call`
inside `PolicyEngine.evaluate`. Requires a `session_store` — three of the
four detectors need real session history/declared-tools state, and
without one they'd silently never fire, which is worse than refusing to
construct the engine at all (`PolicyEngine.__init__` raises `ValueError`
if `enable_anomaly_detection=True` and `session_store is None`).

## Consequences
**Positive:**
- Catches a class of problem policy rules structurally cannot: context
  across multiple individually-in-policy calls, not one call in
  isolation.
- Stays inside INV-04 — every detector is a pure function over fixed
  thresholds/pattern lists, tested for determinism
  (`test_detect_anomalies_is_deterministic`,
  `test_INV_13_evaluate_call_is_pure_and_repeatable`-style coverage in
  `tests/test_anomaly.py`).
- Opt-in and additive: `enable_anomaly_detection` defaults to `False`, so
  every existing `PolicyEngine` caller and test is unaffected
  (`test_policy_engine_anomaly_detection_disabled_by_default`).
- A finding can only make the outcome more restrictive, never less —
  structurally cannot be used to bypass a policy DENY.

**Negative / honest scope limits (see `LIMITATIONS.md`):**
- **Curated, example-scale rule lists, not general coverage.** Three
  high-risk sequence pairs and one entropy threshold demonstrate the
  mechanism against this project's five demo tools — not a claim of
  covering every risky sequence or every obfuscation technique.
- **The entropy threshold (4.5 bits/char) is a reasoned estimate, not
  calibrated against `tests/fixtures/benign_calls.yaml`.** TODO(verify) —
  Phase 7's evaluation work should confirm the shipped benign corpus
  doesn't trip it, or record the false-positive rate honestly if it does.
- **"Entropy spike" is really an absolute threshold, not a true
  baseline-relative jump.** `SessionHistoryEntry` deliberately stores
  only `(tool_name, timestamp)`, not argument content (see
  "Alternatives considered"), so there's no per-session baseline to jump
  from — the name describes the intent, the implementation is an
  absolute-threshold check against typical natural-language entropy.
- **Round numbers, not load-tested.** `CALL_VOLUME_MAX_CALLS` (20) and
  `CALL_VOLUME_WINDOW_SECONDS` (10s) are headroom-driven choices for this
  project's scale, the same honest caveat `MAX_RULE_COUNT`/etc. already
  carry from Phase 3.
- **`enable_anomaly_detection` requiring `session_store` is a hard
  constraint, not a soft warning** — a deliberate choice to fail loudly at
  construction time (INV-01-flavored, though anomaly detection itself
  isn't a core invariant) rather than let a caller believe detection is
  running when three-quarters of it silently isn't.

## Alternatives considered
- **Fold anomaly checks directly into `policy_engine.evaluate_call` as
  another rule type.** Rejected: anomaly findings are about *context
  across calls* (volume, sequence, declared-tools drift), a different
  shape of input than a single rule matching a single call's arguments
  against static YAML. Keeping it a separate module with its own
  orchestration (`detect_anomalies`) keeps the policy engine's existing
  conflict-resolution logic ([[0009-policy-conflict-resolution]])
  untouched and independently testable, and keeps a reader able to
  answer "is this a human-authored rule or a heuristic detector" from
  which file they're looking at.
- **Extend `SessionHistoryEntry` to store argument content, enabling a
  true per-session entropy baseline.** Rejected for this phase: storing
  argument content in session history conflicts with the log-hygiene
  instinct INV-11 already applies to the audit log (even in-memory,
  unredacted argument content sitting around for a session's TTL is a
  larger exposure surface than a `(tool_name, timestamp)` tuple), and
  doubles `firewall/session.py`'s scope for a refinement Phase 7 can
  evaluate the actual need for.
- **Score findings with weights and sum to a numeric risk score,
  threshold on the sum.** Rejected: closer to the "policy engine but with
  vibes" failure mode this decision exists to avoid — a fixed action per
  finding (FLAG/ESCALATE/HALT) keeps every detector's contribution
  individually explainable in the audit trail, rather than requiring a
  reader to reconstruct why a particular sum crossed a particular line.

## Related
- [[policy-engine]]
- [[0009-policy-conflict-resolution]]
- [[0012-rbac-composition-with-allowlist-rules]]
