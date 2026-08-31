---
tags: [architecture, anomaly-detection, phase-4]
status: implemented
---

# Anomaly Detection

`firewall/anomaly.py` — Phase 4. A second, deliberately separate
deterministic layer from [[policy-engine]] — see
[[0013-rule-based-anomaly-detection]] for the full design rationale.
Where policy rules decide whether one call, in isolation, is within a
human-authored rule, anomaly detection catches a call that is
individually in-policy but whose surrounding context (call volume, tool
sequence, declared-toolset drift, argument "randomness") matches a known
attack shape. Still zero LLM in the decision path (INV-04): every
detector is a pure function over fixed thresholds/pattern lists, no
model call, no embedding, no fuzzy scoring.

Four detectors, each `(call, session_history, declared_tools) →
AnomalyFinding | None`:

- **`detect_call_volume_spike`** — >20 calls of any kind in one session
  within a 10s window.
- **`detect_tool_outside_declared_set`** — opt-in via
  `SessionStore.declare_session(..., declared_tools=...)`; silent for a
  session that never declared one.
- **`detect_high_risk_sequence`** — three curated `(prior, current)`
  tool pairs, e.g. `read_file → send_email`.
- **`detect_argument_entropy_spike`** — Shannon entropy ≥4.5 bits/char
  over any string argument ≥20 characters (typical English prose runs
  ~3.5–4.2).

Each `AnomalyFinding` carries an `AnomalyAction` — `FLAG` (recorded,
outcome unchanged), `ESCALATE` (raises outcome to at least
`NEEDS_APPROVAL`), `HALT` (raises outcome to `DENY`) — mirroring
[[policy-engine]]'s own DENY > NEEDS_APPROVAL > ALLOW precedence
([[0009-policy-conflict-resolution]]). `apply_anomaly_findings` folds
findings into an already-computed `Decision`: every finding's reason is
always appended to the audit trail, but the outcome can only become MORE
restrictive, never less — a finding cannot undo a policy DENY.

Wired into `PolicyEngine` as `enable_anomaly_detection: bool = False`
(opt-in, additive — every existing caller/test is unaffected). Requires
a `session_store` — three of the four detectors need real session
state, and running without one would mean they silently never fire, so
`PolicyEngine.__init__` raises `ValueError` rather than allow a
misleadingly-partial setup.

**Honest scope limits (see `LIMITATIONS.md` and
[[0013-rule-based-anomaly-detection]]):** curated, example-scale rule
lists (three sequence pairs, one entropy threshold) demonstrating the
mechanism against this project's five demo tools, not general attack
coverage; the entropy threshold is a reasoned estimate, not yet
calibrated against `tests/fixtures/benign_calls.yaml`; "entropy spike"
is an absolute threshold against typical prose, not a true per-session
baseline-relative jump (session history intentionally stores no
argument content).

## Depends on
- [[policy-engine]] — Runs after `evaluate_call`, folds into its `Decision`.
- [[session-state-and-audit-trail]] — `SessionStore.get_history`/`get_declared_tools` supply three of the four detectors' real inputs.

## Used by
- [[action-firewall]] — Second decision layer alongside the policy engine.

## Key decisions
- [[0013-rule-based-anomaly-detection]] — Why a separate module, the four detectors and their thresholds, why `session_store` is required, alternatives considered (folding into policy rules, a numeric weighted score, a true per-session entropy baseline).
