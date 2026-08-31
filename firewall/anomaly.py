"""Rule-based anomaly detection — Phase 4.

Four detectors, each a pure function over `(call, session_history,
declared_tools)` — no model call, no embedding, no heuristic scoring
outside fixed thresholds and pattern lists (INV-04: this is a second,
clearly separate deterministic layer, not a fusion of the policy engine
with anything probabilistic). Every detector is deterministic given its
inputs (INV-13): no wall-clock reads beyond what `call.timestamp_utc` and
`session_history` already carry.

This module deliberately does not decide anything about default_action or
policy rules — see `firewall/policy_engine.py` for that. It exists to
catch a different class of problem: a call that is individually within
policy, but whose surrounding context (how many calls, which tools, in
what order, how "random" an argument looks) resembles a known attack
shape. `apply_anomaly_findings` folds its findings into an
already-computed `Decision`, using the exact same DENY > NEEDS_APPROVAL >
ALLOW precedence as policy conflict resolution (ADR 0009) — a finding can
raise the outcome, never lower it.

See ADR 0013 for the threshold rationale and the honest scope limits
(a curated, example-scale rule list, not a claim of covering every
attack shape — see LIMITATIONS.md).
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum

from firewall.interceptor import CallRecord, Decision, Outcome
from firewall.session import SessionHistoryEntry


class AnomalyAction(str, Enum):
    """What a finding does to the call's outcome once folded in by
    `apply_anomaly_findings` — mirrors the project's existing
    DENY > NEEDS_APPROVAL > ALLOW precedence (ADR 0009)."""

    FLAG = "flag"  # recorded in the audit trail; outcome unchanged
    ESCALATE = "escalate"  # outcome raised to at least NEEDS_APPROVAL
    HALT = "halt"  # outcome raised to DENY


_ACTION_TO_OUTCOME: dict[AnomalyAction, Outcome | None] = {
    AnomalyAction.HALT: Outcome.DENY,
    AnomalyAction.ESCALATE: Outcome.NEEDS_APPROVAL,
    AnomalyAction.FLAG: None,  # doesn't imply any outcome by itself
}

_OUTCOME_RANK: dict[Outcome, int] = {
    Outcome.ALLOW: 0,
    Outcome.NEEDS_APPROVAL: 1,
    Outcome.DENY: 2,
}


@dataclass(frozen=True)
class AnomalyFinding:
    """One detector's verdict on one call. `detector` is a short slug
    (matches the function name below, minus `detect_`) used both in
    human-readable output and as the `anomaly:<detector>` rule_id an
    escalating/halting finding attaches to the final `Decision`."""

    detector: str
    action: AnomalyAction
    reason: str


# ---------------------------------------------------------------------------
# Detector 1 — call-volume spike
# ---------------------------------------------------------------------------

CALL_VOLUME_WINDOW_SECONDS = 10.0
CALL_VOLUME_MAX_CALLS = 20
# Rationale: a legitimate single agent turn issues a handful of tool
# calls. 20 calls of ANY kind from one session within 10 seconds is well
# outside normal single-turn usage — the shape a runaway loop, or an
# agent steered by injected instructions into rapid repeated action,
# would produce. Deliberately a *total* volume check across every tool,
# not per-tool: per-tool rate limiting already exists as policy's `rate`
# rule type; this detector catches overall burstiness a per-tool cap
# wouldn't (e.g. 5 calls each to 4 different tools inside one second).
# Round numbers chosen for headroom, not derived from load testing — see
# ADR 0013 and LIMITATIONS.md.


def detect_call_volume_spike(
    call: CallRecord, session_history: Sequence[SessionHistoryEntry]
) -> AnomalyFinding | None:
    window_start = call.timestamp_utc - timedelta(seconds=CALL_VOLUME_WINDOW_SECONDS)
    recent_calls = sum(1 for _tool, ts in session_history if ts >= window_start)
    total_including_this_call = recent_calls + 1
    if total_including_this_call > CALL_VOLUME_MAX_CALLS:
        return AnomalyFinding(
            detector="call_volume_spike",
            action=AnomalyAction.ESCALATE,
            reason=(
                f"{total_including_this_call} calls in this session within "
                f"{CALL_VOLUME_WINDOW_SECONDS:.0f}s (threshold "
                f"{CALL_VOLUME_MAX_CALLS})"
            ),
        )
    return None


# ---------------------------------------------------------------------------
# Detector 2 — tool outside the session's declared set
# ---------------------------------------------------------------------------
# Opt-in, same pattern as SessionStore.declared_tools itself: an empty set
# means "this session never declared a toolset," not "this session may
# call nothing" — so this detector is silent unless a caller has actually
# opted a session into declaring one.


def detect_tool_outside_declared_set(
    call: CallRecord, declared_tools: frozenset[str]
) -> AnomalyFinding | None:
    if not declared_tools:
        return None
    if call.tool_name in declared_tools:
        return None
    return AnomalyFinding(
        detector="tool_outside_declared_set",
        action=AnomalyAction.HALT,
        reason=(
            f"tool {call.tool_name!r} is not among this session's declared "
            f"tools {sorted(declared_tools)!r}"
        ),
    )


# ---------------------------------------------------------------------------
# Detector 3 — high-risk sequence
# ---------------------------------------------------------------------------

HIGH_RISK_SEQUENCES: tuple[tuple[str, str], ...] = (
    ("read_file", "send_email"),
    ("read_file", "compose_draft"),
    ("search_web", "transfer_funds"),
)
# Rationale: each (prior_tool, current_tool) pair is individually benign
# under policy, but the combination inside one session matches a
# recognizable attack shape. read_file -> send_email (or -> compose_draft,
# which usually precedes it) is the read-then-exfiltrate pattern;
# search_web -> transfer_funds is "an agent that just fetched untrusted
# web content immediately moving money" — the shape a prompt-injection-
# driven financial attack would take. A curated, example-scale list (three
# pairs) demonstrating the mechanism against this project's five demo
# tools, not a claim of covering every risky combination — see ADR 0013.


def detect_high_risk_sequence(
    call: CallRecord, session_history: Sequence[SessionHistoryEntry]
) -> AnomalyFinding | None:
    prior_tools = {tool for tool, _ts in session_history}
    for prior_tool, current_tool in HIGH_RISK_SEQUENCES:
        if call.tool_name == current_tool and prior_tool in prior_tools:
            return AnomalyFinding(
                detector="high_risk_sequence",
                action=AnomalyAction.ESCALATE,
                reason=(
                    f"{prior_tool!r} appeared earlier in this session, now "
                    f"followed by {current_tool!r} — matches a known "
                    f"high-risk sequence"
                ),
            )
    return None


# ---------------------------------------------------------------------------
# Detector 4 — argument entropy spike
# ---------------------------------------------------------------------------

ARGUMENT_ENTROPY_MIN_LENGTH = 20
ARGUMENT_ENTROPY_THRESHOLD_BITS_PER_CHAR = 4.5
# Rationale: typical English prose measures roughly 3.5-4.2 bits/char of
# Shannon entropy; base64-encoded or otherwise-obfuscated payloads
# (shellcode, encoded exfiltration data, a smuggled instruction payload)
# characteristically measure noticeably higher, often 5.5-6 bits/char.
# 4.5 bits/char sits comfortably above normal prose and below typical
# encoded-data entropy. TODO(verify): not calibrated against this
# project's own benign_calls.yaml corpus — see ADR 0013 and
# LIMITATIONS.md. Values shorter than ARGUMENT_ENTROPY_MIN_LENGTH are
# skipped because entropy estimates on short strings are unreliable (a
# 5-character string can trivially read as "high entropy" by chance).
#
# Honest naming note: this is an absolute-threshold check against typical
# natural-language entropy, not a true baseline-relative "jump" measured
# against this session's own history — session history
# (firewall/session.py's SessionHistoryEntry) deliberately stores only
# (tool_name, timestamp), not argument content, so there is no per-session
# baseline available to jump from. See ADR 0013 "Alternatives considered"
# for why extending session history to store argument content was
# rejected.


def _shannon_entropy_bits_per_char(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def detect_argument_entropy_spike(call: CallRecord) -> AnomalyFinding | None:
    for parameter, value in call.canonical_args.items():
        if not isinstance(value, str) or len(value) < ARGUMENT_ENTROPY_MIN_LENGTH:
            continue
        entropy = _shannon_entropy_bits_per_char(value)
        if entropy >= ARGUMENT_ENTROPY_THRESHOLD_BITS_PER_CHAR:
            return AnomalyFinding(
                detector="argument_entropy_spike",
                action=AnomalyAction.FLAG,
                reason=(
                    f"parameter {parameter!r} measures {entropy:.2f} "
                    f"bits/char (threshold "
                    f"{ARGUMENT_ENTROPY_THRESHOLD_BITS_PER_CHAR}) — "
                    f"consistent with encoded or obfuscated content rather "
                    f"than natural-language text"
                ),
            )
    return None


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def detect_anomalies(
    call: CallRecord,
    *,
    session_history: Sequence[SessionHistoryEntry] = (),
    declared_tools: frozenset[str] = frozenset(),
) -> tuple[AnomalyFinding, ...]:
    """Runs every detector and returns every finding it produced, in a
    fixed order (INV-13: pure, deterministic — no detector reads anything
    but its documented inputs)."""
    findings = (
        detect_call_volume_spike(call, session_history),
        detect_tool_outside_declared_set(call, declared_tools),
        detect_high_risk_sequence(call, session_history),
        detect_argument_entropy_spike(call),
    )
    return tuple(f for f in findings if f is not None)


def apply_anomaly_findings(
    decision: Decision, findings: Sequence[AnomalyFinding]
) -> Decision:
    """Folds anomaly findings into an already-computed policy `Decision`.

    Every finding's reason is appended to `reason` regardless of severity
    — even a FLAG-only finding must be visible in the audit trail
    (INV-10/INV-11). The outcome itself only ever becomes MORE
    restrictive, never less: DENY > NEEDS_APPROVAL > ALLOW, the same
    precedence policy conflict resolution uses (ADR 0009). A finding can
    never downgrade a DENY the policy engine already returned, and a plain
    FLAG never changes the outcome at all — only ESCALATE/HALT-actioned
    findings can raise it, and only up to the outcome their action
    implies.
    """
    if not findings:
        return decision

    final_outcome = decision.outcome
    final_rule_id = decision.rule_id
    final_rank = _OUTCOME_RANK[decision.outcome]

    for finding in findings:
        implied_outcome = _ACTION_TO_OUTCOME[finding.action]
        if implied_outcome is None:
            continue
        implied_rank = _OUTCOME_RANK[implied_outcome]
        if implied_rank > final_rank:
            final_rank = implied_rank
            final_outcome = implied_outcome
            final_rule_id = f"anomaly:{finding.detector}"

    notes = "; ".join(
        f"ANOMALY[{f.detector}/{f.action.value}]: {f.reason}" for f in findings
    )
    return Decision(
        outcome=final_outcome,
        reason=f"{decision.reason} | {notes}",
        rule_id=final_rule_id,
    )
