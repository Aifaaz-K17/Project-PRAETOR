"""Tests for firewall/anomaly.py — Phase 4 (rule-based anomaly detection,
folded into a Decision alongside the policy engine's own outcome).

Every detector is exercised in isolation first (its documented inputs
only), then `detect_anomalies`'s orchestration and `apply_anomaly_findings`'s
folding logic are tested independently of any one detector's specifics —
see ADR 0013 for the design rationale and honest scope limits.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from firewall.anomaly import (
    ARGUMENT_ENTROPY_MIN_LENGTH,
    ARGUMENT_ENTROPY_THRESHOLD_BITS_PER_CHAR,
    CALL_VOLUME_MAX_CALLS,
    CALL_VOLUME_WINDOW_SECONDS,
    AnomalyAction,
    AnomalyFinding,
    apply_anomaly_findings,
    detect_anomalies,
    detect_argument_entropy_spike,
    detect_call_volume_spike,
    detect_high_risk_sequence,
    detect_tool_outside_declared_set,
)
from firewall.interceptor import CallRecord, Decision, Outcome

# A 32-distinct-character string: Shannon entropy of log2(32) = 5.0 bits/char,
# comfortably above the 4.5 threshold and above the 20-char minimum length.
HIGH_ENTROPY_VALUE = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV"  # pragma: allowlist secret
assert len(HIGH_ENTROPY_VALUE) == len(set(HIGH_ENTROPY_VALUE)) == 32

LOW_ENTROPY_VALUE = "the quick brown fox jumps over the lazy dog"


def make_call(
    *,
    call_id: str = "c1",
    tool_name: str = "read_file",
    role: str = "analyst",
    args: dict | None = None,
    session_id: str = "s1",
    identity: str = "u1",
    timestamp_utc: datetime | None = None,
) -> CallRecord:
    args = args if args is not None else {}
    return CallRecord(
        call_id=call_id,
        tool_name=tool_name,
        raw_args=args,
        canonical_args=dict(args),
        session_id=session_id,
        identity=identity,
        role=role,
        timestamp_utc=timestamp_utc or datetime.now(UTC),
        timestamp_monotonic_ns=0,
        sequence_index=0,
    )


# ---------------------------------------------------------------------------
# Detector 1 — call-volume spike
# ---------------------------------------------------------------------------


def test_call_volume_spike_silent_under_threshold() -> None:
    now = datetime.now(UTC)
    history = tuple(
        ("read_file", now - timedelta(seconds=1))
        for _ in range(CALL_VOLUME_MAX_CALLS - 2)
    )
    call = make_call(timestamp_utc=now)
    assert detect_call_volume_spike(call, history) is None


def test_call_volume_spike_fires_over_threshold_within_window() -> None:
    now = datetime.now(UTC)
    history = tuple(
        ("read_file", now - timedelta(seconds=1)) for _ in range(CALL_VOLUME_MAX_CALLS)
    )
    call = make_call(timestamp_utc=now)
    finding = detect_call_volume_spike(call, history)
    assert finding is not None
    assert finding.detector == "call_volume_spike"
    assert finding.action == AnomalyAction.ESCALATE


def test_call_volume_spike_ignores_calls_outside_the_window() -> None:
    """Calls old enough to fall outside CALL_VOLUME_WINDOW_SECONDS must not
    count toward the burst threshold, no matter how many there are."""
    now = datetime.now(UTC)
    history = tuple(
        ("read_file", now - timedelta(seconds=CALL_VOLUME_WINDOW_SECONDS + 5))
        for _ in range(CALL_VOLUME_MAX_CALLS * 3)
    )
    call = make_call(timestamp_utc=now)
    assert detect_call_volume_spike(call, history) is None


# ---------------------------------------------------------------------------
# Detector 2 — tool outside declared set
# ---------------------------------------------------------------------------


def test_tool_outside_declared_set_silent_when_nothing_declared() -> None:
    call = make_call(tool_name="transfer_funds")
    assert detect_tool_outside_declared_set(call, frozenset()) is None


def test_tool_outside_declared_set_silent_when_tool_is_declared() -> None:
    call = make_call(tool_name="read_file")
    declared = frozenset({"read_file", "send_email"})
    assert detect_tool_outside_declared_set(call, declared) is None


def test_tool_outside_declared_set_halts_on_undeclared_tool() -> None:
    call = make_call(tool_name="transfer_funds")
    declared = frozenset({"read_file", "send_email"})
    finding = detect_tool_outside_declared_set(call, declared)
    assert finding is not None
    assert finding.detector == "tool_outside_declared_set"
    assert finding.action == AnomalyAction.HALT


# ---------------------------------------------------------------------------
# Detector 3 — high-risk sequence
# ---------------------------------------------------------------------------


def test_high_risk_sequence_silent_with_no_prior_calls() -> None:
    call = make_call(tool_name="send_email")
    assert detect_high_risk_sequence(call, ()) is None


def test_high_risk_sequence_silent_when_prior_tool_not_risky_for_this_one() -> None:
    now = datetime.now(UTC)
    history = (("search_web", now - timedelta(seconds=1)),)
    call = make_call(tool_name="send_email", timestamp_utc=now)
    assert detect_high_risk_sequence(call, history) is None


def test_high_risk_sequence_escalates_on_read_then_send_email() -> None:
    now = datetime.now(UTC)
    history = (("read_file", now - timedelta(seconds=1)),)
    call = make_call(tool_name="send_email", timestamp_utc=now)
    finding = detect_high_risk_sequence(call, history)
    assert finding is not None
    assert finding.detector == "high_risk_sequence"
    assert finding.action == AnomalyAction.ESCALATE


def test_high_risk_sequence_escalates_on_search_then_transfer_funds() -> None:
    now = datetime.now(UTC)
    history = (("search_web", now - timedelta(seconds=1)),)
    call = make_call(tool_name="transfer_funds", timestamp_utc=now)
    finding = detect_high_risk_sequence(call, history)
    assert finding is not None
    assert finding.detector == "high_risk_sequence"


# ---------------------------------------------------------------------------
# Detector 4 — argument entropy spike
# ---------------------------------------------------------------------------


def test_argument_entropy_spike_silent_on_natural_language() -> None:
    call = make_call(args={"query": LOW_ENTROPY_VALUE})
    assert detect_argument_entropy_spike(call) is None


def test_argument_entropy_spike_silent_below_minimum_length() -> None:
    short_high_entropy = HIGH_ENTROPY_VALUE[: ARGUMENT_ENTROPY_MIN_LENGTH - 1]
    call = make_call(args={"query": short_high_entropy})
    assert detect_argument_entropy_spike(call) is None


def test_argument_entropy_spike_flags_high_entropy_value() -> None:
    call = make_call(args={"note": HIGH_ENTROPY_VALUE})
    finding = detect_argument_entropy_spike(call)
    assert finding is not None
    assert finding.detector == "argument_entropy_spike"
    assert finding.action == AnomalyAction.FLAG
    assert "note" in finding.reason


def test_argument_entropy_spike_ignores_non_string_values() -> None:
    call = make_call(args={"amount": 123456789012345})
    assert detect_argument_entropy_spike(call) is None


def test_argument_entropy_threshold_constant_is_above_typical_prose() -> None:
    """Sanity check on the threshold itself: typical English prose must
    NOT cross it, and the curated high-entropy fixture must."""
    from firewall.anomaly import _shannon_entropy_bits_per_char

    assert (
        _shannon_entropy_bits_per_char(LOW_ENTROPY_VALUE)
        < ARGUMENT_ENTROPY_THRESHOLD_BITS_PER_CHAR
    )
    assert (
        _shannon_entropy_bits_per_char(HIGH_ENTROPY_VALUE)
        >= ARGUMENT_ENTROPY_THRESHOLD_BITS_PER_CHAR
    )


# ---------------------------------------------------------------------------
# Orchestration — detect_anomalies
# ---------------------------------------------------------------------------


def test_detect_anomalies_returns_empty_tuple_when_nothing_fires() -> None:
    call = make_call(tool_name="read_file", args={"path": "notes.txt"})
    findings = detect_anomalies(call, session_history=(), declared_tools=frozenset())
    assert findings == ()


def test_detect_anomalies_collects_findings_from_multiple_detectors_in_fixed_order() -> (
    None
):
    """A call that trips both the high-risk-sequence detector AND the
    entropy detector must report both findings, in the same fixed
    detector order every time (INV-13)."""
    now = datetime.now(UTC)
    history = (("read_file", now - timedelta(seconds=1)),)
    call = make_call(
        tool_name="send_email",
        args={"note": HIGH_ENTROPY_VALUE},
        timestamp_utc=now,
    )
    findings = detect_anomalies(
        call, session_history=history, declared_tools=frozenset()
    )
    detectors = [f.detector for f in findings]
    assert detectors == ["high_risk_sequence", "argument_entropy_spike"]


def test_detect_anomalies_is_deterministic() -> None:
    now = datetime.now(UTC)
    history = (("read_file", now - timedelta(seconds=1)),)
    call = make_call(tool_name="send_email", timestamp_utc=now)
    first = detect_anomalies(call, session_history=history, declared_tools=frozenset())
    second = detect_anomalies(call, session_history=history, declared_tools=frozenset())
    assert first == second


# ---------------------------------------------------------------------------
# apply_anomaly_findings — folding findings into a Decision
# ---------------------------------------------------------------------------


def make_decision(
    *, outcome: Outcome = Outcome.ALLOW, rule_id: str | None = "policy-rule-1"
) -> Decision:
    return Decision(outcome=outcome, reason="base reason", rule_id=rule_id)


def test_apply_anomaly_findings_no_findings_leaves_decision_untouched() -> None:
    decision = make_decision()
    result = apply_anomaly_findings(decision, ())
    assert result == decision


def test_apply_anomaly_findings_flag_only_does_not_change_outcome_but_is_recorded() -> (
    None
):
    decision = make_decision(outcome=Outcome.ALLOW)
    finding = AnomalyFinding(
        detector="argument_entropy_spike",
        action=AnomalyAction.FLAG,
        reason="high entropy",
    )
    result = apply_anomaly_findings(decision, (finding,))
    assert result.outcome == Outcome.ALLOW
    assert result.rule_id == decision.rule_id
    assert "ANOMALY[argument_entropy_spike/flag]" in result.reason
    assert "high entropy" in result.reason


def test_apply_anomaly_findings_escalate_raises_allow_to_needs_approval() -> None:
    decision = make_decision(outcome=Outcome.ALLOW)
    finding = AnomalyFinding(
        detector="call_volume_spike", action=AnomalyAction.ESCALATE, reason="burst"
    )
    result = apply_anomaly_findings(decision, (finding,))
    assert result.outcome == Outcome.NEEDS_APPROVAL
    assert result.rule_id == "anomaly:call_volume_spike"


def test_apply_anomaly_findings_halt_raises_allow_to_deny() -> None:
    decision = make_decision(outcome=Outcome.ALLOW)
    finding = AnomalyFinding(
        detector="tool_outside_declared_set",
        action=AnomalyAction.HALT,
        reason="undeclared",
    )
    result = apply_anomaly_findings(decision, (finding,))
    assert result.outcome == Outcome.DENY
    assert result.rule_id == "anomaly:tool_outside_declared_set"


def test_apply_anomaly_findings_never_downgrades_an_existing_deny() -> None:
    """A FLAG- or ESCALATE-actioned finding must never soften a DENY the
    policy engine already returned — anomaly findings can only make the
    outcome MORE restrictive, never less."""
    decision = make_decision(outcome=Outcome.DENY, rule_id="policy-deny-rule")
    finding = AnomalyFinding(
        detector="argument_entropy_spike",
        action=AnomalyAction.FLAG,
        reason="high entropy",
    )
    result = apply_anomaly_findings(decision, (finding,))
    assert result.outcome == Outcome.DENY
    assert result.rule_id == "policy-deny-rule"


def test_apply_anomaly_findings_escalate_does_not_downgrade_an_existing_deny() -> None:
    decision = make_decision(outcome=Outcome.DENY, rule_id="policy-deny-rule")
    finding = AnomalyFinding(
        detector="call_volume_spike", action=AnomalyAction.ESCALATE, reason="burst"
    )
    result = apply_anomaly_findings(decision, (finding,))
    assert result.outcome == Outcome.DENY
    assert result.rule_id == "policy-deny-rule"


def test_apply_anomaly_findings_multiple_findings_take_the_most_restrictive() -> None:
    decision = make_decision(outcome=Outcome.ALLOW)
    flag = AnomalyFinding(
        detector="argument_entropy_spike", action=AnomalyAction.FLAG, reason="entropy"
    )
    escalate = AnomalyFinding(
        detector="call_volume_spike", action=AnomalyAction.ESCALATE, reason="burst"
    )
    halt = AnomalyFinding(
        detector="tool_outside_declared_set",
        action=AnomalyAction.HALT,
        reason="undeclared",
    )
    result = apply_anomaly_findings(decision, (flag, escalate, halt))
    assert result.outcome == Outcome.DENY
    assert result.rule_id == "anomaly:tool_outside_declared_set"
    # every finding's reason must still be visible in the audit trail,
    # even the ones that didn't decide the final outcome (INV-10/INV-11)
    assert "ANOMALY[argument_entropy_spike/flag]" in result.reason
    assert "ANOMALY[call_volume_spike/escalate]" in result.reason
    assert "ANOMALY[tool_outside_declared_set/halt]" in result.reason
