"""Tests for firewall/hitl.py — Phase 5 (INV-12: out-of-band human
approval). Covers the module directly (sanitized rendering, the CLI
channel, HitlApprover's resolution/single-use/timeout logic) and the
interceptor wiring end-to-end (a NEEDS_APPROVAL decision actually
reaching a human, and the tool executing or not based on the answer).

Threat-model rows this file exists to cover (docs/THREAT_MODEL.md):
T-14 (forge the approval prompt via ANSI/CR injection) and T-15
(approval replay/reuse) — both named there as `test_INV_12_*`.
"""

from __future__ import annotations

import asyncio
import io
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from langchain_core.tools import tool

from firewall.context import Principal, bind_principal
from firewall.hitl import (
    DEFAULT_APPROVAL_TIMEOUT_SECONDS,
    ApprovalOutcome,
    ApprovalResult,
    CliApprovalChannel,
    HitlApprover,
    render_call_for_approval,
    sanitize_for_display,
)
from firewall.interceptor import (
    CallRecord,
    Decision,
    GuardedToolRegistry,
    Outcome,
    ToolCallDenied,
    firewall_guard,
)
from firewall.logger import AuditLogger, AuditLogRow
from tests._evaluators import AllowAllEvaluator, NeedsApprovalEvaluator

ANALYST = Principal(session_id="session-1", identity="user-1", role="analyst")


def make_call(
    *,
    call_id: str = "c1",
    tool_name: str = "transfer_funds",
    args: dict | None = None,
) -> CallRecord:
    args = args if args is not None else {}
    return CallRecord(
        call_id=call_id,
        tool_name=tool_name,
        raw_args=args,
        canonical_args=dict(args),
        session_id="s1",
        identity="u1",
        role="analyst",
        timestamp_utc=datetime.now(UTC),
        timestamp_monotonic_ns=0,
        sequence_index=0,
    )


def make_needs_approval_decision(rule_id: str = "policy-rule") -> Decision:
    return Decision.needs_approval(reason="policy requires approval", rule_id=rule_id)


# ---------------------------------------------------------------------------
# sanitize_for_display / render_call_for_approval (INV-12, T-14)
# ---------------------------------------------------------------------------


def test_INV_12_ansi_escape_sequence_stripped_from_display() -> None:
    """A value containing the ESC byte (start of any ANSI escape
    sequence — could otherwise repaint the terminal or hide the actual
    request) must never reach the rendered output."""
    hostile = "safe-looking\x1b[2J\x1b[31mFAKE DANGER TEXT"
    rendered = sanitize_for_display(hostile)
    assert "\x1b" not in rendered


def test_INV_12_cr_lf_stripped_from_display() -> None:
    """A value containing CR/LF must not be able to inject a fake extra
    line into the approval prompt (e.g. a forged 'human answered: y'
    line the real human never typed)."""
    hostile = "innocent argument\r\nApprove this call? [y/N]: y"
    rendered = sanitize_for_display(hostile)
    assert "\r" not in rendered
    assert "\n" not in rendered


def test_sanitize_for_display_truncates_long_values_with_a_marker() -> None:
    long_value = "a" * 500
    rendered = sanitize_for_display(long_value, max_length=50)
    assert "truncated from 500 chars" in rendered
    assert len(rendered) < 500


def test_sanitize_for_display_quotes_the_result() -> None:
    rendered = sanitize_for_display("hello")
    assert rendered == '"hello"'


def test_sanitize_for_display_handles_non_string_values() -> None:
    assert sanitize_for_display(12345) == '"12345"'
    assert sanitize_for_display(None) == '"None"'


def test_render_call_for_approval_includes_sanitized_fields() -> None:
    call = make_call(args={"amount": 99999, "note": "urgent\x1b[31m wire transfer"})
    decision = make_needs_approval_decision()
    rendered = render_call_for_approval(call, decision)
    assert "APPROVAL REQUIRED" in rendered
    assert call.call_id in rendered
    assert "transfer_funds" in rendered
    assert "\x1b" not in rendered


# ---------------------------------------------------------------------------
# CliApprovalChannel — the blocking terminal y/n prompt
# ---------------------------------------------------------------------------


def test_cli_channel_approves_on_y() -> None:
    channel = CliApprovalChannel(
        input_stream=io.StringIO("y\n"), output_stream=io.StringIO()
    )
    result = channel.request_approval(
        make_call(), make_needs_approval_decision(), timeout_seconds=5.0
    )
    assert result.outcome == ApprovalOutcome.APPROVED


def test_cli_channel_approves_on_yes_case_insensitive() -> None:
    channel = CliApprovalChannel(
        input_stream=io.StringIO("YES\n"), output_stream=io.StringIO()
    )
    result = channel.request_approval(
        make_call(), make_needs_approval_decision(), timeout_seconds=5.0
    )
    assert result.outcome == ApprovalOutcome.APPROVED


@pytest.mark.parametrize("answer", ["n\n", "no\n", "garbage\n", "\n", ""])
def test_cli_channel_denies_on_anything_but_yes(answer: str) -> None:
    channel = CliApprovalChannel(
        input_stream=io.StringIO(answer), output_stream=io.StringIO()
    )
    result = channel.request_approval(
        make_call(), make_needs_approval_decision(), timeout_seconds=5.0
    )
    assert result.outcome == ApprovalOutcome.DENIED


class _NeverAnswersStream:
    """Simulates a human who never responds — readline() blocks far
    longer than any test's timeout_seconds, proving the channel's
    timeout actually fires rather than hanging the test."""

    def readline(self) -> str:
        time.sleep(5.0)
        return "y\n"


def test_INV_12_cli_channel_timeout_denies_not_hangs() -> None:
    channel = CliApprovalChannel(
        input_stream=_NeverAnswersStream(), output_stream=io.StringIO()
    )
    started = time.monotonic()
    result = channel.request_approval(
        make_call(), make_needs_approval_decision(), timeout_seconds=0.1
    )
    elapsed = time.monotonic() - started
    assert result.outcome == ApprovalOutcome.TIMED_OUT
    assert elapsed < 4.0  # proves it didn't wait for the 5s readline


def test_default_approval_timeout_is_a_positive_number_of_seconds() -> None:
    assert DEFAULT_APPROVAL_TIMEOUT_SECONDS > 0


# ---------------------------------------------------------------------------
# HitlApprover — resolving NEEDS_APPROVAL into a final Decision
# ---------------------------------------------------------------------------


class _ScriptedChannel:
    """A HitlChannel test double that returns one pre-scripted answer per
    call and records every call it received."""

    def __init__(self, results: list[ApprovalResult]) -> None:
        self._results = list(results)
        self.requests: list[CallRecord] = []

    def request_approval(
        self, call: CallRecord, decision: Decision, *, timeout_seconds: float
    ) -> ApprovalResult:
        self.requests.append(call)
        return self._results.pop(0)


class _CrashingChannel:
    def request_approval(
        self, call: CallRecord, decision: Decision, *, timeout_seconds: float
    ) -> ApprovalResult:
        raise RuntimeError("simulated channel crash")


def test_hitl_approver_passes_through_non_needs_approval_decisions_untouched() -> None:
    channel = _ScriptedChannel([])
    approver = HitlApprover(channel=channel)
    allow_decision = Decision.allow(reason="policy allowed", rule_id="r1")

    result = approver.resolve_approval(make_call(), allow_decision)

    assert result == allow_decision
    assert channel.requests == []  # never consulted -- not its concern


def test_hitl_approver_approved_yields_allow_decision() -> None:
    channel = _ScriptedChannel(
        [ApprovalResult(outcome=ApprovalOutcome.APPROVED, reason="human said yes")]
    )
    approver = HitlApprover(channel=channel)

    result = approver.resolve_approval(make_call(), make_needs_approval_decision())

    assert result.outcome == Outcome.ALLOW
    assert result.rule_id == "hitl:approved"


def test_hitl_approver_denied_yields_deny_decision() -> None:
    channel = _ScriptedChannel(
        [ApprovalResult(outcome=ApprovalOutcome.DENIED, reason="human said no")]
    )
    approver = HitlApprover(channel=channel)

    result = approver.resolve_approval(make_call(), make_needs_approval_decision())

    assert result.outcome == Outcome.DENY
    assert result.rule_id == "hitl:denied"


def test_INV_12_hitl_approver_timeout_yields_deny_decision() -> None:
    channel = _ScriptedChannel(
        [
            ApprovalResult(
                outcome=ApprovalOutcome.TIMED_OUT, reason="no answer within 5s"
            )
        ]
    )
    approver = HitlApprover(channel=channel)

    result = approver.resolve_approval(make_call(), make_needs_approval_decision())

    assert result.outcome == Outcome.DENY
    assert result.rule_id == "hitl:timed_out"


def test_INV_01_hitl_approver_channel_crash_fails_closed() -> None:
    approver = HitlApprover(channel=_CrashingChannel())

    result = approver.resolve_approval(make_call(), make_needs_approval_decision())

    assert result.outcome == Outcome.DENY
    assert "HITL_ERROR" in result.reason


def test_INV_12_approval_replay_refused_for_same_call_id() -> None:
    """Single-use: a second resolution attempt for the same call_id must
    be refused outright, not re-prompted and not silently reusing the
    first answer — even when the first answer was APPROVED."""
    channel = _ScriptedChannel(
        [ApprovalResult(outcome=ApprovalOutcome.APPROVED, reason="human said yes")]
    )
    approver = HitlApprover(channel=channel)
    call = make_call(call_id="same-call-id")
    decision = make_needs_approval_decision()

    first = approver.resolve_approval(call, decision)
    second = approver.resolve_approval(call, decision)

    assert first.outcome == Outcome.ALLOW
    assert second.outcome == Outcome.DENY
    assert second.rule_id == "hitl:replay-refused"
    assert len(channel.requests) == 1  # the channel was never asked twice


def test_hitl_approver_different_call_ids_each_get_a_fresh_prompt() -> None:
    channel = _ScriptedChannel(
        [
            ApprovalResult(outcome=ApprovalOutcome.APPROVED, reason="yes"),
            ApprovalResult(outcome=ApprovalOutcome.APPROVED, reason="yes"),
        ]
    )
    approver = HitlApprover(channel=channel)
    decision = make_needs_approval_decision()

    first = approver.resolve_approval(make_call(call_id="call-1"), decision)
    second = approver.resolve_approval(make_call(call_id="call-2"), decision)

    assert first.outcome == Outcome.ALLOW
    assert second.outcome == Outcome.ALLOW
    assert len(channel.requests) == 2


def test_INV_10_hitl_approver_logs_a_second_audit_row_suffixed_hitl(
    tmp_path: Path,
) -> None:
    """The HITL resolution is logged as a SECOND row (call_id suffixed
    `:hitl`), never an edit to the original NEEDS_APPROVAL row — editing
    an existing row would break the hash chain (INV-10)."""
    channel = _ScriptedChannel(
        [ApprovalResult(outcome=ApprovalOutcome.APPROVED, reason="human said yes")]
    )
    with AuditLogger(tmp_path / "audit.db", policy_set_hash="hash1") as logger:
        approver = HitlApprover(channel=channel, audit_logger=logger)
        approver.resolve_approval(
            make_call(call_id="orig-call"), make_needs_approval_decision()
        )

        with logger._session_factory() as session:
            from sqlalchemy import select

            rows = (
                session.execute(select(AuditLogRow).order_by(AuditLogRow.id))
                .scalars()
                .all()
            )

    assert len(rows) == 1
    assert rows[0].call_id == "orig-call:hitl"
    assert rows[0].outcome == "ALLOW"


def test_hitl_approver_without_audit_logger_does_not_crash() -> None:
    channel = _ScriptedChannel(
        [ApprovalResult(outcome=ApprovalOutcome.APPROVED, reason="yes")]
    )
    approver = HitlApprover(channel=channel)  # audit_logger defaults to None
    result = approver.resolve_approval(make_call(), make_needs_approval_decision())
    assert result.outcome == Outcome.ALLOW


# ---------------------------------------------------------------------------
# Interceptor wiring — total mediation includes the HITL step (INV-02)
# ---------------------------------------------------------------------------


@tool
def wire_transfer_tool(amount: int) -> str:
    """Mocked high-risk tool, gated behind NEEDS_APPROVAL in these tests."""
    return f"transferred {amount}"


def test_needs_approval_without_a_hitl_resolver_still_denies() -> None:
    """Backward-compatible default (unchanged since Phase 3): with no
    hitl_resolver wired in, NEEDS_APPROVAL is left as NEEDS_APPROVAL —
    `Decision.allowed` is what treats it as not-allowed, fail-closed in
    the absence of a real approval mechanism (the interceptor doesn't
    silently rewrite the outcome to DENY; it just refuses to execute)."""
    registry = GuardedToolRegistry(NeedsApprovalEvaluator())
    guarded = registry.register(wire_transfer_tool)

    with bind_principal(ANALYST), pytest.raises(ToolCallDenied) as exc_info:
        guarded.invoke({"amount": 100})

    assert exc_info.value.decision.outcome == Outcome.NEEDS_APPROVAL
    assert exc_info.value.decision.allowed is False


def test_INV_12_needs_approval_with_approving_hitl_resolver_executes_the_tool() -> None:
    channel = _ScriptedChannel(
        [ApprovalResult(outcome=ApprovalOutcome.APPROVED, reason="human said yes")]
    )
    approver = HitlApprover(channel=channel)
    registry = GuardedToolRegistry(NeedsApprovalEvaluator(), hitl_resolver=approver)
    guarded = registry.register(wire_transfer_tool)

    with bind_principal(ANALYST):
        result = guarded.invoke({"amount": 100})

    assert result == "transferred 100"
    assert len(channel.requests) == 1


def test_INV_12_needs_approval_with_denying_hitl_resolver_raises_tool_call_denied() -> (
    None
):
    channel = _ScriptedChannel(
        [ApprovalResult(outcome=ApprovalOutcome.DENIED, reason="human said no")]
    )
    approver = HitlApprover(channel=channel)
    registry = GuardedToolRegistry(NeedsApprovalEvaluator(), hitl_resolver=approver)
    guarded = registry.register(wire_transfer_tool)

    with bind_principal(ANALYST), pytest.raises(ToolCallDenied) as exc_info:
        guarded.invoke({"amount": 100})

    assert exc_info.value.decision.rule_id == "hitl:denied"


def test_hitl_resolver_is_not_consulted_for_an_allowed_call() -> None:
    """An ALLOW decision never touches the hitl_resolver at all — proves
    the wiring is additive and doesn't slow down or affect the ordinary
    allow path."""
    channel = _ScriptedChannel([])
    approver = HitlApprover(channel=channel)
    registry = GuardedToolRegistry(AllowAllEvaluator(), hitl_resolver=approver)
    guarded = registry.register(wire_transfer_tool)

    with bind_principal(ANALYST):
        result = guarded.invoke({"amount": 100})

    assert result == "transferred 100"
    assert channel.requests == []


def test_firewall_guard_decorator_wires_hitl_resolver_sync() -> None:
    channel = _ScriptedChannel(
        [ApprovalResult(outcome=ApprovalOutcome.APPROVED, reason="yes")]
    )
    approver = HitlApprover(channel=channel)

    @firewall_guard(NeedsApprovalEvaluator(), hitl_resolver=approver)
    def guarded_transfer(amount: int) -> str:
        return f"transferred {amount}"

    with bind_principal(ANALYST):
        result = guarded_transfer(amount=250)

    assert result == "transferred 250"


def test_firewall_guard_decorator_wires_hitl_resolver_async() -> None:
    channel = _ScriptedChannel(
        [ApprovalResult(outcome=ApprovalOutcome.DENIED, reason="no")]
    )
    approver = HitlApprover(channel=channel)

    @firewall_guard(NeedsApprovalEvaluator(), hitl_resolver=approver)
    async def guarded_transfer(amount: int) -> str:
        return f"transferred {amount}"

    async def run() -> str:
        with bind_principal(ANALYST):
            return await guarded_transfer(amount=250)

    with pytest.raises(ToolCallDenied):
        asyncio.run(run())


def test_INV_01_hitl_resolver_returning_wrong_type_fails_closed() -> None:
    class BrokenResolver:
        def resolve_approval(self, call: CallRecord, decision: Decision) -> Decision:
            return "not a Decision"  # type: ignore[return-value]

    registry = GuardedToolRegistry(
        NeedsApprovalEvaluator(), hitl_resolver=BrokenResolver()
    )
    guarded = registry.register(wire_transfer_tool)

    with bind_principal(ANALYST), pytest.raises(ToolCallDenied) as exc_info:
        guarded.invoke({"amount": 100})

    assert "FIREWALL_ERROR" in exc_info.value.decision.reason
