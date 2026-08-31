"""Human-in-the-loop approval — Phase 5 (INV-12).

`evaluate_call` (Phase 3) can return `NEEDS_APPROVAL` — a call that policy
doesn't want to auto-allow, but also doesn't want to auto-deny. Through
Phase 4, nothing resolved that state: `Decision.allowed` treats
`NEEDS_APPROVAL` the same as `DENY` at the interceptor level, which is
fail-closed-correct in the *absence* of a real approval mechanism, but
means NEEDS_APPROVAL-gated tools (`compose_draft` for `intern`, emailing
`partner.example.org`) were never actually reachable. This module is that
mechanism: a blocking CLI prompt, out-of-band from the agent.

INV-12's four requirements, each mapped to what's actually built here:
- "The approval channel is not reachable by any agent tool" — the
  channel reads/writes the *process's own* stdin/stdout. Nothing
  reachable from a `GuardedTool`/`firewall_guard`-wrapped function ever
  gets a reference to a `HitlChannel` or `HitlApprover` — it's wired in
  at registry-construction time, the same trust boundary as `Evaluator`.
- "Agent-controlled text shown to the approver is escaped (strip
  ANSI/CR/LF, truncate, quote)" — `sanitize_for_display`.
- "Approval timeout -> DENY" — `CliApprovalChannel`'s reader-thread +
  `queue.Queue(timeout=...)` pattern; `HitlApprover` maps a timeout to a
  DENY `Decision`, never to ALLOW or to re-raising.
- "Approval is bound to a call-ID and single-use" — `HitlApprover`
  tracks consumed `call_id`s under a lock; asking twice for the same
  `call_id` is refused (denied), not re-prompted or reused.

Structural typing, not inheritance: `firewall.interceptor.HitlResolver`
is the `Protocol` `HitlApprover` implements (mirrors `Evaluator`'s own
pattern) — this file imports from `firewall.interceptor`, and
`interceptor.py` never imports this file, avoiding a circular import
while still type-checking the wiring.
"""

from __future__ import annotations

import dataclasses
import queue
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Protocol, TextIO

from firewall.interceptor import CallRecord, Decision, Outcome
from firewall.logger import AuditLogger

# ---------------------------------------------------------------------------
# Sanitized rendering (INV-12: strip ANSI/CR/LF, truncate, quote)
# ---------------------------------------------------------------------------

# Every C0 control character (0x00-0x1F) plus DEL (0x7F). This is
# deliberately the same range firewall/canonicalize.py strips for the
# same underlying reason, applied here to a different problem: it
# removes CR/LF (which could otherwise inject a fake extra line into the
# approval prompt — e.g. a forged "APPROVED" line the human never typed)
# and the ESC byte (0x1B) that begins every ANSI escape sequence (which
# could otherwise repaint the terminal — move the cursor, clear the
# DENY/APPROVE prompt line, change colors to disguise the request) before
# any of it reaches a human's real terminal.
_DISPLAY_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

DEFAULT_DISPLAY_MAX_LENGTH = 200


def sanitize_for_display(
    value: object, *, max_length: int = DEFAULT_DISPLAY_MAX_LENGTH
) -> str:
    """Render an arbitrary, agent-controlled value safely for a human
    approver's terminal. Strips every C0 control character, truncates to
    `max_length` with a marker (never silently — a cut-off value could
    otherwise hide a denylisted phrase past the visible portion), and
    wraps the result in double quotes so where the value ends and the
    rest of the prompt begins is never ambiguous to a skimming human.
    """
    text = str(value)
    cleaned = _DISPLAY_CONTROL_CHAR_RE.sub("", text)
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + f"...(truncated from {len(text)} chars)"
    return f'"{cleaned}"'


def render_call_for_approval(call: CallRecord, decision: Decision) -> str:
    """The full sanitized prompt body shown to a human approver — every
    agent-controlled field goes through `sanitize_for_display`."""
    lines = [
        "=" * 70,
        "APPROVAL REQUIRED",
        f"  call_id:  {call.call_id}",
        f"  tool:     {sanitize_for_display(call.tool_name)}",
        f"  session:  {sanitize_for_display(call.session_id)}",
        f"  identity: {sanitize_for_display(call.identity)}",
        f"  role:     {sanitize_for_display(call.role)}",
        f"  reason:   {sanitize_for_display(decision.reason)}",
        f"  rule:     {sanitize_for_display(decision.rule_id or '(none)')}",
        "  arguments:",
    ]
    for key, value in call.canonical_args.items():
        lines.append(f"    {sanitize_for_display(key)}: {sanitize_for_display(value)}")
    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# The approval channel — what actually asks a human and gets an answer
# ---------------------------------------------------------------------------


class ApprovalOutcome(str, Enum):
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    TIMED_OUT = "TIMED_OUT"


@dataclass(frozen=True)
class ApprovalResult:
    outcome: ApprovalOutcome
    reason: str


class HitlChannel(Protocol):
    """What actually renders a request and blocks for a human answer.
    Structural typing (same pattern as `Evaluator`) so tests can
    substitute a scripted channel without touching real stdin/stdout."""

    def request_approval(
        self, call: CallRecord, decision: Decision, *, timeout_seconds: float
    ) -> ApprovalResult: ...


DEFAULT_APPROVAL_TIMEOUT_SECONDS = 120.0


class CliApprovalChannel:
    """Blocking terminal `y/n` prompt (ADR 0005's primary mechanism).

    Reads a line from `input_stream` on a background daemon thread and
    waits on it with a timeout via `queue.Queue.get(timeout=...)` —
    `input()`/`readline()` has no built-in cross-platform timeout, and
    `select.select` on stdin doesn't work reliably on Windows console
    input, so a reader thread plus a bounded queue wait is the portable
    way to get "block for an answer, but not forever." The reader thread
    itself is not cancelled on timeout (Python has no safe way to
    interrupt a blocking `readline()` call) — it stays blocked on
    `input_stream` until the process exits or a line eventually arrives,
    which it then discards. This is a real, documented, and in a CLI
    demo tool low-cost tradeoff — see LIMITATIONS.md.
    """

    def __init__(
        self,
        *,
        input_stream: TextIO | None = None,
        output_stream: TextIO | None = None,
    ) -> None:
        self._input_stream = input_stream if input_stream is not None else sys.stdin
        self._output_stream = output_stream if output_stream is not None else sys.stdout

    def request_approval(
        self, call: CallRecord, decision: Decision, *, timeout_seconds: float
    ) -> ApprovalResult:
        print(
            render_call_for_approval(call, decision),
            file=self._output_stream,
            flush=True,
        )
        print(
            f"Approve this call? [y/N] (times out in {timeout_seconds:.0f}s): ",
            file=self._output_stream,
            end="",
            flush=True,
        )

        answer_queue: queue.Queue[str] = queue.Queue(maxsize=1)

        def _read_one_line() -> None:
            try:
                line = self._input_stream.readline()
            except Exception:  # noqa: BLE001 - any stdin failure is a non-answer
                line = ""
            answer_queue.put(line)

        reader = threading.Thread(target=_read_one_line, daemon=True)
        reader.start()

        try:
            raw_answer = answer_queue.get(timeout=timeout_seconds)
        except queue.Empty:
            print(
                "\n(timed out waiting for an answer)",
                file=self._output_stream,
                flush=True,
            )
            return ApprovalResult(
                outcome=ApprovalOutcome.TIMED_OUT,
                reason=f"no answer within {timeout_seconds:.0f}s",
            )

        answer = raw_answer.strip().lower()
        if answer in ("y", "yes"):
            return ApprovalResult(
                outcome=ApprovalOutcome.APPROVED, reason="human approved"
            )
        return ApprovalResult(
            outcome=ApprovalOutcome.DENIED,
            reason=(
                f"human denied (answered {answer!r})"
                if answer
                else "human denied (no input)"
            ),
        )


# ---------------------------------------------------------------------------
# HitlApprover — resolves NEEDS_APPROVAL into a final ALLOW/DENY Decision
# ---------------------------------------------------------------------------


@dataclass
class HitlApprover:
    """Implements `firewall.interceptor.HitlResolver` structurally (has a
    `resolve_approval` method) — pass an instance of this as
    `GuardedToolRegistry(..., hitl_resolver=...)` or
    `firewall_guard(..., hitl_resolver=...)` to make NEEDS_APPROVAL calls
    actually reachable instead of being treated as DENY.

    `timeout_seconds` and `channel` are the only required knobs;
    `audit_logger`, if given, gets a second, separate audit row per
    resolved approval (see `_log_resolution`'s docstring for why this is
    a second row, never an edit to the first).
    """

    channel: HitlChannel
    timeout_seconds: float = DEFAULT_APPROVAL_TIMEOUT_SECONDS
    audit_logger: AuditLogger | None = None
    _consumed_call_ids: set[str] = field(default_factory=set, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def resolve_approval(self, call: CallRecord, decision: Decision) -> Decision:
        """Not our concern unless `decision.outcome` is NEEDS_APPROVAL —
        anything else passes through unchanged, so this can be wired in
        unconditionally without affecting ALLOW/DENY decisions at all.
        """
        if decision.outcome != Outcome.NEEDS_APPROVAL:
            return decision

        with self._lock:
            already_consumed = call.call_id in self._consumed_call_ids
            if not already_consumed:
                self._consumed_call_ids.add(call.call_id)

        if already_consumed:
            # INV-12: "single-use" — a second resolution attempt for the
            # same call_id (a retry bug, a duplicated call_id from a
            # compromised code path) is refused outright, not re-prompted
            # and not silently reusing whatever the first answer was.
            return Decision.deny(
                reason="HITL_ERROR: approval already consumed for this call_id (single-use)",
                rule_id="hitl:replay-refused",
            )

        started_at_ns = time.perf_counter_ns()
        try:
            result = self.channel.request_approval(
                call, decision, timeout_seconds=self.timeout_seconds
            )
        except Exception as exc:  # noqa: BLE001 - INV-01: a channel failure is a DENY
            result = ApprovalResult(
                outcome=ApprovalOutcome.DENIED,
                reason=f"HITL_ERROR: {type(exc).__name__}: {exc}",
            )
        latency_ns = time.perf_counter_ns() - started_at_ns

        final_decision = self._to_decision(result, original=decision)
        self._log_resolution(call, final_decision, latency_ns)
        return final_decision

    @staticmethod
    def _to_decision(result: ApprovalResult, *, original: Decision) -> Decision:
        if result.outcome == ApprovalOutcome.APPROVED:
            return Decision.allow(
                reason=f"HITL approved: {result.reason} (was: {original.reason})",
                rule_id="hitl:approved",
            )
        rule_id = (
            "hitl:timed_out"
            if result.outcome == ApprovalOutcome.TIMED_OUT
            else "hitl:denied"
        )
        return Decision.deny(
            reason=f"HITL denied: {result.reason} (was: {original.reason})",
            rule_id=rule_id,
        )

    def _log_resolution(
        self, call: CallRecord, final_decision: Decision, latency_ns: int
    ) -> None:
        """Writes a second audit row for this call_id, never edits the
        first. `AuditLogRow.call_id` is unique, and INV-10's hash chain
        makes editing an existing row structurally impossible anyway (it
        would break every row's hash after it) — so the original
        NEEDS_APPROVAL row (written by whatever logged the policy
        decision, e.g. PolicyEngine) stands as-is, documenting "what
        policy said," and this row, suffixed `:hitl`, documents "what
        actually happened" once a human answered.
        """
        if self.audit_logger is None:
            return
        follow_up_call = dataclasses.replace(
            call,
            call_id=f"{call.call_id}:hitl",
            timestamp_utc=datetime.now(UTC),
        )
        self.audit_logger.log_call(
            call=follow_up_call, decision=final_decision, latency_ns=latency_ns
        )
