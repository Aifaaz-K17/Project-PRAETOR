"""Tests for demo_agent/attack_scenarios.py — Phase 6.

Codifies what `python -m demo_agent.attack_scenarios`'s manual run
already demonstrates: every scenario's `--no-firewall` baseline must
actually succeed (proving the vulnerability is real, not theoretical),
and every scenario's `with_firewall=True` run must actually be blocked.
If either flips, the scenario is no longer demonstrating what it claims
to.
"""

from __future__ import annotations

import pytest

from demo_agent.attack_scenarios import (
    ALL_SCENARIOS,
    scenario_1_path_traversal,
    scenario_2_exfiltration_to_attacker_domain,
    scenario_3_privilege_escalation,
    scenario_4_out_of_order_action,
    scenario_5_resource_exhaustion,
)


def test_all_scenarios_tuple_has_exactly_5_entries() -> None:
    assert len(ALL_SCENARIOS) == 5


@pytest.mark.parametrize(
    "scenario",
    [
        scenario_1_path_traversal,
        scenario_2_exfiltration_to_attacker_domain,
        scenario_3_privilege_escalation,
        scenario_4_out_of_order_action,
        scenario_5_resource_exhaustion,
    ],
    ids=[
        "scenario_1_path_traversal",
        "scenario_2_exfiltration",
        "scenario_3_privilege_escalation",
        "scenario_4_out_of_order",
        "scenario_5_resource_exhaustion",
    ],
)
def test_baseline_attack_succeeds_without_the_firewall(scenario) -> None:  # type: ignore[no-untyped-def]
    """The whole point of the --no-firewall baseline: the attack must
    genuinely succeed when unmediated, proving the vulnerability is
    real. If a baseline ever gets blocked, the mock tool has picked up
    validation of its own (defeating the comparison) — see
    demo_agent/tools.py's module docstring for why that's deliberately
    avoided."""
    result = scenario(with_firewall=False)
    assert result.blocked is False, (
        f"{result.scenario_id} baseline was blocked, but the mock tools "
        f"must have no validation of their own: {result.detail}"
    )


@pytest.mark.parametrize(
    "scenario",
    [
        scenario_1_path_traversal,
        scenario_2_exfiltration_to_attacker_domain,
        scenario_3_privilege_escalation,
        scenario_4_out_of_order_action,
        scenario_5_resource_exhaustion,
    ],
    ids=[
        "scenario_1_path_traversal",
        "scenario_2_exfiltration",
        "scenario_3_privilege_escalation",
        "scenario_4_out_of_order",
        "scenario_5_resource_exhaustion",
    ],
)
def test_attack_is_blocked_with_the_firewall(scenario) -> None:  # type: ignore[no-untyped-def]
    result = scenario(with_firewall=True)
    assert result.blocked is True, f"{result.scenario_id}: {result.detail}"


def test_scenario_3_is_blocked_by_rbac_specifically_not_the_amount_bound() -> None:
    """Scenario 3 (T-6, privilege escalation) must demonstrate an
    intern's transfer_funds attempt failing for lack of RBAC access
    specifically — using a small, in-bounds amount so the block can't be
    coincidentally attributed to the unrelated amount-bound rule."""
    result = scenario_3_privilege_escalation(with_firewall=True)
    assert "default_action=deny" in result.detail


def test_scenario_5_rate_limit_allows_exactly_3_before_blocking() -> None:
    """rate-transfer-funds caps at 3 calls per rolling 60s — the 4th
    rapid-fire call must be the one that gets blocked, not earlier."""
    result = scenario_5_resource_exhaustion(with_firewall=True)
    assert "allowed" in result.detail
    assert result.detail.count("allowed") == 3
