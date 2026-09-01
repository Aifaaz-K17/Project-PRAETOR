"""Orchestrates every non-interactive demo/verification script in one
run — Phase 6.

Runs, in order: `scripts/verify_policies.py`'s check, the bypass corpus
(`scripts/run_bypass_suite.py`), and all 5 attack scenarios
(`demo_agent/attack_scenarios.py`), then prints a consolidated summary
and exit code. Deliberately excludes `demo_agent/full_demo.py` — that
one blocks on a real interactive approval prompt (INV-12), which would
defeat the point of an unattended, scriptable run; run it separately
when you want the interactive walkthrough.

Run with: python scripts/run_all_demos.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Run standalone (`python scripts/run_all_demos.py`), not as a package —
# put the repo root on sys.path so `import firewall`/`demo_agent`
# resolve regardless of the caller's current directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from demo_agent.attack_scenarios import run_all_scenarios
from firewall.policy_engine import PolicyLoadError, load_policy_set
from scripts.run_bypass_suite import run_bypass_suite

_POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"


def _step(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def _run_policy_check() -> bool:
    _step("1/3 -- policies/ loads cleanly")
    try:
        loaded = load_policy_set(_POLICIES_DIR)
    except PolicyLoadError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return False
    print(
        f"OK: {len(loaded.policy_set.rules)} rules, hash {loaded.policy_set_hash[:16]}..."
    )
    return True


def _run_bypass_suite() -> bool:
    _step("2/3 -- bypass corpus (44 entries)")
    passed, total, failures = run_bypass_suite(quiet=True)
    print(f"{passed}/{total} bypass corpus entries passed.")
    return not failures


def _run_attack_scenarios() -> bool:
    _step("3/3 -- 5 attack scenarios (baseline + firewall)")
    results = run_all_scenarios()
    all_correct = True
    for result in results:
        correct = result.blocked if result.with_firewall else not result.blocked
        all_correct = all_correct and correct
        mode = "WITH FIREWALL   " if result.with_firewall else "WITHOUT FIREWALL"
        status = "OK" if correct else "UNEXPECTED"
        print(f"[{status:10}] {result.scenario_id} ({result.threat_row}) {mode}")
        print(f"             {result.detail}")
    return all_correct


def main() -> int:
    policy_ok = _run_policy_check()
    bypass_ok = _run_bypass_suite() if policy_ok else False
    scenarios_ok = _run_attack_scenarios() if policy_ok else False

    _step("SUMMARY")
    print(f"policies/ load cleanly:  {'PASS' if policy_ok else 'FAIL'}")
    print(f"bypass corpus:            {'PASS' if bypass_ok else 'FAIL'}")
    print(f"attack scenarios:         {'PASS' if scenarios_ok else 'FAIL'}")

    if policy_ok and bypass_ok and scenarios_ok:
        print("\nAll demos passed.")
        return 0
    print("\nSome demos failed -- see above.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
