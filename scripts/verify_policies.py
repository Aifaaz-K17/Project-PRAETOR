"""Validate every YAML file under policies/ against the policy schema.

Loads each file with yaml.safe_load (never yaml.load — CLAUDE.md forbidden
actions), checks it against the Pydantic policy models, confirms every
rule regex compiles cleanly (rejecting obvious ReDoS shapes at load time —
INV-09), and prints the SHA-256 hash Praetor pins at startup (INV-03) so
it can be compared against what a running process reports, or recorded
alongside an audit log for exact reproducibility.

Run this after editing anything under policies/, and in CI before any
demo — a malformed or unsafe policy file must be caught here, not at the
first real tool call.
"""

import argparse
import sys
from pathlib import Path

# Run standalone (`python scripts/verify_policies.py`), not as a package —
# put the repo root on sys.path so `import firewall...` resolves regardless
# of the caller's current directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from firewall.policy_engine import PolicyLoadError, load_policy_set
from firewall.policy_schema import RuleAction


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policies-dir",
        default="policies",
        help="Directory containing policy YAML files.",
    )
    args = parser.parse_args()

    try:
        loaded = load_policy_set(args.policies_dir)
    except PolicyLoadError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1

    print(f"OK: {args.policies_dir} loaded cleanly.")
    print(f"  Rules: {len(loaded.policy_set.rules)}")
    print(f"  Default action: {loaded.policy_set.default_action.value}")
    print(f"  Regex patterns compiled: {len(loaded.compiled_patterns)}")
    print(f"  Policy set hash (SHA-256): {loaded.policy_set_hash}")

    rules_by_tool: dict[str, list[str]] = {}
    for rule in loaded.policy_set.rules:
        rules_by_tool.setdefault(rule.tool, []).append(rule.id)
    print(f"  Tools covered: {', '.join(sorted(rules_by_tool)) or '(none)'}")

    deny_count = sum(1 for r in loaded.policy_set.rules if r.action == RuleAction.DENY)
    approval_count = sum(1 for r in loaded.policy_set.rules if r.requires_approval)
    print(f"  Deny-shaped rules: {deny_count}")
    print(f"  Rules requiring approval: {approval_count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
