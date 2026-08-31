"""Validate every YAML file under policies/ against the policy schema.

Loads each file with yaml.safe_load (never yaml.load — CLAUDE.md forbidden
actions), checks it against the Pydantic policy models, confirms rule
regexes compile within the complexity/timeout bounds (INV-09), and prints
the SHA-256 hash Praetor would pin at startup (INV-03).

STATUS: stub. firewall/policy_engine does not exist yet, so there are no
Pydantic models to validate against. Exits non-zero rather than reporting a
false "all policies valid".
"""

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policies-dir",
        default="policies",
        help="Directory containing policy YAML files.",
    )
    args = parser.parse_args()

    policy_files = sorted(Path(args.policies_dir).glob("*.yml")) + sorted(
        Path(args.policies_dir).glob("*.yaml")
    )
    print(
        f"verify_policies.py: not yet implemented — firewall/policy_engine "
        f"does not exist. Found {len(policy_files)} YAML file(s) in "
        f"{args.policies_dir}, none validated.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
