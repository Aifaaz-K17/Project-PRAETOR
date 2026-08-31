"""Verify the audit log hash chain (INV-10).

Walks every row in the audit database in order, recomputes each entry's
SHA-256 over its canonical JSON, and confirms it matches the stored
`entry_hash` and that `prev_hash` matches the previous row's `entry_hash`.
Any mismatch means a row was edited, deleted, or reordered after the fact.

The actual walk-and-recompute logic lives in `firewall.logger.verify_chain`
(shared with `tests/test_logger.py`, which proves it against a deliberately
tampered database) — this script is a thin CLI wrapper around it, printing
a report and setting the process exit code, matching the pattern
`scripts/verify_policies.py` already uses.
"""

import argparse
import sys
from pathlib import Path

# Run standalone (`python scripts/verify_chain.py`), not as a package — put
# the repo root on sys.path so `import firewall...` resolves regardless of
# the caller's current directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from firewall.logger import verify_chain


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db",
        default="firewall_audit.db",
        help="Path to the audit SQLite database.",
    )
    args = parser.parse_args()

    result = verify_chain(args.db)

    if result.ok:
        print(f"OK: {args.db} — {result.rows_checked} row(s), hash chain intact.")
        return 0

    print(f"TAMPERED: {args.db}", file=sys.stderr)
    print(f"  Rows checked before the break: {result.rows_checked}", file=sys.stderr)
    print(f"  {result.first_break}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
