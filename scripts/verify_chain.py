"""Verify the audit log hash chain (INV-10).

Walks every row in the audit database in order, recomputes each entry's
SHA-256 over its canonical JSON, and confirms it matches the stored
`entry_hash` and that `prev_hash` matches the previous row's `entry_hash`.
Any mismatch means a row was edited or deleted after the fact.

STATUS: stub. The audit logger (firewall/logger, INV-10/INV-11) does not
exist yet, so there is no schema to read. This script intentionally exits
non-zero rather than pretending to verify anything — a firewall tool that
silently no-ops on missing dependencies violates fail-closed (INV-01).
"""

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db",
        default="firewall_audit.db",
        help="Path to the audit SQLite database.",
    )
    args = parser.parse_args()

    print(
        f"verify_chain.py: not yet implemented — firewall/logger does not "
        f"exist. Cannot verify {args.db}.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
