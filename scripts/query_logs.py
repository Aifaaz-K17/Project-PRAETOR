"""Query the audit log for the dashboard and report evaluation harness.

Read-only CLI over the audit database (INV-11: never prints secrets, full
file contents, or full email bodies — previews and hashes only).

STATUS: stub. firewall/logger does not exist yet, so there is no schema to
query.
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
    parser.add_argument(
        "--session-id",
        help="Filter to a single session ID.",
    )
    args = parser.parse_args()

    print(
        f"query_logs.py: not yet implemented — firewall/logger does not "
        f"exist. Cannot query {args.db}.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
