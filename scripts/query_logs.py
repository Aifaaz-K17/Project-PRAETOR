"""Query the audit log for the dashboard and report evaluation harness.

Read-only CLI over the audit database. Safe by construction, not just by
convention: every row was already redacted (INV-11) by `firewall.logger`
at write time — `redacted_args_json` never contains a secret or a full
raw value, only a preview or a `[REDACTED: ...]` marker plus a SHA-256 of
whatever was replaced — so this script never needs its own redaction pass
before printing. It only filters and formats what's already safe to show.
"""

import argparse
import json
import sys
from pathlib import Path

# Run standalone (`python scripts/query_logs.py`), not as a package — put
# the repo root on sys.path so `import firewall...` resolves regardless of
# the caller's current directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from firewall.logger import AuditLogRow


def _build_query(args: argparse.Namespace):  # type: ignore[no-untyped-def]
    query = select(AuditLogRow).order_by(AuditLogRow.id)
    if args.session_id:
        query = query.where(AuditLogRow.session_id == args.session_id)
    if args.tool_name:
        query = query.where(AuditLogRow.tool_name == args.tool_name)
    if args.outcome:
        query = query.where(AuditLogRow.outcome == args.outcome.upper())
    if args.role:
        query = query.where(AuditLogRow.role == args.role)
    return query.limit(args.limit)


def _print_row(row: AuditLogRow) -> None:
    args_preview = json.loads(row.redacted_args_json)
    print(
        f"[{row.timestamp_utc}] {row.outcome:14} "
        f"tool={row.tool_name!r} role={row.role!r} identity={row.identity!r} "
        f"session={row.session_id!r} call_id={row.call_id!r}"
    )
    print(f"    reason: {row.reason}")
    print(f"    args:   {args_preview}")
    matched_rules = json.loads(row.matched_rule_ids_json)
    if matched_rules:
        print(f"    rule:   {', '.join(matched_rules)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db",
        default="firewall_audit.db",
        help="Path to the audit SQLite database.",
    )
    parser.add_argument("--session-id", help="Filter to a single session ID.")
    parser.add_argument("--tool-name", help="Filter to a single tool name.")
    parser.add_argument(
        "--outcome", help="Filter to a single outcome: ALLOW, DENY, or NEEDS_APPROVAL."
    )
    parser.add_argument("--role", help="Filter to a single role.")
    parser.add_argument(
        "--limit", type=int, default=50, help="Maximum rows to print (default 50)."
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"query_logs.py: database not found: {db_path}", file=sys.stderr)
        return 1

    engine = create_engine(f"sqlite:///{db_path}", future=True)
    try:
        session_factory = sessionmaker(bind=engine, future=True)
        with session_factory() as session:
            rows = session.execute(_build_query(args)).scalars().all()
    finally:
        engine.dispose()

    if not rows:
        print("No matching rows.")
        return 0

    for row in rows:
        _print_row(row)
    print(f"\n{len(rows)} row(s) shown (limit={args.limit}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
