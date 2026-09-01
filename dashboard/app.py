"""Read-only Streamlit dashboard over the real audit log — Phase 6.

Replaces the Phase 0 placeholder (static "0" metrics). Every number and
row on this page comes from a real query against a real
`firewall.logger.AuditLogRow` table — this file never writes to the
database, never imports `AuditLogger`, and never calls anything from
`firewall.policy_engine`/`firewall.interceptor` (CLAUDE.md §7: "dashboard
button is a stretch" for approval — this stays read-only, matching the
project's standing answer). Safe by the same construction
`scripts/query_logs.py` already relies on: every row was redacted at
write time (INV-11), so nothing this page displays needs its own
redaction pass.

Run with: streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import cast

# Run standalone (`streamlit run dashboard/app.py`), not as a package —
# put the repo root on sys.path so `import firewall...` resolves
# regardless of the caller's current directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from firewall.logger import AuditLogRow, verify_chain

DEFAULT_DB_PATH = (
    Path(__file__).resolve().parent.parent / "sandbox" / "runtime" / "demo_audit.db"
)

st.set_page_config(page_title="Praetor Audit Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ Praetor — Audit Trail Dashboard")
st.caption(
    "Read-only. Every row below is a real, hash-chained entry from "
    "firewall/logger.py's audit database — nothing on this page is "
    "invented or simulated."
)

db_path_input = st.sidebar.text_input("Audit database path", value=str(DEFAULT_DB_PATH))
db_path = Path(db_path_input)

if not db_path.exists():
    st.warning(
        f"No audit database found at `{db_path}`. Run a demo scenario first — e.g. "
        "`python -m demo_agent.attack_scenarios` or `python -m demo_agent.full_demo` "
        "— to populate one, then refresh."
    )
    st.stop()


@st.cache_data(ttl=5)
def _load_rows(path_str: str, mtime: float) -> pd.DataFrame:
    """Cached for 5s and keyed on the file's own mtime, so the dashboard
    picks up new rows shortly after a demo script runs without re-reading
    the whole table on every Streamlit rerun in between."""
    engine = create_engine(f"sqlite:///{path_str}", future=True)
    try:
        session_factory = sessionmaker(bind=engine, future=True)
        with session_factory() as session:
            rows = (
                session.execute(select(AuditLogRow).order_by(AuditLogRow.id))
                .scalars()
                .all()
            )
    finally:
        engine.dispose()

    return pd.DataFrame(
        [
            {
                "id": row.id,
                "timestamp_utc": row.timestamp_utc,
                "session_id": row.session_id,
                "identity": row.identity,
                "role": row.role,
                "tool_name": row.tool_name,
                "outcome": row.outcome,
                "reason": row.reason,
                "matched_rules": ", ".join(
                    json.loads(cast(str, row.matched_rule_ids_json))
                ),
                "latency_ms": row.latency_ns / 1_000_000,
                "args_preview": json.loads(cast(str, row.redacted_args_json)),
            }
            for row in rows
        ]
    )


df = _load_rows(str(db_path), db_path.stat().st_mtime)

if df.empty:
    st.info("The audit database exists but has no rows yet.")
    st.stop()

# --- Integrity check (INV-10) -----------------------------------------
chain_result = verify_chain(db_path)
if chain_result.ok:
    st.sidebar.success(f"Hash chain intact ({chain_result.rows_checked} rows verified)")
else:
    st.sidebar.error(f"HASH CHAIN BROKEN: {chain_result.first_break}")

# --- Top-line metrics ----------------------------------------------------
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total calls", len(df))
col2.metric("Allowed", int((df["outcome"] == "ALLOW").sum()))
col3.metric("Denied", int((df["outcome"] == "DENY").sum()))
col4.metric("Needs approval", int((df["outcome"] == "NEEDS_APPROVAL").sum()))

# --- Filters ---------------------------------------------------------------
st.sidebar.header("Filters")
tool_options = ["(all)"] + sorted(df["tool_name"].unique().tolist())
role_options = ["(all)"] + sorted(df["role"].unique().tolist())
outcome_options = ["(all)"] + sorted(df["outcome"].unique().tolist())

selected_tool = st.sidebar.selectbox("Tool", tool_options)
selected_role = st.sidebar.selectbox("Role", role_options)
selected_outcome = st.sidebar.selectbox("Outcome", outcome_options)

filtered = df
if selected_tool != "(all)":
    filtered = filtered[filtered["tool_name"] == selected_tool]
if selected_role != "(all)":
    filtered = filtered[filtered["role"] == selected_role]
if selected_outcome != "(all)":
    filtered = filtered[filtered["outcome"] == selected_outcome]

# --- Calls by tool / outcome ------------------------------------------
st.subheader("Calls by tool and outcome")
by_tool = (
    df.groupby(["tool_name", "outcome"])
    .size()
    .reset_index(name="count")
    .pivot(index="tool_name", columns="outcome", values="count")
    .fillna(0)
)
st.bar_chart(by_tool)

# --- Audit trail table -----------------------------------------------
st.subheader(f"Audit trail ({len(filtered)} of {len(df)} rows)")
st.dataframe(
    filtered[
        [
            "timestamp_utc",
            "session_id",
            "identity",
            "role",
            "tool_name",
            "outcome",
            "reason",
            "matched_rules",
            "latency_ms",
        ]
    ],
    use_container_width=True,
    hide_index=True,
)

with st.expander("Raw redacted arguments for the filtered rows"):
    st.dataframe(
        filtered[["id", "tool_name", "args_preview"]],
        use_container_width=True,
        hide_index=True,
    )
