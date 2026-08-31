"""
Streamlit Dashboard Shell.
Displays firewall status, tool invocation logs, and anomaly detection feeds.
"""

import streamlit as st

st.set_page_config(page_title="AI Agent Action Firewall", page_icon="🛡️", layout="wide")

st.title("🛡️ AI Agent Action Firewall — Live Security Dashboard")
st.markdown(
    "Real-time deterministic policy enforcement and audit feed for LLM tool executions."
)

col1, col2, col3 = st.columns(3)
col1.metric(label="Total Tool Calls", value="0")
col2.metric(label="Allowed Calls", value="0")
col3.metric(label="Blocked / Escalated", value="0")

st.subheader("Audit Trail Log Feed")
st.info(
    "No logs recorded yet. Run a demo scenario or test suite to populate audit records."
)
