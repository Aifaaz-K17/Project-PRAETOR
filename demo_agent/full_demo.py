"""The real, end-to-end demo — Phase 6.

Where `demo_agent/interception_demo.py` (Phase 1) proved the interceptor
mechanics with `_DemoEvaluator`, an illustrative stand-in explicitly
NOT a policy claim, this is the real thing: `demo_agent.wiring.
build_firewall()` assembles the actual policy engine, session store,
audit logger, and HITL approver, and every call below goes through all
of it. A realistic multi-step session for an `analyst` — read a file,
draft an email, send it (escalated to approval by the anomaly detector,
since read-then-send is a modeled high-risk sequence, then approved) —
followed by an `intern` search and a `finance` transfer, printing each
real `Decision` as it happens.

Run with: python -m demo_agent.full_demo
"""

from __future__ import annotations

from demo_agent.wiring import DemoFirewall, build_firewall
from firewall.context import Principal, bind_principal
from firewall.interceptor import ToolCallDenied


def _run(
    fw: DemoFirewall, label: str, *, role: str, session_id: str, tool: str, args: dict
) -> None:
    print(f"\n--- {label} ---")
    print(f"    principal: role={role!r} session={session_id!r}")
    print(f"    call:      {tool}({args})")
    principal = Principal(session_id=session_id, identity="demo-user", role=role)
    with bind_principal(principal):
        try:
            result = fw.guarded(tool).invoke(args)
            print(f"    RESULT:    {result}")
        except ToolCallDenied as exc:
            print(f"    DENIED:    {exc.decision.reason}")
            print(f"    rule_id:   {exc.decision.rule_id}")


def main() -> None:
    print("Praetor -- full end-to-end demo (real PolicyEngine + SessionStore")
    print("+ AuditLogger + HitlApprover, all 5 tools, running for real).")
    print(
        "\nApproval prompts below are real -- this demo blocks on stdin for "
        "them, exactly as a live deployment would. Type 'y' to approve, "
        "anything else to deny."
    )

    with build_firewall(fresh_db=True) as fw:
        _run(
            fw,
            "1) analyst reads an in-scope file",
            role="analyst",
            session_id="full-demo-analyst",
            tool="read_file",
            args={"path": "notes.txt"},
        )
        _run(
            fw,
            "2) analyst drafts an email referencing what they just read",
            role="analyst",
            session_id="full-demo-analyst",
            tool="compose_draft",
            args={
                "subject": "Notes summary",
                "body": "See attached.",
                "attachment_path": "notes.txt",
            },
        )
        _run(
            fw,
            "3) analyst sends it (read-then-send is a modeled high-risk "
            "sequence -- expect an approval prompt)",
            role="analyst",
            session_id="full-demo-analyst",
            tool="send_email",
            args={
                "to": "alice@corp.example.com",
                "subject": "Notes summary",
                "body": "b",
            },
        )
        _run(
            fw,
            "4) intern searches an allowlisted reference site",
            role="intern",
            session_id="full-demo-intern",
            tool="search_web",
            args={"query": "pathlib resolve", "target_host": "docs.python.org"},
        )
        _run(
            fw,
            "5) finance transfers an in-bounds amount",
            role="finance",
            session_id="full-demo-finance",
            tool="transfer_funds",
            args={"amount": 250, "note": "vendor payment"},
        )
        _run(
            fw,
            "6) analyst attempts a path-traversal read (should be denied "
            "outright, no prompt)",
            role="analyst",
            session_id="full-demo-analyst",
            tool="read_file",
            args={"path": "../requirements.txt"},
        )

        print(f"\nAudit trail written to: {fw.db_path}")
        print("Inspect it with: python scripts/query_logs.py")
        print("Verify its hash chain with: python scripts/verify_chain.py")
        print("Or view it live with: streamlit run dashboard/app.py")


if __name__ == "__main__":
    main()
