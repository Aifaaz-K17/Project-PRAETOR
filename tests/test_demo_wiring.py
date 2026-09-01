"""Tests for demo_agent/wiring.py — Phase 6.

`demo_agent/attack_scenarios.py`'s own test suite already exercises
`build_firewall()` extensively end-to-end; this file covers `wiring.py`'s
own contract directly: all 5 tools register, `DemoFirewall.guarded()`
looks them up correctly, the context-manager closes the audit logger,
and `fresh_db=True` actually starts from a clean database.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from demo_agent.wiring import build_firewall
from firewall.context import Principal, bind_principal
from firewall.hitl import ApprovalOutcome, ApprovalResult


class _ScriptedChannel:
    def __init__(self, outcome: ApprovalOutcome = ApprovalOutcome.APPROVED) -> None:
        self._outcome = outcome

    def request_approval(self, call, decision, *, timeout_seconds: float):  # type: ignore[no-untyped-def]
        return ApprovalResult(outcome=self._outcome, reason="test")


def test_build_firewall_registers_all_5_tools(tmp_path: Path) -> None:
    with build_firewall(
        db_path=tmp_path / "audit.db", hitl_channel=_ScriptedChannel(), fresh_db=True
    ) as fw:
        names = {t.name for t in fw.registry.get_tools_for_agent()}
    assert names == {
        "read_file",
        "send_email",
        "search_web",
        "transfer_funds",
        "compose_draft",
    }


def test_guarded_looks_up_a_registered_tool_by_name(tmp_path: Path) -> None:
    with build_firewall(
        db_path=tmp_path / "audit.db", hitl_channel=_ScriptedChannel(), fresh_db=True
    ) as fw:
        guarded = fw.guarded("read_file")
        assert guarded.name == "read_file"


def test_guarded_raises_for_an_unregistered_tool_name(tmp_path: Path) -> None:
    with build_firewall(
        db_path=tmp_path / "audit.db", hitl_channel=_ScriptedChannel(), fresh_db=True
    ) as fw, pytest.raises(KeyError):
        fw.guarded("not_a_real_tool")


def test_a_real_call_goes_through_the_full_stack_and_gets_recorded(
    tmp_path: Path,
) -> None:
    with build_firewall(
        db_path=tmp_path / "audit.db", hitl_channel=_ScriptedChannel(), fresh_db=True
    ) as fw:
        principal = Principal(session_id="s1", identity="tester", role="analyst")
        with bind_principal(principal):
            result = fw.guarded("search_web").invoke(
                {"query": "x", "target_host": "docs.python.org"}
            )
        assert "mocked" in result
        assert [tool for tool, _ in fw.session_store.get_history("s1")] == [
            "search_web"
        ]


def test_fresh_db_true_starts_from_an_empty_database(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    with build_firewall(
        db_path=db_path, hitl_channel=_ScriptedChannel(), fresh_db=True
    ) as fw:
        principal = Principal(session_id="s1", identity="tester", role="analyst")
        with bind_principal(principal):
            fw.guarded("search_web").invoke(
                {"query": "x", "target_host": "docs.python.org"}
            )

    # Reopening with fresh_db=True must wipe the previous run's data.
    with build_firewall(
        db_path=db_path, hitl_channel=_ScriptedChannel(), fresh_db=True
    ) as fw2, fw2.audit_logger._session_factory() as session:
        from sqlalchemy import select

        from firewall.logger import AuditLogRow

        rows = session.execute(select(AuditLogRow)).scalars().all()
    assert rows == []


def test_context_manager_closes_the_audit_logger(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    with build_firewall(
        db_path=db_path, hitl_channel=_ScriptedChannel(), fresh_db=True
    ) as fw:
        engine = fw.audit_logger._engine
    # After exiting the context manager, the engine's connections are
    # disposed — the same Windows file-lock reason AuditLogger itself is
    # a context manager for (see firewall/logger.py).
    assert engine.pool.checkedout() == 0
