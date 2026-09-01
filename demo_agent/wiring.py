"""Wires the real firewall stack together — Phase 6.

Every earlier phase built one piece of this in isolation, each with its
own tests against constructed inputs: `PolicyEngine` (Phase 3),
`SessionStore`/`AuditLogger` (Phase 4), `HitlApprover` (Phase 5). Nothing
until now assembled all of them, registered the 5 real mocked tools
(`demo_agent/tools.py`) behind a `GuardedToolRegistry`, and ran a real
LLM-shaped call through the whole thing end to end — that's what this
module is for, and what `demo_agent/full_demo.py` and
`demo_agent/attack_scenarios.py` build on.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Self

from langchain_core.tools import tool

from demo_agent import tools as mock_tools
from firewall.hitl import CliApprovalChannel, HitlApprover, HitlChannel
from firewall.interceptor import GuardedTool, GuardedToolRegistry
from firewall.logger import AuditLogger
from firewall.policy_engine import LoadedPolicySet, PolicyEngine, load_policy_set
from firewall.session import SessionStore

_REPO_ROOT = Path(__file__).resolve().parent.parent
_POLICIES_DIR = _REPO_ROOT / "policies"
DEFAULT_DB_PATH = _REPO_ROOT / "sandbox" / "runtime" / "demo_audit.db"


@tool
def read_file(path: str) -> str:
    """Reads a file's contents from inside the sandboxed fixture root."""
    return mock_tools.read_file(path)


@tool
def send_email(to: str, subject: str = "", body: str = "") -> str:
    """Sends an email (mocked — no real message is ever sent)."""
    return mock_tools.send_email(to, subject, body)


@tool
def search_web(query: str, target_host: str = "") -> str:
    """Searches the web (mocked — no real HTTP request is ever made)."""
    return mock_tools.search_web(query, target_host)


@tool
def transfer_funds(amount: float, note: str = "") -> str:
    """Transfers funds (mocked — no real ledger is ever touched)."""
    return mock_tools.transfer_funds(amount, note)


@tool
def compose_draft(subject: str, body: str = "", attachment_path: str = "") -> str:
    """Drafts an email (mocked — the draft is never actually persisted)."""
    return mock_tools.compose_draft(subject, body, attachment_path)


_ALL_MOCK_TOOLS = (read_file, send_email, search_web, transfer_funds, compose_draft)


@dataclass
class DemoFirewall:
    """Everything one call to `build_firewall` assembles, bundled for
    convenience. A context manager itself — `with build_firewall() as
    fw:` closes the audit logger's SQLite engine on exit (the same
    Windows file-lock reason `AuditLogger` itself is a context manager
    — see `firewall/logger.py`).
    """

    registry: GuardedToolRegistry
    loaded_policies: LoadedPolicySet
    session_store: SessionStore
    audit_logger: AuditLogger
    hitl_approver: HitlApprover
    db_path: Path

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.audit_logger.close()

    def guarded(self, name: str) -> GuardedTool:
        """Look up one registered guarded tool by name — convenience for
        demo scripts that want `fw.guarded("read_file").invoke(...)`
        instead of holding onto every individual reference by hand."""
        for guarded_tool in self.registry.get_tools_for_agent():
            if guarded_tool.name == name:
                return guarded_tool
        raise KeyError(f"no tool named {name!r} is registered")


def build_firewall(
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
    hitl_channel: HitlChannel | None = None,
    hitl_timeout_seconds: float = 120.0,
    enable_anomaly_detection: bool = True,
    fresh_db: bool = False,
) -> DemoFirewall:
    """Assembles the real stack: load policies -> SessionStore ->
    AuditLogger -> HitlApprover -> PolicyEngine -> GuardedToolRegistry,
    with all 5 mocked tools registered.

    `hitl_channel` defaults to a real `CliApprovalChannel` (blocking
    terminal `y/n`, INV-12) — pass a scripted `HitlChannel` test double
    for a non-interactive run (every `demo_agent/attack_scenarios.py`
    scenario and `scripts/run_all_demos.py` do exactly this, since a
    demo script blocking on real stdin mid-run would defeat the point of
    an automated demo).

    `fresh_db=True` deletes any existing database at `db_path` first —
    useful for a demo script that wants a clean audit trail each run;
    the default (`False`) keeps accumulating history across runs, which
    is what a real deployment would do.
    """
    db_path = Path(db_path)
    if fresh_db and db_path.exists():
        db_path.unlink()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    loaded = load_policy_set(_POLICIES_DIR)
    session_store = SessionStore()
    audit_logger = AuditLogger(db_path, policy_set_hash=loaded.policy_set_hash)

    channel = hitl_channel if hitl_channel is not None else CliApprovalChannel()
    hitl_approver = HitlApprover(
        channel=channel,
        timeout_seconds=hitl_timeout_seconds,
        audit_logger=audit_logger,
        session_store=session_store,
    )

    engine = PolicyEngine(
        loaded,
        session_store=session_store,
        audit_logger=audit_logger,
        enable_anomaly_detection=enable_anomaly_detection,
    )

    registry = GuardedToolRegistry(engine, hitl_resolver=hitl_approver)
    for one_tool in _ALL_MOCK_TOOLS:
        registry.register(one_tool)

    return DemoFirewall(
        registry=registry,
        loaded_policies=loaded,
        session_store=session_store,
        audit_logger=audit_logger,
        hitl_approver=hitl_approver,
        db_path=db_path,
    )
