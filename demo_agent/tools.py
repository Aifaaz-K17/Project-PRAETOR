"""The 5 mocked tools — Phase 6 (ADR 0004's scope).

Every tool here is deliberately mocked, per INV-14 ("no live targets,
ever"): `read_file` is the one exception that touches a real
filesystem. `send_email`, `search_web`, `transfer_funds`, and
`compose_draft` never make a real network call or write anything
outside an in-memory mock — `conftest.py`'s INV-14 fixture would raise
`NetworkBlockedError` if any of them ever tried, which is a second,
structural guarantee on top of "we just didn't write the code to do
that."

**None of these functions validate their own arguments** — no path
containment check, no domain allowlist, no amount cap, no role check.
This is deliberate, not an oversight: these are meant to simulate the
kind of tool a typical integration would actually wrap (`open(path)`,
an HTTP client, a payments SDK call) — code that trusts its caller,
because validating every caller is exactly the job Praetor's whole
thesis says belongs at the interception layer, not duplicated in every
tool. `demo_agent/attack_scenarios.py`'s `--no-firewall` baselines rely
on this: calling these functions directly, unmediated, is what proves
the vulnerability is real, not merely theoretical. Every attack payload
used against `read_file` in this project stays inside the repository
(never a real external/system path) — see `attack_scenarios.py`'s
module docstring for why that boundary is chosen deliberately, not
because the mock enforces it.

These functions are undecorated on purpose — `@tool` is applied where
they're registered (`demo_agent/wiring.py`), not here, so this module
can also be imported and called directly (e.g. by
`demo_agent/attack_scenarios.py`'s no-firewall baselines, or
`scripts/run_bypass_suite.py`) without going through LangChain's tool
machinery, and without going through the firewall, at all.
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SANDBOX_ROOT = _REPO_ROOT / "sandbox"


def read_file(path: str) -> str:
    """Reads a file's contents — for real, and with NO containment
    check of its own (see the module docstring for why). Resolves
    `path` relative to `sandbox/` (the shape a real tool integration
    would use — "read this file from the working directory"), but
    `Path.resolve()` will happily walk `..` segments right out of it if
    given one, exactly like a naive `open()` call would.
    """
    candidate = (_SANDBOX_ROOT / path).resolve()
    if not candidate.is_file():
        return f"[read_file: no such file: {path!r} (resolved: {candidate})]"
    return candidate.read_text(encoding="utf-8")


def send_email(to: str, subject: str = "", body: str = "") -> str:
    """Mocked — never sends anything real. Returns a confirmation string
    shaped like what a real email API would return, for demo realism."""
    return f"[mocked] email queued to {to!r} (subject={subject!r})"


def search_web(query: str, target_host: str = "") -> str:
    """Mocked — never makes a real HTTP request. `conftest.py`'s
    INV-14 fixture blocks any accidental real network attempt anyway,
    but this function never even tries."""
    host_note = f" on {target_host!r}" if target_host else ""
    return f"[mocked] search results for {query!r}{host_note}: (3 mocked results)"


def transfer_funds(amount: float, note: str = "") -> str:
    """Mocked — no real ledger, no real money. Returns a confirmation
    string with a fake transaction id for demo realism."""
    return f"[mocked] transferred {amount} (note={note!r}), txn_id=DEMO-0001"


def compose_draft(subject: str, body: str = "", attachment_path: str = "") -> str:
    """Mocked — drafts are never actually persisted anywhere. If an
    attachment_path is given, reports (read-only, no enforcement) whether
    it resolves to a real file inside sandbox/, purely so the mocked
    output is honest about whether the referenced file exists — not a
    security check of any kind (the firewall already made that decision
    before this function ever runs, and this function's own report can't
    stop anything even if it wanted to).
    """
    attachment_note = ""
    if attachment_path:
        candidate = (_SANDBOX_ROOT / attachment_path).resolve()
        exists = (
            candidate.is_relative_to(_SANDBOX_ROOT.resolve()) and candidate.is_file()
        )
        attachment_note = f", attachment {'found' if exists else 'NOT FOUND'}"
    return f"[mocked] draft composed (subject={subject!r}){attachment_note}"
