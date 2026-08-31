"""Phase 1 demo: print what the interception layer actually does.

Registers two mocked tools with a `GuardedToolRegistry`, binds a principal
the way trusted session-creation code would, and makes a few calls — some
allowed, one denied — printing each `CallRecord`/`Decision` pair to the
console. There is no real policy engine yet (that's Phase 3); the
`_DemoEvaluator` below is a deliberately simple stand-in, not a claim about
what Praetor's real policy logic looks like.

Run with: python -m demo_agent.interception_demo
"""

from __future__ import annotations

from langchain_core.tools import tool

from firewall.context import Principal, bind_principal
from firewall.interceptor import (
    CallRecord,
    Decision,
    Evaluator,
    GuardedToolRegistry,
    ToolCallDenied,
)


class _DemoEvaluator(Evaluator):
    """Illustrative only: denies any call whose args contain the word
    'delete'. Phase 3 replaces this with the real YAML-driven policy
    engine — nothing here is a policy claim."""

    def evaluate(self, call: CallRecord) -> Decision:
        args_text = " ".join(str(v) for v in call.canonical_args.values())
        if "delete" in args_text.lower():
            return Decision.deny(
                reason="demo rule: 'delete' is not allowed", rule_id="demo-001"
            )
        return Decision.allow(reason="demo rule: no denylisted words found")


@tool
def read_file(path: str) -> str:
    """Mocked file read tool."""
    return f"[mocked contents of {path}]"


@tool
def send_email(to: str, body: str) -> str:
    """Mocked email tool."""
    return f"[mocked email sent to {to}]"


def _print_result(label: str, call_fn) -> None:  # type: ignore[no-untyped-def]
    print(f"\n--- {label} ---")
    try:
        result = call_fn()
        print(f"  RESULT: {result}")
    except ToolCallDenied as denied:
        print(f"  DENIED: {denied.decision.reason} (rule_id={denied.decision.rule_id})")


def main() -> None:
    registry = GuardedToolRegistry(_DemoEvaluator())
    guarded_read = registry.register(read_file)
    guarded_send = registry.register(send_email)

    principal = Principal(
        session_id="demo-session-1", identity="demo-user", role="analyst"
    )
    print(f"Bound principal: {principal}")

    with bind_principal(principal):
        _print_result(
            "read_file(path='sandbox/notes.txt') -- should be ALLOWED",
            lambda: guarded_read.invoke({"path": "sandbox/notes.txt"}),
        )
        _print_result(
            "send_email(to='team@example.com', body='status update') -- should be ALLOWED",
            lambda: guarded_send.invoke(
                {"to": "team@example.com", "body": "status update"}
            ),
        )
        _print_result(
            "read_file(path='sandbox/please delete this') -- should be DENIED",
            lambda: guarded_read.invoke({"path": "sandbox/please delete this"}),
        )

    print(f"\nRegistry unguarded_tools(): {registry.unguarded_tools()} (must be empty)")
    print(
        f"Tools available to an agent: {[t.name for t in registry.get_tools_for_agent()]}"
    )


if __name__ == "__main__":
    main()
