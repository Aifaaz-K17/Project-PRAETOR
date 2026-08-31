"""Tests for firewall/interceptor.py — Phase 1 (Total Mediation)."""

import asyncio
import threading

import pytest
from langchain_core.tools import tool

from firewall.context import Principal, bind_principal
from firewall.interceptor import (
    GuardedToolRegistry,
    ToolCallDenied,
    _SequenceCounters,
    firewall_guard,
)
from tests._evaluators import (
    AllowAllEvaluator,
    CrashingEvaluator,
    DenyAllEvaluator,
    MutatingEvaluator,
    RoleGatedEvaluator,
)

ANALYST = Principal(session_id="session-1", identity="user-1", role="analyst")


@tool
def echo_tool(message: str) -> str:
    """Echoes back the input message."""
    return f"Echo: {message}"


@tool
async def async_echo_tool(message: str) -> str:
    """Async echo tool."""
    return f"AsyncEcho: {message}"


@tool
def raising_tool(message: str) -> str:
    """Always raises, to prove tool errors propagate untouched."""
    raise ValueError(f"boom: {message}")


# ---------------------------------------------------------------------------
# Execution paths (sync/async/invoke/run/batch/retries)
# ---------------------------------------------------------------------------


def test_sync_tool_invoke_is_intercepted_and_executes() -> None:
    evaluator = AllowAllEvaluator()
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(echo_tool)

    with bind_principal(ANALYST):
        result = guarded.invoke({"message": "hello"})

    assert result == "Echo: hello"
    assert len(evaluator.calls) == 1
    assert evaluator.calls[0].tool_name == "echo_tool"
    assert evaluator.calls[0].raw_args == {"message": "hello"}


def test_sync_tool_invoke_with_bare_string_input() -> None:
    evaluator = AllowAllEvaluator()
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(echo_tool)

    with bind_principal(ANALYST):
        result = guarded.invoke("hello-string")

    assert result == "Echo: hello-string"
    assert evaluator.calls[0].raw_args == {"message": "hello-string"}


def test_async_tool_ainvoke_is_intercepted() -> None:
    evaluator = AllowAllEvaluator()
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(async_echo_tool)

    async def run() -> str:
        with bind_principal(ANALYST):
            return await guarded.ainvoke({"message": "hi"})

    result = asyncio.run(run())
    assert result == "AsyncEcho: hi"
    assert len(evaluator.calls) == 1


def test_run_and_arun_paths_are_intercepted() -> None:
    evaluator = AllowAllEvaluator()
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(echo_tool)

    with bind_principal(ANALYST):
        sync_result = guarded.run({"message": "via-run"})

    async def run_async() -> str:
        with bind_principal(ANALYST):
            return await guarded.arun({"message": "via-arun"})

    async_result = asyncio.run(run_async())

    assert sync_result == "Echo: via-run"
    assert async_result == "Echo: via-arun"
    assert len(evaluator.calls) == 2


def test_batch_intercepts_each_call_separately() -> None:
    evaluator = AllowAllEvaluator()
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(echo_tool)

    with bind_principal(ANALYST):
        results = guarded.batch([{"message": "a"}, {"message": "b"}, {"message": "c"}])

    assert results == ["Echo: a", "Echo: b", "Echo: c"]
    assert len(evaluator.calls) == 3
    assert {c.call_id for c in evaluator.calls} == {
        c.call_id for c in evaluator.calls
    }  # all distinct
    assert len({c.call_id for c in evaluator.calls}) == 3
    assert [c.sequence_index for c in evaluator.calls] == [0, 1, 2]


def test_abatch_intercepts_each_call_separately() -> None:
    evaluator = AllowAllEvaluator()
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(async_echo_tool)

    async def run() -> list[str]:
        with bind_principal(ANALYST):
            return await guarded.abatch([{"message": "x"}, {"message": "y"}])

    results = asyncio.run(run())
    assert results == ["AsyncEcho: x", "AsyncEcho: y"]
    assert len(evaluator.calls) == 2


def test_retries_are_each_independently_intercepted() -> None:
    evaluator = AllowAllEvaluator()
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(echo_tool)

    with bind_principal(ANALYST):
        for _ in range(3):
            guarded.invoke({"message": "retry"})

    assert len(evaluator.calls) == 3
    assert [c.sequence_index for c in evaluator.calls] == [0, 1, 2]
    assert len({c.call_id for c in evaluator.calls}) == 3


def test_tool_that_raises_still_gets_evaluated_and_exception_propagates() -> None:
    evaluator = AllowAllEvaluator()
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(raising_tool)

    with bind_principal(ANALYST), pytest.raises(ValueError, match="boom: kaboom"):
        guarded.invoke({"message": "kaboom"})

    # Mediation happened (evaluator ran) even though the tool's own logic
    # then failed — the firewall isn't what broke.
    assert len(evaluator.calls) == 1


def test_denied_call_never_executes() -> None:
    executed: list[str] = []

    @tool
    def side_effect_tool(message: str) -> str:
        """Records that it ran."""
        executed.append(message)
        return "ran"

    evaluator = DenyAllEvaluator()
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(side_effect_tool)

    with bind_principal(ANALYST), pytest.raises(ToolCallDenied):
        guarded.invoke({"message": "should-not-run"})

    assert executed == []
    assert len(evaluator.calls) == 1


# ---------------------------------------------------------------------------
# INV-01 — fail closed
# ---------------------------------------------------------------------------


def test_INV_01_crashing_evaluator_fails_closed() -> None:
    executed: list[str] = []

    @tool
    def side_effect_tool(message: str) -> str:
        """Records that it ran."""
        executed.append(message)
        return "ran"

    evaluator = CrashingEvaluator()
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(side_effect_tool)

    with bind_principal(ANALYST), pytest.raises(ToolCallDenied) as exc_info:
        guarded.invoke({"message": "x"})

    assert exc_info.value.decision.reason.startswith("FIREWALL_ERROR:")
    assert executed == []


def test_INV_01_unbound_principal_fails_closed() -> None:
    """No bind_principal(...) context at all — must deny, not guess a
    default identity and proceed."""
    evaluator = AllowAllEvaluator()
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(echo_tool)

    with pytest.raises(ToolCallDenied) as exc_info:
        guarded.invoke({"message": "x"})

    assert exc_info.value.decision.reason.startswith("FIREWALL_ERROR:")
    # get_current_principal() raised before evaluate() was ever reached.
    assert evaluator.calls == []


def test_evaluator_returning_non_decision_fails_closed() -> None:
    class BrokenEvaluator:
        def evaluate(self, call):  # type: ignore[no-untyped-def]
            return "ALLOW"  # not a Decision — a real bug in a policy engine

    registry = GuardedToolRegistry(BrokenEvaluator())
    guarded = registry.register(echo_tool)

    with bind_principal(ANALYST), pytest.raises(ToolCallDenied) as exc_info:
        guarded.invoke({"message": "x"})

    assert exc_info.value.decision.reason.startswith("FIREWALL_ERROR:")


# ---------------------------------------------------------------------------
# INV-05 — principal binding
# ---------------------------------------------------------------------------


def test_INV_05_agent_cannot_set_own_role() -> None:
    """A tool call whose arguments happen to contain `role`/`session_id`
    keys must not influence the decision at all — only the contextvars-
    bound principal matters."""
    evaluator = RoleGatedEvaluator(required_role="admin")
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(echo_tool)

    bound_as_user = Principal(session_id="real-session", identity="user-1", role="user")
    with bind_principal(bound_as_user), pytest.raises(ToolCallDenied):
        # The attacker-controlled LLM tries to smuggle elevated privilege
        # in through the tool's own arguments.
        guarded.invoke(
            {"message": "x", "role": "admin", "session_id": "forged-session"}
        )

    recorded = evaluator.calls[0]
    assert recorded.role == "user"  # from the bound principal, not the args
    assert recorded.session_id == "real-session"
    # The forged values are still visible in raw_args for audit purposes —
    # they're just never consulted for the decision.
    assert recorded.raw_args["role"] == "admin"


# ---------------------------------------------------------------------------
# INV-07 — no TOCTOU
# ---------------------------------------------------------------------------


def test_INV_07_mutating_evaluator_does_not_affect_executed_args() -> None:
    evaluator = MutatingEvaluator(mutated_value="MUTATED_BY_POLICY_HOOK")
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(echo_tool)

    with bind_principal(ANALYST):
        result = guarded.invoke({"message": "original-value"})

    # The evaluator mutated call.canonical_args in place — that must have
    # zero effect on what the tool actually received.
    assert result == "Echo: original-value"
    assert "MUTATED_BY_POLICY_HOOK" not in result


# ---------------------------------------------------------------------------
# INV-02 — total mediation
# ---------------------------------------------------------------------------


def test_INV_02_bypass_audit() -> None:
    """The headline test: register several tools, run a scripted
    multi-step session exercising every execution path, and prove nothing
    slipped through unguarded."""

    @tool
    def tool_a(message: str) -> str:
        """Tool A."""
        return f"A: {message}"

    @tool
    async def tool_b(message: str) -> str:
        """Tool B (async)."""
        return f"B: {message}"

    @tool
    def tool_c(message: str) -> str:
        """Tool C."""
        return f"C: {message}"

    evaluator = AllowAllEvaluator()
    registry = GuardedToolRegistry(evaluator)
    guarded_a = registry.register(tool_a)
    guarded_b = registry.register(tool_b)
    guarded_c = registry.register(tool_c)

    total_invocations = 0

    async def scripted_session() -> None:
        nonlocal total_invocations
        with bind_principal(ANALYST):
            guarded_a.invoke({"message": "1"})
            total_invocations += 1
            guarded_a.run({"message": "2"})
            total_invocations += 1
            await guarded_b.ainvoke({"message": "3"})
            total_invocations += 1
            await guarded_b.arun({"message": "4"})
            total_invocations += 1
            guarded_c.batch([{"message": "5"}, {"message": "6"}])
            total_invocations += 2
            await guarded_b.abatch([{"message": "7"}, {"message": "8"}])
            total_invocations += 2
            for _ in range(2):  # simulated retries
                guarded_c.invoke({"message": "retry"})
                total_invocations += 1

    asyncio.run(scripted_session())

    # (a) interception counter equals total invocation count
    assert len(evaluator.calls) == total_invocations == 10

    # (b) the registry's own bookkeeping shows nothing unguarded
    assert registry.unguarded_tools() == []

    # (c) a reflective sweep of the tool list the agent would actually
    # receive finds no callable missing the "this wraps something" marker
    agent_tools = registry.get_tools_for_agent()
    assert len(agent_tools) == 3
    for guarded_tool in agent_tools:
        assert hasattr(guarded_tool, "__wrapped__")
        assert guarded_tool.__wrapped__ is not None


def test_INV_02_direct_reference_bypasses_registry() -> None:
    """Honest negative test (documented in THREAT_MODEL.md R-1 and
    LIMITATIONS.md): if code holds a reference to the *original* tool
    object passed into `.register()`, calling it directly skips mediation
    entirely. Registry wrapping covers every path reachable through the
    GuardedTool it returns — it cannot stop code that deliberately reaches
    around that returned object back to the thing it wrapped.
    """
    evaluator = DenyAllEvaluator()
    registry = GuardedToolRegistry(evaluator)
    registry.register(echo_tool)  # the wrapped reference is discarded here

    # `echo_tool` (module-level) is the *original*, undecorated tool. A
    # DenyAllEvaluator is bound to the registry, but that's irrelevant: the
    # direct reference never goes near the registry or the evaluator at all.
    result = echo_tool.invoke({"message": "unguarded"})

    assert result == "Echo: unguarded"
    assert evaluator.calls == []  # proof the firewall was never consulted


# ---------------------------------------------------------------------------
# firewall_guard decorator (developer sugar)
# ---------------------------------------------------------------------------


def test_firewall_guard_decorator_sync() -> None:
    evaluator = AllowAllEvaluator()

    @firewall_guard(evaluator)
    def add(a: int, b: int) -> int:
        return a + b

    with bind_principal(ANALYST):
        result = add(2, 3)

    assert result == 5
    assert len(evaluator.calls) == 1
    assert evaluator.calls[0].raw_args == {"a": 2, "b": 3}
    assert hasattr(add, "__wrapped__")


def test_firewall_guard_decorator_async() -> None:
    evaluator = AllowAllEvaluator()

    @firewall_guard(evaluator)
    async def add_async(a: int, b: int) -> int:
        return a + b

    async def run() -> int:
        with bind_principal(ANALYST):
            return await add_async(2, 3)

    result = asyncio.run(run())
    assert result == 5
    assert len(evaluator.calls) == 1


def test_firewall_guard_decorator_direct_reference_bypass() -> None:
    """Same honest residual as the registry, for the decorator path: keep
    a reference to the function *before* decorating it, and that reference
    is never mediated."""
    evaluator = DenyAllEvaluator()

    def raw_add(a: int, b: int) -> int:
        return a + b

    guarded_add = firewall_guard(evaluator)(raw_add)

    # The pre-decoration reference still works, completely unguarded.
    assert raw_add(2, 3) == 5
    assert evaluator.calls == []

    with bind_principal(ANALYST), pytest.raises(ToolCallDenied):
        guarded_add(2, 3)
    assert len(evaluator.calls) == 1


# ---------------------------------------------------------------------------
# Parallel calls and concurrency safety
# ---------------------------------------------------------------------------


def test_parallel_async_calls_within_same_principal_are_each_intercepted() -> None:
    evaluator = AllowAllEvaluator()
    registry = GuardedToolRegistry(evaluator)
    guarded = registry.register(async_echo_tool)

    async def run() -> list[str]:
        with bind_principal(ANALYST):
            return await asyncio.gather(
                guarded.ainvoke({"message": "p1"}),
                guarded.ainvoke({"message": "p2"}),
                guarded.ainvoke({"message": "p3"}),
            )

    results = asyncio.run(run())
    assert sorted(results) == ["AsyncEcho: p1", "AsyncEcho: p2", "AsyncEcho: p3"]
    assert len(evaluator.calls) == 3
    assert len({c.call_id for c in evaluator.calls}) == 3
    assert len({c.sequence_index for c in evaluator.calls}) == 3
    assert all(c.session_id == "session-1" for c in evaluator.calls)


def test_sequence_counters_thread_safe_under_concurrent_calls() -> None:
    counters = _SequenceCounters()
    calls_per_thread = 200
    thread_count = 8
    results: list[int] = []
    lock = threading.Lock()

    def worker() -> None:
        local_results = [
            counters.next("shared-session") for _ in range(calls_per_thread)
        ]
        with lock:
            results.extend(local_results)

    threads = [threading.Thread(target=worker) for _ in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # No lost updates and no duplicates: every index from 0..N-1 exactly once.
    assert sorted(results) == list(range(calls_per_thread * thread_count))
