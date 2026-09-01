"""The interception layer — Phase 1.

`GuardedToolRegistry` is the real enforcement point (INV-02): it wraps a
LangChain tool at *registration* time, and every execution path on the
returned `GuardedTool` (`.invoke`, `.ainvoke`, `.run`, `.arun`, `.batch`,
`.abatch`) funnels through the same single chokepoint, `_evaluate_call`,
before the underlying tool ever runs. `@firewall_guard` is developer sugar
for guarding a single plain function the same way; the registry is what
Phase 6's demo agent actually uses.

What this phase does NOT do yet: decide anything about whether a call is
*safe*. `Evaluator.evaluate()` is a seam — Phase 3's real policy engine
will implement it. Every evaluator here is a stand-in used to test the
mediation mechanics.
"""

from __future__ import annotations

import copy
import functools
import inspect
import threading
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol, TypeVar

from langchain_core.tools import BaseTool

from firewall.context import get_current_principal


@dataclass(frozen=True)
class CallRecord:
    """Everything the policy engine needs to decide, plus everything the
    audit log needs to record. Frozen: nothing downstream should be able to
    mutate the record of what was actually asked for.
    """

    call_id: str
    tool_name: str
    raw_args: dict[str, Any]
    # An identity deep-copy of raw_args, taken before the evaluator ever
    # sees it (INV-07 — see _evaluate_call). This is deliberately NOT
    # itself run through firewall/canonicalize.py: canonicalizing a value
    # requires knowing its *type* (is this argument a path? a host? plain
    # text?), and that mapping is inherently per-rule, not generic — a
    # "path" parameter might be named "path" for one tool and "file_path"
    # for another. So type-specific canonicalization happens where the
    # type is actually known: inside each policy rule's matcher in
    # firewall/policy_engine.py (a path_scope rule calls canonical_path on
    # exactly the parameter it names, a domain_allowlist rule calls
    # canonical_host, and so on) — never here, generically, on the whole
    # dict. The policy engine still only ever reads canonical_args, never
    # raw_args, satisfying INV-06's "canonicalize, then decide."
    canonical_args: dict[str, Any]
    session_id: str
    identity: str
    role: str
    timestamp_utc: datetime
    timestamp_monotonic_ns: int
    sequence_index: int
    tool_call_id: str | None = None


class Outcome(str, Enum):
    """The three outcomes a policy rule (or a whole evaluation) can
    produce. NEEDS_APPROVAL sits strictly between ALLOW and DENY in
    conflict resolution (ADR 0009): it beats ALLOW, but DENY beats it."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"


@dataclass(frozen=True)
class Decision:
    """The outcome of evaluating one CallRecord.

    `outcome` is the real, 3-state result (added in Phase 3 to match what
    CLAUDE.md's own architecture diagram always specified: ALLOW / DENY /
    NEEDS_APPROVAL). `allowed` is a derived, backward-compatible property
    — Phase 1's interceptor code was written against a boolean and still
    only needs to know "did this end up executing or not", which is true
    for ALLOW and false for both DENY and NEEDS_APPROVAL.

    Since Phase 5, `_evaluate_call` resolves a NEEDS_APPROVAL outcome
    into a final ALLOW/DENY *before* anything ever reads `.allowed` — see
    `HitlResolver` below — whenever a `hitl_resolver` is wired into
    `GuardedToolRegistry`/`firewall_guard` (`firewall.hitl.HitlApprover`
    is the real implementation). Without one configured (the default,
    and every Phase 1-4 caller's unchanged behavior), a `Decision` this
    class wraps can still legitimately carry `NEEDS_APPROVAL` all the
    way to `.allowed`, which reads it as `False` — fail-closed in the
    absence of a configured approval mechanism, not a claim that
    approval is unimplemented (see `LIMITATIONS.md`).
    """

    outcome: Outcome
    reason: str
    rule_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome == Outcome.ALLOW

    @staticmethod
    def allow(reason: str, rule_id: str | None = None) -> Decision:
        return Decision(outcome=Outcome.ALLOW, reason=reason, rule_id=rule_id)

    @staticmethod
    def deny(reason: str, rule_id: str | None = None) -> Decision:
        return Decision(outcome=Outcome.DENY, reason=reason, rule_id=rule_id)

    @staticmethod
    def needs_approval(reason: str, rule_id: str | None = None) -> Decision:
        return Decision(outcome=Outcome.NEEDS_APPROVAL, reason=reason, rule_id=rule_id)


class Evaluator(Protocol):
    """What Phase 3's policy engine will implement. Structural typing (not
    inheritance) so test doubles need nothing but this one method."""

    def evaluate(self, call: CallRecord) -> Decision: ...


class HitlResolver(Protocol):
    """What Phase 5's `firewall.hitl.HitlApprover` implements. Structural
    typing, same pattern as `Evaluator` — this file deliberately never
    imports `firewall.hitl` (which needs `CallRecord`/`Decision`/
    `Outcome` from here), so defining the seam as a `Protocol` in this
    module avoids a circular import while still type-checking the wiring
    in `_evaluate_call` below.

    Called only when a `Decision`'s outcome is `NEEDS_APPROVAL`; must
    return a `Decision` whose outcome is `ALLOW` or `DENY` (never
    `NEEDS_APPROVAL` again) — see `HitlApprover.resolve_approval`'s
    docstring for the full contract (INV-12: single-use, timeout-denies).
    """

    def resolve_approval(self, call: CallRecord, decision: Decision) -> Decision: ...


class ToolCallDenied(Exception):
    """Raised by the interceptor instead of letting a denied call execute."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(f"Tool call denied: {decision.reason}")


class _SequenceCounters:
    """Per-session, monotonically increasing call counters.

    Phase 1 placeholder: thread-safe, but no TTL/eviction. Phase 4's
    firewall/session.py replaces this with the full session state store —
    tracked in LIMITATIONS.md so it isn't forgotten.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}

    def next(self, session_id: str) -> int:
        with self._lock:
            index = self._counts.get(session_id, 0)
            self._counts[session_id] = index + 1
            return index


def _evaluate_call(
    *,
    tool_name: str,
    raw_args: dict[str, Any],
    evaluator: Evaluator,
    sequence_counters: _SequenceCounters,
    tool_call_id: str | None,
    hitl_resolver: HitlResolver | None = None,
) -> tuple[Decision, dict[str, Any]]:
    """The single chokepoint every execution path calls before running a
    tool. Returns the Decision and the exact args snapshot to execute with.

    INV-01 (fail closed): the entire body runs under one try/except. A
    crashing evaluator, an unbound principal, or a malformed Decision all
    produce the same thing — a DENY tagged FIREWALL_ERROR — never a silent
    ALLOW and never a propagated exception that might let a caller's own
    error handling accidentally proceed to execute the tool anyway. The
    optional Phase 5 HITL resolution step (below) runs inside this same
    try/except for the same reason — a crashing/hanging approval channel
    must fail closed too, not bypass the rest of this function's
    guarantees.

    INV-07 (no TOCTOU): two independent deep copies are taken up front.
    `canonical_args` is handed to the evaluator and may be mutated by a
    careless or hostile policy hook — that copy is never used again.
    `args_for_execution` is what actually reaches the tool, and nothing
    after this point can change it.

    `hitl_resolver`, if given, is consulted only when the evaluator
    returns `NEEDS_APPROVAL` — it resolves that into a final ALLOW/DENY
    `Decision` (a blocking human approval prompt, by default — see
    `firewall.hitl`). Without one (the default, and every Phase 1-4
    caller's existing behavior), `NEEDS_APPROVAL` is left as-is and
    `Decision.allowed` treats it the same as DENY — fail-closed in the
    absence of a real approval mechanism, exactly as documented since
    Phase 3. Running this at the SAME chokepoint every other decision
    goes through (not e.g. in `GuardedTool.invoke` after the fact) is
    what makes total mediation (INV-02) apply to the HITL step too — no
    execution path can reach a NEEDS_APPROVAL tool without going through
    approval resolution.
    """
    canonical_args = copy.deepcopy(raw_args)
    args_for_execution = copy.deepcopy(raw_args)

    try:
        principal = get_current_principal()
        sequence_index = sequence_counters.next(principal.session_id)
        record = CallRecord(
            call_id=str(uuid.uuid4()),
            tool_name=tool_name,
            raw_args=raw_args,
            canonical_args=canonical_args,
            session_id=principal.session_id,
            identity=principal.identity,
            role=principal.role,
            timestamp_utc=datetime.now(UTC),
            timestamp_monotonic_ns=time.monotonic_ns(),
            sequence_index=sequence_index,
            tool_call_id=tool_call_id,
        )
        decision = evaluator.evaluate(record)
        if not isinstance(decision, Decision):
            raise TypeError(
                f"Evaluator must return a Decision, got {type(decision).__name__}"
            )
        if hitl_resolver is not None and decision.outcome == Outcome.NEEDS_APPROVAL:
            decision = hitl_resolver.resolve_approval(record, decision)
            if not isinstance(decision, Decision):
                raise TypeError(
                    f"HitlResolver must return a Decision, got {type(decision).__name__}"
                )
    except Exception as exc:  # noqa: BLE001 - INV-01: any firewall-side error is a DENY
        decision = Decision.deny(reason=f"FIREWALL_ERROR: {type(exc).__name__}: {exc}")

    return decision, args_for_execution


def _mediate_sync(
    execute: Callable[[dict[str, Any]], Any],
    **evaluate_kwargs: Any,
) -> Any:
    decision, args_for_execution = _evaluate_call(**evaluate_kwargs)
    if not decision.allowed:
        raise ToolCallDenied(decision)
    return execute(args_for_execution)


async def _mediate_async(
    execute: Callable[[dict[str, Any]], Awaitable[Any]],
    **evaluate_kwargs: Any,
) -> Any:
    decision, args_for_execution = _evaluate_call(**evaluate_kwargs)
    if not decision.allowed:
        raise ToolCallDenied(decision)
    return await execute(args_for_execution)


def _normalize_tool_input(
    tool: BaseTool, tool_input: str | dict[str, Any]
) -> tuple[dict[str, Any], str | None]:
    """Turn whatever shape a caller used (a plain dict of kwargs, a bare
    string for a single-argument tool, or a LangChain ToolCall dict) into a
    plain args dict, so every downstream CallRecord has a consistent shape
    regardless of call style.
    """
    if isinstance(tool_input, dict):
        looks_like_tool_call = isinstance(tool_input.get("args"), dict) and (
            "id" in tool_input or tool_input.get("type") == "tool_call"
        )
        if looks_like_tool_call:
            return dict(tool_input["args"]), tool_input.get("id")
        return dict(tool_input), None
    if isinstance(tool_input, str):
        param_names = list(tool.args.keys())
        if len(param_names) == 1:
            return {param_names[0]: tool_input}, None
        # Ambiguous: a bare string for a multi-arg tool. Phase 1 doesn't
        # need to solve this — no scenario tool uses it — so it's recorded
        # under a sentinel key rather than guessed at.
        return {"__raw_string_input__": tool_input}, None
    raise TypeError(f"Unsupported tool input type: {type(tool_input).__name__}")


class GuardedTool:
    """The wrapper `GuardedToolRegistry.register()` returns. Every method
    here is a thin adapter that normalizes its input and calls
    `_mediate_sync`/`_mediate_async` — there is deliberately no other way
    for this class to reach `self._original`.
    """

    def __init__(
        self,
        original: BaseTool,
        evaluator: Evaluator,
        sequence_counters: _SequenceCounters,
        hitl_resolver: HitlResolver | None = None,
    ) -> None:
        self._original = original
        self._evaluator = evaluator
        self._sequence_counters = sequence_counters
        self._hitl_resolver = hitl_resolver
        # Standard "this wraps something" marker (the convention
        # functools.wraps uses) — the INV-02 bypass-audit test's reflective
        # sweep checks every tool handed to an agent carries this.
        self.__wrapped__ = original

    @property
    def name(self) -> str:
        return self._original.name

    @property
    def description(self) -> str:
        return self._original.description

    def __repr__(self) -> str:
        return f"GuardedTool(name={self.name!r})"

    def invoke(
        self,
        input: str | dict[str, Any],
        config: Any = None,
        **kwargs: Any,
    ) -> Any:
        args, tool_call_id = _normalize_tool_input(self._original, input)

        def execute(final_args: dict[str, Any]) -> Any:
            return self._original.invoke(final_args, config=config, **kwargs)

        return _mediate_sync(
            execute,
            tool_name=self.name,
            raw_args=args,
            evaluator=self._evaluator,
            sequence_counters=self._sequence_counters,
            tool_call_id=tool_call_id,
            hitl_resolver=self._hitl_resolver,
        )

    async def ainvoke(
        self,
        input: str | dict[str, Any],
        config: Any = None,
        **kwargs: Any,
    ) -> Any:
        args, tool_call_id = _normalize_tool_input(self._original, input)

        async def execute(final_args: dict[str, Any]) -> Any:
            return await self._original.ainvoke(final_args, config=config, **kwargs)

        return await _mediate_async(
            execute,
            tool_name=self.name,
            raw_args=args,
            evaluator=self._evaluator,
            sequence_counters=self._sequence_counters,
            tool_call_id=tool_call_id,
            hitl_resolver=self._hitl_resolver,
        )

    def run(self, tool_input: str | dict[str, Any], **kwargs: Any) -> Any:
        args, tool_call_id = _normalize_tool_input(self._original, tool_input)

        def execute(final_args: dict[str, Any]) -> Any:
            return self._original.run(final_args, **kwargs)

        return _mediate_sync(
            execute,
            tool_name=self.name,
            raw_args=args,
            evaluator=self._evaluator,
            sequence_counters=self._sequence_counters,
            tool_call_id=tool_call_id,
            hitl_resolver=self._hitl_resolver,
        )

    async def arun(self, tool_input: str | dict[str, Any], **kwargs: Any) -> Any:
        args, tool_call_id = _normalize_tool_input(self._original, tool_input)

        async def execute(final_args: dict[str, Any]) -> Any:
            return await self._original.arun(final_args, **kwargs)

        return await _mediate_async(
            execute,
            tool_name=self.name,
            raw_args=args,
            evaluator=self._evaluator,
            sequence_counters=self._sequence_counters,
            tool_call_id=tool_call_id,
            hitl_resolver=self._hitl_resolver,
        )

    def batch(
        self, inputs: Iterable[str | dict[str, Any]], config: Any = None, **kwargs: Any
    ) -> list[Any]:
        # An explicit loop over self.invoke() — not a Runnable.batch()
        # override — so total mediation never depends on trusting an
        # inherited default we haven't independently verified.
        return [self.invoke(item, config=config, **kwargs) for item in inputs]

    async def abatch(
        self, inputs: Iterable[str | dict[str, Any]], config: Any = None, **kwargs: Any
    ) -> list[Any]:
        return [await self.ainvoke(item, config=config, **kwargs) for item in inputs]


class GuardedToolRegistry:
    """The real enforcement point (INV-02). Every tool an agent can call
    must come from `.register()` and be handed to the agent via
    `.get_tools_for_agent()` — nothing else exposes a callable tool.
    """

    def __init__(
        self, evaluator: Evaluator, hitl_resolver: HitlResolver | None = None
    ) -> None:
        self._evaluator = evaluator
        self._hitl_resolver = hitl_resolver
        self._sequence_counters = _SequenceCounters()
        self._guarded_tools: dict[str, GuardedTool] = {}

    def register(self, tool: BaseTool) -> GuardedTool:
        guarded = GuardedTool(
            tool, self._evaluator, self._sequence_counters, self._hitl_resolver
        )
        self._guarded_tools[guarded.name] = guarded
        return guarded

    def get_tools_for_agent(self) -> list[GuardedTool]:
        """The only tool list that should ever be bound to an LLM or handed
        to an agent executor."""
        return list(self._guarded_tools.values())

    def unguarded_tools(self) -> list[str]:
        """Names of anything this registry tracks that is not, in fact, a
        GuardedTool. Should always be empty through the public API alone —
        this is the structural self-check the INV-02 bypass-audit test
        asserts on.
        """
        return [
            name
            for name, guarded_tool in self._guarded_tools.items()
            if not isinstance(guarded_tool, GuardedTool)
        ]


_F = TypeVar("_F", bound=Callable[..., Any])


def firewall_guard(
    evaluator: Evaluator, hitl_resolver: HitlResolver | None = None
) -> Callable[[_F], _F]:
    """Developer sugar: guard a single plain function (sync or async) the
    same way GuardedToolRegistry guards a LangChain tool.

    This is NOT the enforcement point (INV-02) — it only protects call
    sites that go through the name this decorator returns. Anyone holding
    a reference to the pre-decoration function bypasses it entirely. That
    residual is real, documented, and tested (see
    test_INV_02_direct_reference_bypasses_registry and THREAT_MODEL.md R-1)
    rather than hidden.
    """
    sequence_counters = _SequenceCounters()

    def decorator(func: _F) -> _F:
        signature = inspect.signature(func)

        def bind_kwargs(
            args: tuple[Any, ...], kwargs: dict[str, Any]
        ) -> dict[str, Any]:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            return dict(bound.arguments)

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                raw_args = bind_kwargs(args, kwargs)

                async def execute(final_args: dict[str, Any]) -> Any:
                    return await func(**final_args)

                return await _mediate_async(
                    execute,
                    tool_name=func.__name__,
                    raw_args=raw_args,
                    evaluator=evaluator,
                    sequence_counters=sequence_counters,
                    tool_call_id=None,
                    hitl_resolver=hitl_resolver,
                )

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            raw_args = bind_kwargs(args, kwargs)

            def execute(final_args: dict[str, Any]) -> Any:
                return func(**final_args)

            return _mediate_sync(
                execute,
                tool_name=func.__name__,
                raw_args=raw_args,
                evaluator=evaluator,
                sequence_counters=sequence_counters,
                tool_call_id=None,
                hitl_resolver=hitl_resolver,
            )

        return sync_wrapper  # type: ignore[return-value]

    return decorator
