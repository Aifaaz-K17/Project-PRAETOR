"""Test-only Evaluator implementations for Phase 1's interception tests.

Not a real policy engine (that's Phase 3) — these exist purely to exercise
the interceptor's mediation mechanics: does every path call the evaluator,
does a crash fail closed, does a mutation get ignored, does the principal
(not the args) decide role-based outcomes.

Named with a leading underscore, and not matching `test_*.py`, so pytest
never collects this file as a test module itself.
"""

from __future__ import annotations

from firewall.interceptor import CallRecord, Decision, Evaluator


class RecordingEvaluator(Evaluator):
    """Base class: remembers every CallRecord it was asked to evaluate, so
    tests can assert on how many times (and with what) the evaluator was
    actually invoked."""

    def __init__(self) -> None:
        self.calls: list[CallRecord] = []

    def evaluate(self, call: CallRecord) -> Decision:
        self.calls.append(call)
        return self._decide(call)

    def _decide(self, call: CallRecord) -> Decision:
        raise NotImplementedError


class AllowAllEvaluator(RecordingEvaluator):
    def _decide(self, call: CallRecord) -> Decision:
        return Decision.allow(reason="test evaluator: allow all")


class DenyAllEvaluator(RecordingEvaluator):
    def _decide(self, call: CallRecord) -> Decision:
        return Decision.deny(reason="test evaluator: deny all")


class CrashingEvaluator(RecordingEvaluator):
    """Simulates a bug in a real policy engine — must be turned into a
    fail-closed DENY by the interceptor, never let the exception through
    and never allow the call."""

    def _decide(self, call: CallRecord) -> Decision:
        raise RuntimeError("simulated policy engine crash")


class MutatingEvaluator(RecordingEvaluator):
    """Simulates a careless or hostile policy hook that mutates the args it
    was handed. INV-07 requires this to have no effect on what the tool
    actually executes with."""

    def __init__(self, mutated_value: str = "MUTATED_BY_POLICY_HOOK") -> None:
        super().__init__()
        self._mutated_value = mutated_value

    def _decide(self, call: CallRecord) -> Decision:
        for key in list(call.canonical_args.keys()):
            call.canonical_args[key] = self._mutated_value
        return Decision.allow(reason="test evaluator: allow after mutating args")


class RoleGatedEvaluator(RecordingEvaluator):
    """Allows only calls whose CallRecord.role equals `required_role`. Used
    to prove the role that matters is the one bound via contextvars, not
    anything the caller put in the tool's own arguments (INV-05)."""

    def __init__(self, required_role: str) -> None:
        super().__init__()
        self._required_role = required_role

    def _decide(self, call: CallRecord) -> Decision:
        if call.role == self._required_role:
            return Decision.allow(reason=f"role {call.role} matches required")
        return Decision.deny(
            reason=f"role {call.role} != required {self._required_role}"
        )
