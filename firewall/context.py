"""Principal binding (INV-05).

The interceptor must know *who* is making a tool call — session ID, agent
identity, and RBAC role — to hand to the policy engine. INV-05 says that
information can never come from the tool call's own arguments (an attacker
who controls what the LLM writes could otherwise just pass
`role="admin"` as a kwarg and grant themselves anything).

Instead, the principal is set exactly once, by trusted server-side code, at
session creation — before any agent code runs — using a `contextvars.ContextVar`.
`ContextVar` is the right primitive here rather than a plain global or a
thread-local: it is automatically isolated per `asyncio` Task as well as per
thread, so two concurrent sessions (sync or async) can never see each
other's principal, with no locking required.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    """Who is making tool calls in the current session.

    Frozen because a principal must not be mutated mid-session — if the role
    needs to change, bind a new Principal for a new context instead.
    """

    session_id: str
    identity: str
    role: str


class PrincipalNotBoundError(RuntimeError):
    """Raised when firewall code asks for the current principal outside of
    any bound session.

    This is deliberate fail-closed behavior (INV-01): if nobody has proven
    who is calling, the interceptor cannot evaluate a call at all, and must
    not guess or fall back to some default identity.
    """


_current_principal: ContextVar[Principal | None] = ContextVar(
    "praetor_current_principal", default=None
)


@contextmanager
def bind_principal(principal: Principal) -> Iterator[Principal]:
    """Bind `principal` as the current principal for the duration of the
    `with` block (and any code called within it, including across `await`
    points in the same task, and in any thread spawned that copies context).

    Trusted server-side code calls this once at session creation — nothing
    reachable from agent/tool code should ever call it with attacker-
    influenced values.
    """
    token: Token[Principal | None] = _current_principal.set(principal)
    try:
        yield principal
    finally:
        _current_principal.reset(token)


def get_current_principal() -> Principal:
    """Return the principal bound by the nearest enclosing `bind_principal`.

    Raises PrincipalNotBoundError if nothing is bound — there is no default
    principal, because a default would be a silent privilege decision.
    """
    principal = _current_principal.get()
    if principal is None:
        raise PrincipalNotBoundError(
            "No principal is bound in this context. Tool calls cannot be "
            "evaluated without a trusted session_id/identity/role — wrap "
            "the call in `with bind_principal(...):` at session creation, "
            "not inside agent-reachable code (INV-05)."
        )
    return principal
