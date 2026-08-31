"""Policy schema — Phase 3.

Every policy file is validated against these Pydantic v2 models at load
time. A malformed policy file must be a precise, immediate startup
failure (CLAUDE.md §3: "never a silent skip and never a runtime crash") —
Pydantic's `ValidationError` gives us exactly that: a specific field, a
specific reason, raised the moment the file is parsed, never at decision
time.

Six rule types, matching the shapes CLAUDE.md's Phase 3 spec names:
`parameter_bounds`, `path_scope`, `domain_allowlist`, `sequence`, `rbac`,
`rate`. Every rule carries a `tool` (which tool it applies to, or `"*"`
for any), an `action` (what it contributes when it matches), and an
optional `requires_approval` flag.

Design note on `action` (see ADR 0009 for the full reasoning): allowlist-
shaped rules (`path_scope`, `domain_allowlist`, `rbac`) are written as
`action: allow` and match when the call *is* within scope — the DENY-by-
default (INV-08) handles everything else, so there's no need to also
author an explicit "deny if out of scope" rule. Gate/bound-shaped rules
(`parameter_bounds`, `sequence`, `rate`) are written as `action: deny` and
match when the call *violates* the bound — this is what lets a narrow
DENY rule override a broader ALLOW rule (DENY wins — INV-08's conflict
resolution), which a rule that only ever "voted ALLOW when satisfied"
could not do.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RuleAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class _BaseRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(
        min_length=1, description="Unique rule ID, used in Decision.rule_id."
    )
    tool: str = Field(
        min_length=1,
        description='The tool name this rule applies to, or "*" for every tool.',
    )
    action: RuleAction
    requires_approval: bool = Field(
        default=False,
        description="If true and this rule would ALLOW, escalate to NEEDS_APPROVAL instead.",
    )
    description: str = Field(
        default="",
        description="Human-readable explanation, for POLICY_GUIDE.md-style review.",
    )

    @model_validator(mode="after")
    def _requires_approval_only_on_allow(self) -> _BaseRule:
        if self.requires_approval and self.action != RuleAction.ALLOW:
            raise ValueError(
                "requires_approval only makes sense on an action: allow rule "
                "(a deny rule already blocks the call outright — there is "
                "nothing left to approve)"
            )
        return self


class ParameterBoundsRule(_BaseRule):
    type: Literal["parameter_bounds"]
    parameter: str = Field(min_length=1)
    min: float | None = None
    max: float | None = None
    max_length: int | None = Field(default=None, gt=0)
    pattern: str | None = Field(
        default=None,
        description="A regex (compiled with the `regex` package, linted and timeout-bounded — INV-09). Matches trigger the rule.",
    )

    @model_validator(mode="after")
    def _at_least_one_bound(self) -> ParameterBoundsRule:
        if (
            self.min is None
            and self.max is None
            and self.max_length is None
            and self.pattern is None
        ):
            raise ValueError(
                "parameter_bounds rule must set at least one of: min, max, max_length, pattern"
            )
        return self


class PathScopeRule(_BaseRule):
    type: Literal["path_scope"]
    parameter: str = Field(min_length=1)
    allowed_roots: tuple[str, ...] = Field(min_length=1)
    roles: tuple[str, ...] = Field(
        default_factory=tuple,
        description=(
            "Optional: restrict this grant to these roles. Empty (the "
            "default) means unrestricted by role — see ADR 0012 for why "
            "that default is dangerous whenever an rbac rule elsewhere "
            "means to gate the same tool: an unrestricted path_scope "
            "rule independently grants ALLOW regardless of role, which "
            "bypasses an rbac rule's restriction rather than composing "
            "with it (conflict resolution treats every matching ALLOW "
            "vote as sufficient on its own, not as one of several "
            "conditions that must all hold)."
        ),
    )


class DomainAllowlistRule(_BaseRule):
    type: Literal["domain_allowlist"]
    parameter: str = Field(min_length=1)
    allowed_domains: tuple[str, ...] = Field(min_length=1)
    roles: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Optional: restrict this grant to these roles. Empty means unrestricted by role — see ADR 0012.",
    )


class SequenceRule(_BaseRule):
    type: Literal["sequence"]
    requires_prior_tools: tuple[str, ...] = Field(
        min_length=1,
        description="All of these tools must already appear earlier in this session's call history.",
    )


class RbacRule(_BaseRule):
    type: Literal["rbac"]
    roles: tuple[str, ...] = Field(
        min_length=1, description="Roles permitted to call this tool."
    )


class RateRule(_BaseRule):
    type: Literal["rate"]
    max_calls: int = Field(
        gt=0, description="Maximum calls to this tool allowed within the window."
    )
    window_seconds: float = Field(gt=0)


class ParameterSchemaRule(_BaseRule):
    """Declares the full set of parameter names a tool call is allowed to
    carry (INV-08: "unknown parameter -> DENY", never an implicit allow).

    `action` and `requires_approval` are inherited from `_BaseRule` but
    unused by this rule type — always author `action: allow`,
    `requires_approval: false` by convention; the engine ignores both
    fields for `parameter_schema` rules (see
    `firewall/policy_engine.py::_check_unknown_parameters`). Kept on
    `_BaseRule` rather than given a separate base class to avoid a second
    schema hierarchy for one rule type — see ADR 0011.
    """

    type: Literal["parameter_schema"]
    known_parameters: tuple[str, ...] = Field(
        min_length=1,
        description="Every parameter name this tool's calls may legitimately carry.",
    )


PolicyRule = Annotated[
    ParameterBoundsRule
    | PathScopeRule
    | DomainAllowlistRule
    | SequenceRule
    | RbacRule
    | RateRule
    | ParameterSchemaRule,
    Field(discriminator="type"),
]


class PolicySet(BaseModel):
    """The fully-loaded, validated set of rules from every file under
    `policies/`. Frozen (INV-03: loaded once at startup, never mutated).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    default_action: RuleAction = Field(
        default=RuleAction.DENY,
        description="Outcome when no rule matches a call (INV-08 ships this as DENY).",
    )
    rules: tuple[PolicyRule, ...] = Field(default_factory=tuple)

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> PolicySet:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id: {rule.id!r}")
            seen.add(rule.id)
        return self
