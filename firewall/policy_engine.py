"""Policy engine — Phase 3.

Loads YAML policy files once at startup into a frozen, hashed
`LoadedPolicySet` (INV-03), and evaluates a `CallRecord` against it via the
pure function `evaluate_call` (INV-13: same inputs always produce the same
`Decision`, and an empty rule set never produces ALLOW — INV-08).
`PolicyEngine` is the thin adapter that satisfies
`firewall.interceptor.Evaluator` so it can be plugged straight into a
`GuardedToolRegistry`.

Conflict resolution (see ADR 0009 for the full reasoning): among every
rule that matches a call, DENY beats NEEDS_APPROVAL beats ALLOW; no match
at all falls through to the policy set's `default_action`, which every
policy file this project ships uses as DENY.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import regex
import yaml
from pydantic import ValidationError

from firewall.anomaly import apply_anomaly_findings, detect_anomalies
from firewall.canonicalize import (
    canonical_email,
    canonical_host,
    canonical_path,
    canonical_text,
    matches_domain_allowlist,
)
from firewall.interceptor import CallRecord, Decision, Outcome
from firewall.logger import AuditLogger
from firewall.policy_schema import (
    DomainAllowlistRule,
    ParameterBoundsRule,
    ParameterSchemaRule,
    PathScopeRule,
    PolicyRule,
    PolicySet,
    RateRule,
    RbacRule,
    RuleAction,
    SequenceRule,
)
from firewall.session import SessionHistoryEntry, SessionStore

# --- INV-09: bounded evaluation ------------------------------------------

MAX_ARG_COUNT = 50
MAX_STRING_LENGTH = 65536
MAX_NESTING_DEPTH = 10
MAX_RULE_COUNT = 500
REGEX_TIMEOUT_SECONDS = 0.5

# A path_scope rule's allowed_roots (e.g. "sandbox" in policies/path_scope.yaml)
# is authored relative to the repo root, not to whatever directory the
# process happens to be launched from. Anchoring it here means
# `python -m demo_agent.interception_demo` (or a future FastAPI service
# with its own working directory) resolves "sandbox" the same way
# regardless of caller cwd — previously a relative allowed_root was left
# to Path.resolve()'s implicit cwd-relative behavior, so running from any
# directory other than the repo root would resolve to a different,
# probably-nonexistent path and silently deny every in-scope call (fails
# safe, but confusingly — found by code review).
_REPO_ROOT = Path(__file__).resolve().parent.parent


def _resolve_allowed_root(root: str) -> Path:
    root_path = Path(root)
    return root_path if root_path.is_absolute() else _REPO_ROOT / root_path


class PolicyLoadError(Exception):
    """Raised when policies/ cannot be loaded safely. The process should
    refuse to start rather than run with a partially-loaded or unsafe
    policy set — there is no "load what we can" fallback."""


class PolicyBoundsExceeded(Exception):
    """A call's arguments exceeded an INV-09 cap."""


class PolicyEvaluationTimeout(Exception):
    """A rule's regex evaluation exceeded its timeout (INV-09)."""


# --- ReDoS-prone pattern linting ------------------------------------------
#
# Best-effort static check for well-known catastrophic-backtracking shapes
# (nested quantifiers like (a+)+, and overlapping alternation like (a|aa)+).
# This is NOT exhaustive — detecting every possible ReDoS shape is
# undecidable in general — the actual hard guarantee is the runtime
# timeout in _matches_parameter_bounds. This linter exists to reject the
# most obvious cases at load time, before any real call ever reaches them.

_NESTED_QUANTIFIER_RE = regex.compile(r"\([^()]*[+*]\)[+*?]|\([^()]*\{\d*,\}\)[+*?]")
_OVERLAPPING_ALTERNATION_RE = regex.compile(r"\([^()|]*\|[^()]*\)[+*]")


def _lint_pattern_for_redos(pattern: str, *, rule_id: str) -> None:
    if _NESTED_QUANTIFIER_RE.search(pattern) or _OVERLAPPING_ALTERNATION_RE.search(
        pattern
    ):
        raise PolicyLoadError(
            f"rule {rule_id!r}: pattern {pattern!r} looks like a nested-quantifier "
            "ReDoS shape (e.g. (a+)+ or (a|aa)+) and is rejected at load time"
        )


def _compile_pattern(pattern: str, *, rule_id: str) -> regex.Pattern:
    _lint_pattern_for_redos(pattern, rule_id=rule_id)
    try:
        return regex.compile(pattern)
    except regex.error as exc:
        raise PolicyLoadError(
            f"rule {rule_id!r}: invalid regex {pattern!r}: {exc}"
        ) from exc


# --- INV-09: argument size / nesting caps ---------------------------------


def _check_bounds(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise PolicyBoundsExceeded(
            f"argument nesting exceeds max depth {MAX_NESTING_DEPTH}"
        )
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise PolicyBoundsExceeded(
                f"string argument exceeds max length {MAX_STRING_LENGTH}"
            )
    elif isinstance(value, dict):
        if len(value) > MAX_ARG_COUNT:
            raise PolicyBoundsExceeded(f"argument count exceeds max {MAX_ARG_COUNT}")
        for v in value.values():
            _check_bounds(v, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > MAX_ARG_COUNT:
            raise PolicyBoundsExceeded(
                f"argument list length exceeds max {MAX_ARG_COUNT}"
            )
        for v in value:
            _check_bounds(v, depth=depth + 1)


# --- Loading ---------------------------------------------------------------


@dataclass(frozen=True)
class LoadedPolicySet:
    """The result of `load_policy_set`: a validated, frozen `PolicySet`
    plus its integrity hash and pre-compiled regex patterns."""

    policy_set: PolicySet
    policy_set_hash: str
    compiled_patterns: dict[str, regex.Pattern]


def load_policy_set(policy_dir: str | Path) -> LoadedPolicySet:
    """Load and validate every `*.yaml`/`*.yml` file under `policy_dir`,
    in sorted order (for a deterministic hash and deterministic rule
    ordering). `yaml.safe_load` only (never `yaml.load`) — CLAUDE.md §3.
    """
    policy_dir = Path(policy_dir)
    yaml_files = sorted(set(policy_dir.glob("*.yaml")) | set(policy_dir.glob("*.yml")))

    if not yaml_files:
        raise PolicyLoadError(f"no policy files found in {policy_dir}")

    hasher = hashlib.sha256()
    all_rules: list[PolicyRule] = []
    default_action = RuleAction.DENY
    default_action_file: Path | None = None

    for file_path in yaml_files:
        raw_bytes = file_path.read_bytes()
        hasher.update(file_path.name.encode("utf-8"))
        hasher.update(raw_bytes)

        try:
            raw_doc = yaml.safe_load(raw_bytes)
        except yaml.YAMLError as exc:
            raise PolicyLoadError(f"{file_path}: invalid YAML: {exc}") from exc

        if raw_doc is None:
            continue

        try:
            file_policy_set = PolicySet.model_validate(raw_doc)
        except ValidationError as exc:
            raise PolicyLoadError(
                f"{file_path}: schema validation failed: {exc}"
            ) from exc

        if isinstance(raw_doc, dict) and "default_action" in raw_doc:
            if (
                default_action_file is not None
                and file_policy_set.default_action != default_action
            ):
                raise PolicyLoadError(
                    f"{file_path}: default_action ({file_policy_set.default_action.value}) "
                    f"conflicts with {default_action_file} ({default_action.value})"
                )
            default_action = file_policy_set.default_action
            default_action_file = file_path

        all_rules.extend(file_policy_set.rules)

    if len(all_rules) > MAX_RULE_COUNT:
        raise PolicyLoadError(
            f"total rule count {len(all_rules)} exceeds max {MAX_RULE_COUNT}"
        )

    try:
        merged = PolicySet(default_action=default_action, rules=tuple(all_rules))
    except ValidationError as exc:
        raise PolicyLoadError(
            f"merged policy set is invalid (likely a duplicate rule id): {exc}"
        ) from exc

    compiled_patterns: dict[str, regex.Pattern] = {}
    for rule in merged.rules:
        if isinstance(rule, ParameterBoundsRule) and rule.pattern is not None:
            compiled_patterns[rule.id] = _compile_pattern(rule.pattern, rule_id=rule.id)

    return LoadedPolicySet(
        policy_set=merged,
        policy_set_hash=hasher.hexdigest(),
        compiled_patterns=compiled_patterns,
    )


# --- Per-rule-type matching -------------------------------------------------


def _rule_applies_to_tool(rule: PolicyRule, tool_name: str) -> bool:
    return rule.tool == "*" or rule.tool == tool_name


def _check_unknown_parameters(call: CallRecord, loaded: LoadedPolicySet) -> str | None:
    """INV-08: "unknown parameter -> DENY, never an implicit allow."

    Enforcement is opt-in per tool: a tool with at least one
    `parameter_schema` rule in the loaded policy set must have every
    argument on the call declared in `known_parameters` (the union across
    every matching schema rule), or the call is denied outright. A tool
    with *no* `parameter_schema` rule declared in the loaded set is not
    checked here at all — deliberately, not an oversight (see
    LIMITATIONS.md and ADR 0011): a blanket "every tool must have a schema
    or nothing gets through" would also fire inside every test that
    builds a small synthetic rule set to isolate one piece of conflict-
    resolution logic, breaking tests that were never exercising this
    feature. All five tools this project ships policies for
    (`policies/parameter_schema.yaml`) do declare one.
    """
    schema_rules = [
        rule
        for rule in loaded.policy_set.rules
        if isinstance(rule, ParameterSchemaRule)
        and _rule_applies_to_tool(rule, call.tool_name)
    ]
    if not schema_rules:
        return None

    known: set[str] = set()
    for rule in schema_rules:
        known.update(rule.known_parameters)

    unknown = sorted(set(call.canonical_args.keys()) - known)
    if unknown:
        return f"unknown parameter(s) for tool {call.tool_name!r}: {unknown}"
    return None


def _coerce_numeric(value: Any) -> float | None:
    """Best-effort numeric coercion for a `min`/`max` bounds check.

    A native `int`/`float` (never `bool` — `bool` is a `int` subclass in
    Python, and a boolean has no sensible reading as an amount) is
    returned as-is. A numeric-looking `str` (e.g. `"amount": "500"`
    instead of a bare JSON number — a real, observed shape: LLM
    tool-calling output is parsed from JSON text, and a model can emit a
    number as a quoted string) is parsed with `float()`. Anything else —
    an unparseable string, `None` already excluded by the caller, a list,
    a dict, a `bool` — returns `None`, and the caller treats that as a
    bounds violation rather than silently skipping the check (INV-01):
    see `test_INV_01_policy_bounds_string_typed_amount_still_enforced`
    for the real bypass this closes.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _matches_parameter_bounds(
    rule: ParameterBoundsRule,
    call: CallRecord,
    compiled_patterns: dict[str, regex.Pattern],
) -> bool:
    value = call.canonical_args.get(rule.parameter)
    if value is None:
        return False
    if rule.min is not None or rule.max is not None:
        numeric_value = _coerce_numeric(value)
        if numeric_value is None:
            # Not a type/shape a min/max bound can safely be evaluated
            # against (wrong type, unparseable string, a bool) — fail
            # closed rather than silently treat "can't check" as "no
            # bound applies". A real bug this fixed: `amount: "999999"`
            # (a numeric string) sailed straight past
            # `bounds-transfer-max-amount` (max: 1000), because the old
            # check only ever compared a native int/float — see ADR 0014.
            return True
        if rule.min is not None and numeric_value < rule.min:
            return True
        if rule.max is not None and numeric_value > rule.max:
            return True

    if rule.max_length is not None or rule.pattern is not None:
        # Text-shaped checks (length, denylist pattern) must run against
        # canonicalized text (INV-06), not the raw value — otherwise a
        # percent-encoded or zero-width-obfuscated payload sails straight
        # past a denylist regex that only ever sees the raw string. This
        # was a real bug: canonical_text() existed but was never called
        # from here (found by code review, see LIMITATIONS.md).
        text_result = canonical_text(str(value))
        if not text_result.ok:
            # A value the firewall can't even safely canonicalize is a
            # bounds violation, not something to silently skip past —
            # fail closed (INV-01/INV-06).
            return True
        normalized = text_result.value
        if normalized is None:
            # Unreachable given text_result.ok above, but `assert` is
            # stripped under `python -O` (bandit B101) — stay a real,
            # non-optimizable safeguard rather than trusting that
            # invariant to hold forever.
            raise RuntimeError(
                "canonical_text reported ok=True but returned no value — this is a bug"
            )

        if rule.max_length is not None and len(normalized) > rule.max_length:
            return True

        if rule.pattern is not None:
            pattern = compiled_patterns[rule.id]
            try:
                if pattern.search(normalized, timeout=REGEX_TIMEOUT_SECONDS):
                    return True
            except TimeoutError as exc:
                raise PolicyEvaluationTimeout(
                    f"rule {rule.id!r} regex evaluation exceeded {REGEX_TIMEOUT_SECONDS}s"
                ) from exc

    return False


def _matches_path_scope(rule: PathScopeRule, call: CallRecord) -> bool:
    if rule.roles and call.role not in rule.roles:
        return False
    value = call.canonical_args.get(rule.parameter)
    if not isinstance(value, str):
        return False
    resolved_roots = [_resolve_allowed_root(root) for root in rule.allowed_roots]
    return canonical_path(value, allowed_roots=resolved_roots).ok


def _matches_domain_allowlist(rule: DomainAllowlistRule, call: CallRecord) -> bool:
    if rule.roles and call.role not in rule.roles:
        return False
    value = call.canonical_args.get(rule.parameter)
    if not isinstance(value, str):
        return False

    host_result = canonical_host(value)
    canonical = host_result.value
    if not host_result.ok or canonical is None:
        # Not a bare hostname — try it as an email address instead, so the
        # same rule type covers both a bare-host parameter (e.g. a fetch
        # target) and an email parameter (e.g. send_email's "to"), which is
        # the realistic case CLAUDE.md's Phase 3 spec names ("domain
        # allowlists"). Extract just the domain part of the (already
        # spoofing-checked) canonical email.
        email_result = canonical_email(value)
        if not email_result.ok or email_result.value is None:
            return False
        canonical = email_result.value.rsplit("@", 1)[-1]

    return any(
        matches_domain_allowlist(canonical, domain) for domain in rule.allowed_domains
    )


def _matches_sequence(
    rule: SequenceRule, session_history: Sequence[SessionHistoryEntry]
) -> bool:
    prior_tools = {tool_name for tool_name, _ in session_history}
    missing = [t for t in rule.requires_prior_tools if t not in prior_tools]
    return bool(missing)  # triggers (as a DENY) when something required is missing


def _matches_rbac(rule: RbacRule, call: CallRecord) -> bool:
    return call.role in rule.roles


def _matches_rate(
    rule: RateRule, call: CallRecord, session_history: Sequence[SessionHistoryEntry]
) -> bool:
    window_start = call.timestamp_utc - timedelta(seconds=rule.window_seconds)
    count_in_window = sum(
        1
        for tool_name, called_at in session_history
        if tool_name == call.tool_name
        and window_start <= called_at <= call.timestamp_utc
    )
    return count_in_window >= rule.max_calls  # this call would exceed the cap


def _rule_matches(
    rule: PolicyRule,
    call: CallRecord,
    compiled_patterns: dict[str, regex.Pattern],
    session_history: Sequence[SessionHistoryEntry],
) -> bool:
    if isinstance(rule, ParameterBoundsRule):
        return _matches_parameter_bounds(rule, call, compiled_patterns)
    if isinstance(rule, PathScopeRule):
        return _matches_path_scope(rule, call)
    if isinstance(rule, DomainAllowlistRule):
        return _matches_domain_allowlist(rule, call)
    if isinstance(rule, SequenceRule):
        return _matches_sequence(rule, session_history)
    if isinstance(rule, RbacRule):
        return _matches_rbac(rule, call)
    if isinstance(rule, RateRule):
        return _matches_rate(rule, call, session_history)
    raise AssertionError(
        f"unhandled rule type: {type(rule).__name__}"
    )  # pragma: no cover


# --- Evaluation --------------------------------------------------------------


def evaluate_call(
    call: CallRecord,
    loaded: LoadedPolicySet,
    session_history: Sequence[SessionHistoryEntry] = (),
) -> Decision:
    """Pure: the same `(call, loaded, session_history)` always produces the
    same `Decision` (INV-13), and an empty `loaded.policy_set.rules` never
    produces ALLOW (INV-08 — falls through to `default_action`, which
    every shipped policy file sets to DENY).
    """
    try:
        _check_bounds(call.canonical_args)
    except PolicyBoundsExceeded as exc:
        return Decision.deny(reason=f"POLICY_ERROR: {exc}")

    unknown_parameter_reason = _check_unknown_parameters(call, loaded)
    if unknown_parameter_reason is not None:
        return Decision.deny(reason=unknown_parameter_reason)

    matched_deny: PolicyRule | None = None
    matched_needs_approval: PolicyRule | None = None
    matched_allow: PolicyRule | None = None

    for rule in loaded.policy_set.rules:
        if isinstance(rule, ParameterSchemaRule):
            # Consulted once, upfront, above — not a normal ALLOW/DENY vote.
            continue
        if not _rule_applies_to_tool(rule, call.tool_name):
            continue

        try:
            matched = _rule_matches(
                rule, call, loaded.compiled_patterns, session_history
            )
        except PolicyEvaluationTimeout as exc:
            # Fail closed on the whole call, not just this rule — treating
            # a timed-out rule as "did not match" could silently allow
            # exactly the call it existed to catch.
            return Decision.deny(reason=f"POLICY_ERROR: {exc}")

        if not matched:
            continue

        if rule.action == RuleAction.DENY:
            matched_deny = matched_deny or rule
        elif rule.requires_approval:
            matched_needs_approval = matched_needs_approval or rule
        else:
            matched_allow = matched_allow or rule

    # Conflict resolution (ADR 0009): DENY > NEEDS_APPROVAL > ALLOW > default.
    if matched_deny is not None:
        return Decision.deny(
            reason=f"denied by rule {matched_deny.id}", rule_id=matched_deny.id
        )
    if matched_needs_approval is not None:
        return Decision.needs_approval(
            reason=f"requires approval per rule {matched_needs_approval.id}",
            rule_id=matched_needs_approval.id,
        )
    if matched_allow is not None:
        return Decision.allow(
            reason=f"allowed by rule {matched_allow.id}", rule_id=matched_allow.id
        )

    if loaded.policy_set.default_action == RuleAction.DENY:
        return Decision.deny(reason="no matching rule; default_action=deny")
    return Decision.allow(reason="no matching rule; default_action=allow")


class PolicyEngine:
    """Adapter satisfying `firewall.interceptor.Evaluator` (structural
    typing — no inheritance needed). Wraps a `LoadedPolicySet` and can be
    handed straight to `GuardedToolRegistry(evaluator=...)`.

    `session_store`, if given, is what makes `sequence`/`rate` rules
    actually exercisable through the live interceptor (Phase 4,
    `firewall/session.py`) — `evaluate()` reads that session's history
    before deciding, and records the call into it afterward, but *only*
    when the decision was ALLOW: a denied or needs-approval call never
    happened as far as a later `sequence` rule is concerned, since it
    never actually executed. Without a `session_store` (the default),
    this behaves exactly as it did through Phase 3 — always an empty
    history, the fail-closed-correct default for a session nothing is
    tracking.

    `audit_logger`, if given, gets every decision — ALLOW, DENY, and
    NEEDS_APPROVAL alike (INV-10/INV-11's "shadow logging": allowed calls
    are logged too, not just denials). `latency_ns` measures only this
    method's own `evaluate_call` + session-history + anomaly-detection
    work, not the interceptor's argument handling or the tool's own
    execution time — consistent with Phase 7's evaluation harness wanting
    the firewall's overhead specifically, not the whole call's wall-clock
    time.

    `enable_anomaly_detection`, if `True` (default `False`), runs
    `firewall.anomaly.detect_anomalies` after `evaluate_call` and folds
    any findings into the decision via `apply_anomaly_findings` — see
    ADR 0013. Opt-in and requires `session_store` (three of the four
    detectors need real session history/declared-tools state; without a
    `session_store` those three would always see empty inputs and never
    fire, which is misleading enough to refuse outright rather than
    silently do nothing).
    """

    def __init__(
        self,
        loaded: LoadedPolicySet,
        session_store: SessionStore | None = None,
        audit_logger: AuditLogger | None = None,
        enable_anomaly_detection: bool = False,
    ) -> None:
        if enable_anomaly_detection and session_store is None:
            raise ValueError(
                "enable_anomaly_detection=True requires a session_store — "
                "most detectors need real session history/declared-tools "
                "state and would silently never fire without one"
            )
        self.loaded = loaded
        self.session_store = session_store
        self.audit_logger = audit_logger
        self._anomaly_detection_enabled = enable_anomaly_detection

    def evaluate(self, call: CallRecord) -> Decision:
        start_ns = time.perf_counter_ns()
        history = (
            self.session_store.get_history(call.session_id)
            if self.session_store is not None
            else ()
        )
        decision = evaluate_call(call, self.loaded, session_history=history)

        if self._anomaly_detection_enabled and self.session_store is not None:
            declared_tools = self.session_store.get_declared_tools(call.session_id)
            findings = detect_anomalies(
                call, session_history=history, declared_tools=declared_tools
            )
            decision = apply_anomaly_findings(decision, findings)

        latency_ns = time.perf_counter_ns() - start_ns

        if self.session_store is not None and decision.outcome == Outcome.ALLOW:
            self.session_store.record_call(
                call.session_id, call.tool_name, call.timestamp_utc
            )

        if self.audit_logger is not None:
            self.audit_logger.log_call(
                call=call, decision=decision, latency_ns=latency_ns
            )

        return decision
