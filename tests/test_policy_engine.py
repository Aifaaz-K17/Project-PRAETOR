"""Tests for firewall/policy_engine.py + firewall/policy_schema.py — Phase 3."""

from __future__ import annotations

import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import regex
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError
from sqlalchemy import select

from firewall.canonicalize import canonical_path
from firewall.interceptor import CallRecord, Outcome
from firewall.logger import AuditLogger, AuditLogRow
from firewall.policy_engine import (
    MAX_ARG_COUNT,
    MAX_NESTING_DEPTH,
    MAX_STRING_LENGTH,
    LoadedPolicySet,
    PolicyEngine,
    PolicyLoadError,
    _matches_parameter_bounds,
    evaluate_call,
    load_policy_set,
)
from firewall.policy_schema import (
    DomainAllowlistRule,
    ParameterBoundsRule,
    ParameterSchemaRule,
    PathScopeRule,
    PolicySet,
    RbacRule,
    RuleAction,
)
from firewall.session import SessionStore

REAL_POLICY_DIR = Path(__file__).parent.parent / "policies"
BENIGN_CALLS_PATH = Path(__file__).parent / "fixtures" / "benign_calls.yaml"


def make_call(
    *,
    call_id: str = "test-call",
    tool_name: str = "read_file",
    role: str = "analyst",
    args: dict | None = None,
    session_id: str = "s1",
    identity: str = "u1",
    timestamp_utc: datetime | None = None,
    sequence_index: int = 0,
) -> CallRecord:
    args = args if args is not None else {}
    return CallRecord(
        call_id=call_id,
        tool_name=tool_name,
        raw_args=args,
        canonical_args=dict(args),
        session_id=session_id,
        identity=identity,
        role=role,
        timestamp_utc=timestamp_utc or datetime.now(timezone.utc),
        timestamp_monotonic_ns=0,
        sequence_index=sequence_index,
    )


# ---------------------------------------------------------------------------
# Schema validation — a malformed policy file is a precise startup failure
# ---------------------------------------------------------------------------


def test_malformed_policy_missing_required_field_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicySet.model_validate(
            {"rules": [{"type": "rbac", "id": "r1", "tool": "x", "action": "allow"}]}
        )  # missing `roles`


def test_malformed_policy_unknown_rule_type_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicySet.model_validate(
            {
                "rules": [
                    {
                        "type": "not_a_real_type",
                        "id": "r1",
                        "tool": "x",
                        "action": "allow",
                    }
                ]
            }
        )


def test_malformed_policy_unknown_field_rejected() -> None:
    """extra="forbid" — a typo'd field name must fail loudly, not be
    silently ignored."""
    with pytest.raises(ValidationError):
        PolicySet.model_validate(
            {
                "rules": [
                    {
                        "type": "rbac",
                        "id": "r1",
                        "tool": "x",
                        "action": "allow",
                        "roles": ["admin"],
                        "role": ["typo-of-roles"],
                    }
                ]
            }
        )


def test_parameter_bounds_requires_at_least_one_bound() -> None:
    with pytest.raises(ValidationError):
        ParameterBoundsRule.model_validate(
            {
                "type": "parameter_bounds",
                "id": "r1",
                "tool": "x",
                "action": "deny",
                "parameter": "amount",
            }
        )


def test_requires_approval_only_valid_on_allow_rules() -> None:
    with pytest.raises(ValidationError):
        RbacRule.model_validate(
            {
                "type": "rbac",
                "id": "r1",
                "tool": "x",
                "action": "deny",
                "roles": ["admin"],
                "requires_approval": True,
            }
        )


def test_duplicate_rule_ids_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicySet.model_validate(
            {
                "rules": [
                    {
                        "type": "rbac",
                        "id": "dup",
                        "tool": "x",
                        "action": "allow",
                        "roles": ["a"],
                    },
                    {
                        "type": "rbac",
                        "id": "dup",
                        "tool": "y",
                        "action": "allow",
                        "roles": ["b"],
                    },
                ]
            }
        )


def test_policy_set_and_rules_are_frozen() -> None:
    ps = PolicySet.model_validate(
        {
            "rules": [
                {
                    "type": "rbac",
                    "id": "r1",
                    "tool": "x",
                    "action": "allow",
                    "roles": ["a"],
                }
            ]
        }
    )
    with pytest.raises(ValidationError):
        ps.default_action = RuleAction.ALLOW
    with pytest.raises(ValidationError):
        ps.rules[0].tool = "y"


# ---------------------------------------------------------------------------
# Loading — INV-03 (integrity hash), yaml.safe_load only, startup failures
# ---------------------------------------------------------------------------


def test_load_policy_set_no_files_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyLoadError, match="no policy files found"):
        load_policy_set(tmp_path)


def test_load_policy_set_invalid_yaml_rejected(tmp_path: Path) -> None:
    (tmp_path / "broken.yaml").write_text("rules: [this is not: valid: yaml:")
    with pytest.raises(PolicyLoadError, match="invalid YAML"):
        load_policy_set(tmp_path)


def test_load_policy_set_schema_violation_rejected(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text(textwrap.dedent("""
            rules:
              - type: rbac
                id: r1
                tool: x
                action: allow
            """))  # missing `roles`
    with pytest.raises(PolicyLoadError, match="schema validation failed"):
        load_policy_set(tmp_path)


def test_load_policy_set_conflicting_default_action_rejected(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text("default_action: deny\nrules: []\n")
    (tmp_path / "b.yaml").write_text("default_action: allow\nrules: []\n")
    with pytest.raises(PolicyLoadError, match="conflicts with"):
        load_policy_set(tmp_path)


def test_load_policy_set_hash_is_deterministic_and_order_independent(
    tmp_path: Path,
) -> None:
    """Loading the same file *contents* under different filenames/order
    must produce the same rule set (though not necessarily the same raw
    hash bytes) — what actually matters is that re-loading the SAME
    directory twice gives the SAME hash (INV-03: decisions reproducible
    against an exact rule set)."""
    (tmp_path / "a.yaml").write_text(
        "rules: [{type: rbac, id: r1, tool: x, action: allow, roles: [a]}]\n"
    )
    (tmp_path / "b.yaml").write_text(
        "rules: [{type: rbac, id: r2, tool: y, action: allow, roles: [b]}]\n"
    )

    first = load_policy_set(tmp_path)
    second = load_policy_set(tmp_path)
    assert first.policy_set_hash == second.policy_set_hash
    assert len(first.policy_set_hash) == 64  # SHA-256 hex digest


def test_load_policy_set_hash_changes_when_content_changes(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text(
        "rules: [{type: rbac, id: r1, tool: x, action: allow, roles: [a]}]\n"
    )
    before = load_policy_set(tmp_path)
    (tmp_path / "a.yaml").write_text(
        "rules: [{type: rbac, id: r1, tool: x, action: allow, roles: [b]}]\n"
    )
    after = load_policy_set(tmp_path)
    assert before.policy_set_hash != after.policy_set_hash


def test_yaml_load_never_uses_unsafe_loader() -> None:
    """Structural guard against regressing to yaml.load / FullLoader —
    CLAUDE.md §3 forbids it outright."""
    source = (
        Path(__file__).parent.parent / "firewall" / "policy_engine.py"
    ).read_text()
    assert "yaml.load(" not in source
    assert "yaml.safe_load(" in source


# ---------------------------------------------------------------------------
# The real shipped policies/ directory
# ---------------------------------------------------------------------------


def test_real_policies_directory_loads_cleanly() -> None:
    loaded = load_policy_set(REAL_POLICY_DIR)
    # 20-25 was Phase 3's original scope; the upper bound was deliberately
    # raised to fit the 5 parameter_schema rules (INV-08 unknown-parameter
    # enforcement) added afterward — a documented, reviewed expansion, not
    # unbounded policy sprawl.
    assert 20 <= len(loaded.policy_set.rules) <= 35
    assert loaded.policy_set.default_action == RuleAction.DENY


@pytest.fixture(scope="module")
def real_loaded() -> LoadedPolicySet:
    return load_policy_set(REAL_POLICY_DIR)


def test_INV_03_policies_dir_is_outside_every_tools_allowed_root(
    real_loaded: LoadedPolicySet,
) -> None:
    """No path_scope rule's allowed_roots can ever resolve to (or contain)
    the actual policies/ directory — if one did, a tool the agent can call
    could read or write policy files, breaking INV-03 ("no agent-
    accessible tool can read or write policies/"). Also proves a realistic
    traversal attempt from inside an allowed root cannot reach policies/.
    """
    resolved_policies_dir = REAL_POLICY_DIR.resolve()

    for rule in real_loaded.policy_set.rules:
        if isinstance(rule, PathScopeRule):
            for root in rule.allowed_roots:
                resolved_root = Path(root).resolve()
                assert resolved_root != resolved_policies_dir
                assert not resolved_root.is_relative_to(resolved_policies_dir)
                assert not resolved_policies_dir.is_relative_to(resolved_root)

    # And concretely: try to traverse from the sandbox root into policies/.
    relative_depth = len(resolved_policies_dir.parent.parts)
    traversal_attempt = "../" * (relative_depth + 2) + "policies/rbac.yaml"
    result = canonical_path(
        traversal_attempt, allowed_roots=["sandbox"], base_dir="sandbox"
    )
    assert not result.ok


# ---------------------------------------------------------------------------
# Conflict resolution (ADR 0009): DENY > NEEDS_APPROVAL > ALLOW > default
# ---------------------------------------------------------------------------


def _single_rule_loaded(rule) -> LoadedPolicySet:  # type: ignore[no-untyped-def]
    return LoadedPolicySet(
        policy_set=PolicySet(default_action=RuleAction.DENY, rules=(rule,)),
        policy_set_hash="test",
        compiled_patterns={},
    )


def _rules_loaded(rules: tuple, default_action: RuleAction = RuleAction.DENY) -> LoadedPolicySet:  # type: ignore[type-arg]
    return LoadedPolicySet(
        policy_set=PolicySet(default_action=default_action, rules=rules),
        policy_set_hash="test",
        compiled_patterns={},
    )


def test_no_matching_rule_falls_through_to_default_deny() -> None:
    loaded = _rules_loaded(())
    decision = evaluate_call(make_call(tool_name="anything"), loaded)
    assert decision.outcome == Outcome.DENY
    assert "default_action" in decision.reason


def test_no_matching_rule_falls_through_to_default_allow_when_configured() -> None:
    loaded = _rules_loaded((), default_action=RuleAction.ALLOW)
    decision = evaluate_call(make_call(tool_name="anything"), loaded)
    assert decision.outcome == Outcome.ALLOW


def test_deny_wins_over_allow() -> None:
    allow_rule = RbacRule.model_validate(
        {
            "type": "rbac",
            "id": "allow-r",
            "tool": "transfer_funds",
            "action": "allow",
            "roles": ["finance"],
        }
    )
    deny_rule = ParameterBoundsRule.model_validate(
        {
            "type": "parameter_bounds",
            "id": "deny-r",
            "tool": "transfer_funds",
            "action": "deny",
            "parameter": "amount",
            "max": 100,
        }
    )
    loaded = _rules_loaded((allow_rule, deny_rule))
    decision = evaluate_call(
        make_call(tool_name="transfer_funds", role="finance", args={"amount": 500}),
        loaded,
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "deny-r"


def test_needs_approval_wins_over_allow() -> None:
    plain_allow = RbacRule.model_validate(
        {
            "type": "rbac",
            "id": "plain-allow",
            "tool": "x",
            "action": "allow",
            "roles": ["a", "b"],
        }
    )
    approval_allow = RbacRule.model_validate(
        {
            "type": "rbac",
            "id": "approval-allow",
            "tool": "x",
            "action": "allow",
            "roles": ["a"],
            "requires_approval": True,
        }
    )
    loaded = _rules_loaded((plain_allow, approval_allow))
    decision = evaluate_call(make_call(tool_name="x", role="a"), loaded)
    assert decision.outcome == Outcome.NEEDS_APPROVAL
    assert decision.rule_id == "approval-allow"


def test_deny_wins_over_needs_approval() -> None:
    approval_allow = RbacRule.model_validate(
        {
            "type": "rbac",
            "id": "approval-allow",
            "tool": "x",
            "action": "allow",
            "roles": ["a"],
            "requires_approval": True,
        }
    )
    deny_rule = ParameterBoundsRule.model_validate(
        {
            "type": "parameter_bounds",
            "id": "deny-r",
            "tool": "x",
            "action": "deny",
            "parameter": "n",
            "max": 10,
        }
    )
    loaded = _rules_loaded((approval_allow, deny_rule))
    decision = evaluate_call(make_call(tool_name="x", role="a", args={"n": 50}), loaded)
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "deny-r"


def test_plain_allow_wins_when_nothing_else_matches() -> None:
    allow_rule = RbacRule.model_validate(
        {
            "type": "rbac",
            "id": "allow-r",
            "tool": "x",
            "action": "allow",
            "roles": ["a"],
        }
    )
    loaded = _rules_loaded((allow_rule,))
    decision = evaluate_call(make_call(tool_name="x", role="a"), loaded)
    assert decision.outcome == Outcome.ALLOW
    assert decision.rule_id == "allow-r"


def test_rule_for_a_different_tool_never_matches() -> None:
    rule = RbacRule.model_validate(
        {
            "type": "rbac",
            "id": "r1",
            "tool": "other_tool",
            "action": "allow",
            "roles": ["a"],
        }
    )
    loaded = _rules_loaded((rule,))
    decision = evaluate_call(make_call(tool_name="this_tool", role="a"), loaded)
    assert decision.outcome == Outcome.DENY  # default, since the rule didn't apply


def test_wildcard_tool_rule_matches_any_tool() -> None:
    rule = RbacRule.model_validate(
        {"type": "rbac", "id": "r1", "tool": "*", "action": "allow", "roles": ["admin"]}
    )
    loaded = _rules_loaded((rule,))
    for tool_name in ("read_file", "send_email", "anything_else"):
        decision = evaluate_call(make_call(tool_name=tool_name, role="admin"), loaded)
        assert decision.outcome == Outcome.ALLOW


# ---------------------------------------------------------------------------
# INV-09: bounded evaluation — argument caps
# ---------------------------------------------------------------------------


def test_INV_09_oversized_string_argument_denied() -> None:
    loaded = _rules_loaded(())
    call = make_call(args={"x": "a" * (MAX_STRING_LENGTH + 1)})
    decision = evaluate_call(call, loaded)
    assert decision.outcome == Outcome.DENY
    assert "POLICY_ERROR" in decision.reason


def test_INV_09_too_many_arguments_denied() -> None:
    loaded = _rules_loaded(())
    call = make_call(args={f"k{i}": i for i in range(MAX_ARG_COUNT + 1)})
    decision = evaluate_call(call, loaded)
    assert decision.outcome == Outcome.DENY
    assert "POLICY_ERROR" in decision.reason


def test_INV_09_excessive_nesting_denied() -> None:
    loaded = _rules_loaded(())
    nested: dict = {"x": 0}
    current = nested
    for _ in range(MAX_NESTING_DEPTH + 5):
        current["child"] = {"x": 0}
        current = current["child"]
    call = make_call(args=nested)
    decision = evaluate_call(call, loaded)
    assert decision.outcome == Outcome.DENY
    assert "POLICY_ERROR" in decision.reason


def test_within_bounds_arguments_not_rejected_by_caps() -> None:
    allow_rule = RbacRule.model_validate(
        {"type": "rbac", "id": "r1", "tool": "x", "action": "allow", "roles": ["a"]}
    )
    loaded = _rules_loaded((allow_rule,))
    call = make_call(tool_name="x", role="a", args={"note": "a short, ordinary value"})
    decision = evaluate_call(call, loaded)
    assert decision.outcome == Outcome.ALLOW


# ---------------------------------------------------------------------------
# INV-09: ReDoS protection — static linting AND the runtime timeout
# ---------------------------------------------------------------------------


def test_INV_09_redos_pattern_rejected_at_load_time(tmp_path: Path) -> None:
    (tmp_path / "evil.yaml").write_text(textwrap.dedent("""
            rules:
              - type: parameter_bounds
                id: evil
                tool: x
                action: deny
                parameter: p
                pattern: "(a|aa)+$"
            """))
    with pytest.raises(PolicyLoadError, match="ReDoS"):
        load_policy_set(tmp_path)


def test_INV_09_nested_quantifier_pattern_rejected_at_load_time(tmp_path: Path) -> None:
    (tmp_path / "evil.yaml").write_text(textwrap.dedent("""
            rules:
              - type: parameter_bounds
                id: evil
                tool: x
                action: deny
                parameter: p
                pattern: "(a+)+$"
            """))
    with pytest.raises(PolicyLoadError, match="ReDoS"):
        load_policy_set(tmp_path)


def test_INV_09_ordinary_patterns_are_not_flagged_by_the_linter(tmp_path: Path) -> None:
    (tmp_path / "fine.yaml").write_text(textwrap.dedent("""
            rules:
              - type: parameter_bounds
                id: fine
                tool: x
                action: deny
                parameter: p
                pattern: "(?i)password reset|urgent wire transfer"
            """))
    loaded = load_policy_set(tmp_path)  # must not raise
    assert len(loaded.policy_set.rules) == 1


def test_INV_09_runtime_regex_timeout_denies_rather_than_hangs() -> None:
    """The hard guarantee, tested independently of the static linter: even
    a pattern that somehow reached evaluation without being caught by
    `_lint_pattern_for_redos` must time out into a DENY, not hang. Compiles
    a genuinely catastrophic pattern directly with the `regex` package
    (bypassing `_compile_pattern`'s linting on purpose) and confirms
    `_matches_parameter_bounds` — the function with the actual timeout
    call — denies rather than hanging."""
    evil_pattern = regex.compile(r"(a|aa)+$")
    rule = ParameterBoundsRule.model_validate(
        {
            "type": "parameter_bounds",
            "id": "evil",
            "tool": "x",
            "action": "deny",
            "parameter": "p",
            "pattern": "(a|aa)+$",  # never actually compiled from this string in this test
        }
    )
    call = make_call(tool_name="x", args={"p": "a" * 40 + "!"})

    with pytest.raises(Exception) as exc_info:
        _matches_parameter_bounds(rule, call, compiled_patterns={"evil": evil_pattern})
    assert "regex evaluation exceeded" in str(exc_info.value)


def test_INV_09_runtime_timeout_surfaces_as_deny_through_evaluate_call() -> None:
    """End-to-end version of the above: evaluate_call itself must turn the
    timeout into a DENY Decision, never propagate the exception or hang."""
    evil_pattern = regex.compile(r"(a|aa)+$")
    rule = ParameterBoundsRule.model_validate(
        {
            "type": "parameter_bounds",
            "id": "evil",
            "tool": "x",
            "action": "deny",
            "parameter": "p",
            "pattern": "(a|aa)+$",
        }
    )
    loaded = LoadedPolicySet(
        policy_set=PolicySet(default_action=RuleAction.DENY, rules=(rule,)),
        policy_set_hash="test",
        compiled_patterns={"evil": evil_pattern},
    )
    call = make_call(tool_name="x", args={"p": "a" * 40 + "!"})
    decision = evaluate_call(call, loaded)
    assert decision.outcome == Outcome.DENY
    assert "POLICY_ERROR" in decision.reason


# ---------------------------------------------------------------------------
# Per-rule-type matching — one isolated test per shipped policy
# ---------------------------------------------------------------------------


def _load_single_real_rule(rule_id: str) -> LoadedPolicySet:
    """Isolates one real shipped rule for testing — plus, since
    firewall/policy_engine.py's unknown-parameter check (INV-08) is
    enforced per tool once any parameter_schema rule for that tool is
    present, also pulls in the real schema rule(s) for the same tool.
    Without this, every isolated test here would deny on "unknown
    parameter" before the rule under test ever got a chance to run.
    """
    real = load_policy_set(REAL_POLICY_DIR)
    rule = next(r for r in real.policy_set.rules if r.id == rule_id)
    schema_rules = tuple(
        r
        for r in real.policy_set.rules
        if isinstance(r, ParameterSchemaRule)
        and r.id != rule.id
        and (r.tool == rule.tool or r.tool == "*" or rule.tool == "*")
    )
    compiled = {k: v for k, v in real.compiled_patterns.items() if k == rule_id}
    return LoadedPolicySet(
        policy_set=PolicySet(
            default_action=RuleAction.DENY, rules=(rule, *schema_rules)
        ),
        policy_set_hash="test",
        compiled_patterns=compiled,
    )


# path_scope
def test_policy_path_read_file_sandbox_triggers_in_scope() -> None:
    loaded = _load_single_real_rule("path-read-file-sandbox")
    decision = evaluate_call(
        make_call(tool_name="read_file", args={"path": "notes.txt"}), loaded
    )
    assert decision.outcome == Outcome.ALLOW


def test_policy_path_read_file_sandbox_does_not_trigger_out_of_scope() -> None:
    loaded = _load_single_real_rule("path-read-file-sandbox")
    decision = evaluate_call(
        make_call(tool_name="read_file", args={"path": "../outside/secret.txt"}), loaded
    )
    assert decision.outcome == Outcome.DENY  # falls through to default


def test_policy_path_compose_draft_attachment_sandbox() -> None:
    loaded = _load_single_real_rule("path-compose-draft-attachment-sandbox")
    ok = evaluate_call(
        make_call(
            tool_name="compose_draft", args={"attachment_path": "sandbox/notes.txt"}
        ),
        loaded,
    )
    assert ok.outcome == Outcome.ALLOW
    bad = evaluate_call(
        make_call(
            tool_name="compose_draft", args={"attachment_path": "../outside/x.txt"}
        ),
        loaded,
    )
    assert bad.outcome == Outcome.DENY


def test_INV_05_policy_path_scope_roles_compose_with_rbac_not_bypass_it() -> None:
    """Real bug found via testing (Phase 4): path_scope rules used to be
    unconditional ALLOW grants regardless of role, so an intern with no
    RBAC grant for read_file could still read any in-scope file — the
    path_scope rule's own ALLOW vote was independently sufficient under
    conflict resolution's "any matching ALLOW wins" rule, silently
    bypassing rbac-read-file-analysts rather than composing with it. Fixed
    by adding an optional `roles` field to PathScopeRule, populated on the
    shipped path-read-file-sandbox rule (see ADR 0012)."""
    loaded = _load_single_real_rule("path-read-file-sandbox")
    intern_call = make_call(
        tool_name="read_file", role="intern", args={"path": "notes.txt"}
    )
    assert evaluate_call(intern_call, loaded).outcome == Outcome.DENY

    analyst_call = make_call(
        tool_name="read_file", role="analyst", args={"path": "notes.txt"}
    )
    assert evaluate_call(analyst_call, loaded).outcome == Outcome.ALLOW


def test_INV_05_policy_path_scope_compose_draft_roles_compose_with_rbac() -> None:
    """A second, real instance of the same bug class ADR 0012 fixed for
    path-read-file-sandbox and domain-send-email-corp — found and fixed
    2026-09-01 (ADR 0014). path-compose-draft-attachment-sandbox was left
    as an unconditional ALLOW grant at the time of ADR 0012's fix, so a
    role with NO compose_draft RBAC grant at all (e.g. a bare "guest")
    could still compose a draft with an in-scope attachment — this rule's
    own ALLOW vote was independently sufficient regardless of role.
    Isolated-rule check (mirrors the existing path_scope/domain_allowlist
    regression tests): a role outside `roles` gets no ALLOW vote from
    this rule alone."""
    loaded = _load_single_real_rule("path-compose-draft-attachment-sandbox")
    guest_call = make_call(
        tool_name="compose_draft",
        role="guest",
        args={"subject": "s", "body": "b", "attachment_path": "sandbox/notes.txt"},
    )
    assert evaluate_call(guest_call, loaded).outcome == Outcome.DENY

    analyst_call = make_call(
        tool_name="compose_draft",
        role="analyst",
        args={"subject": "s", "body": "b", "attachment_path": "sandbox/notes.txt"},
    )
    assert evaluate_call(analyst_call, loaded).outcome == Outcome.ALLOW


def test_INV_05_real_policy_set_compose_draft_guest_role_no_longer_bypasses_rbac() -> (
    None
):
    """End-to-end proof against the real, full policy set: before this
    fix, a role with zero compose_draft RBAC grant (e.g. "guest") was
    ALLOWED to compose a draft purely because path-compose-draft-
    attachment-sandbox's unconditional ALLOW vote outvoted the absence of
    any RBAC grant. Also confirms the fix doesn't disturb the two roles
    that must still work: analyst gets a plain ALLOW, and intern still
    gets escalated to NEEDS_APPROVAL rather than losing its approval path
    entirely."""
    loaded = load_policy_set(REAL_POLICY_DIR)
    args = {"subject": "s", "body": "b", "attachment_path": "sandbox/notes.txt"}

    guest_decision = evaluate_call(
        make_call(tool_name="compose_draft", role="guest", args=args), loaded
    )
    assert guest_decision.outcome == Outcome.DENY

    intern_decision = evaluate_call(
        make_call(tool_name="compose_draft", role="intern", args=args), loaded
    )
    assert intern_decision.outcome == Outcome.NEEDS_APPROVAL
    assert intern_decision.rule_id == "rbac-compose-draft-intern-needs-approval"

    analyst_decision = evaluate_call(
        make_call(tool_name="compose_draft", role="analyst", args=args), loaded
    )
    assert analyst_decision.outcome == Outcome.ALLOW


def test_INV_06_policy_path_scope_allowed_root_independent_of_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real bug found by code review: path_scope.yaml's "sandbox" allowed
    root used to resolve relative to the process's current working
    directory, not the repo root — so a legitimate call would be silently
    (and confusingly) denied if the process happened to be launched from
    anywhere else. Changing directory to an unrelated tmp_path here and
    confirming the real rule still resolves "sandbox" to the actual repo
    sandbox/ directory proves the anchor-to-repo-root fix works."""
    monkeypatch.chdir(tmp_path)
    loaded = _load_single_real_rule("path-read-file-sandbox")
    decision = evaluate_call(
        make_call(tool_name="read_file", args={"path": "notes.txt"}), loaded
    )
    assert decision.outcome == Outcome.ALLOW


# domain_allowlist
def test_policy_domain_send_email_corp_triggers() -> None:
    loaded = _load_single_real_rule("domain-send-email-corp")
    decision = evaluate_call(
        make_call(tool_name="send_email", args={"to": "alice@corp.example.com"}), loaded
    )
    assert decision.outcome == Outcome.ALLOW


def test_policy_domain_send_email_corp_does_not_match_other_domain() -> None:
    loaded = _load_single_real_rule("domain-send-email-corp")
    decision = evaluate_call(
        make_call(tool_name="send_email", args={"to": "alice@evil.com"}), loaded
    )
    assert decision.outcome == Outcome.DENY


def test_INV_05_policy_domain_allowlist_roles_compose_with_rbac_not_bypass_it() -> None:
    """Same real bug as path_scope's (see the path_scope regression test
    above and ADR 0012), for domain_allowlist: an intern with no RBAC
    grant for send_email could still send to the corp domain once the
    sequence gate was satisfied, because domain-send-email-corp's ALLOW
    vote was independently sufficient regardless of role. Fixed by adding
    an optional `roles` field, populated on the shipped rule."""
    loaded = _load_single_real_rule("domain-send-email-corp")
    intern_call = make_call(
        tool_name="send_email", role="intern", args={"to": "alice@corp.example.com"}
    )
    assert evaluate_call(intern_call, loaded).outcome == Outcome.DENY

    analyst_call = make_call(
        tool_name="send_email", role="analyst", args={"to": "alice@corp.example.com"}
    )
    assert evaluate_call(analyst_call, loaded).outcome == Outcome.ALLOW


def test_INV_05_real_policy_set_search_web_unrecognized_role_no_longer_bypasses_rbac() -> (
    None
):
    """A third real instance of the same bug class (ADR 0012, ADR 0014):
    rbac-search-web-everyone's "everyone" is still a specific, enumerated
    role list (["intern", "analyst", "finance", "admin"]) — INV-08 is a
    closed-world allowlist. domain-search-web-reference-sites used to be
    unrestricted, so a role string outside that list entirely (a typo, an
    unexpected value from a misconfigured session — RBAC is meant to be
    the single source of truth for "which roles may use this tool at
    all") still got a plain ALLOW as long as target_host was in-scope.
    End-to-end proof against the real, full policy set."""
    loaded = load_policy_set(REAL_POLICY_DIR)
    args = {"query": "x", "target_host": "docs.python.org"}

    unrecognized_decision = evaluate_call(
        make_call(tool_name="search_web", role="not-a-real-role", args=args), loaded
    )
    assert unrecognized_decision.outcome == Outcome.DENY

    intern_decision = evaluate_call(
        make_call(tool_name="search_web", role="intern", args=args), loaded
    )
    assert intern_decision.outcome == Outcome.ALLOW


def test_policy_domain_send_email_partner_needs_approval() -> None:
    loaded = _load_single_real_rule("domain-send-email-partner-needs-approval")
    decision = evaluate_call(
        make_call(tool_name="send_email", args={"to": "x@partner.example.org"}), loaded
    )
    assert decision.outcome == Outcome.NEEDS_APPROVAL


def test_policy_domain_search_web_reference_sites() -> None:
    loaded = _load_single_real_rule("domain-search-web-reference-sites")
    ok = evaluate_call(
        make_call(tool_name="search_web", args={"target_host": "docs.python.org"}),
        loaded,
    )
    assert ok.outcome == Outcome.ALLOW
    bad = evaluate_call(
        make_call(tool_name="search_web", args={"target_host": "evil.com"}), loaded
    )
    assert bad.outcome == Outcome.DENY


# parameter_bounds
def test_policy_bounds_transfer_max_amount() -> None:
    loaded = _load_single_real_rule("bounds-transfer-max-amount")
    ok = evaluate_call(
        make_call(tool_name="transfer_funds", args={"amount": 500}), loaded
    )
    assert (
        ok.outcome == Outcome.DENY
    )  # only rule is a deny-shaped bound; no allow rule present
    over = evaluate_call(
        make_call(tool_name="transfer_funds", args={"amount": 5000}), loaded
    )
    assert over.outcome == Outcome.DENY
    assert over.rule_id == "bounds-transfer-max-amount"


def test_INV_01_policy_bounds_string_typed_amount_still_enforced() -> None:
    """Real bug, found and fixed 2026-09-01 (ADR 0014): a numeric-string
    amount (the shape a real LLM tool-call can emit — JSON args parsed
    from text, where a model wrote `"amount": "999999"` instead of a
    bare JSON number) used to sail straight past this bound, because the
    old check only ever compared a native `int`/`float`. The fix
    coerces a numeric-looking string before comparing, and fails closed
    (denies) on anything that can't be coerced at all — never silently
    treats "wrong type" as "no bound applies"."""
    loaded = _load_single_real_rule("bounds-transfer-max-amount")

    over_cap_as_string = evaluate_call(
        make_call(tool_name="transfer_funds", args={"amount": "5000"}), loaded
    )
    assert over_cap_as_string.outcome == Outcome.DENY
    assert over_cap_as_string.rule_id == "bounds-transfer-max-amount"

    within_cap_as_string = evaluate_call(
        make_call(tool_name="transfer_funds", args={"amount": "500"}), loaded
    )
    assert within_cap_as_string.outcome == Outcome.DENY  # only rule is deny-shaped


def test_INV_01_policy_bounds_uncoercible_amount_fails_closed() -> None:
    """A value that isn't a number and can't be parsed as one (a bool, a
    non-numeric string, a list) must be treated as a bounds violation,
    not silently allowed to skip the check entirely."""
    loaded = _load_single_real_rule("bounds-transfer-max-amount")

    for bad_amount in (True, "not-a-number", [1, 2, 3]):
        decision = evaluate_call(
            make_call(tool_name="transfer_funds", args={"amount": bad_amount}), loaded
        )
        assert (
            decision.outcome == Outcome.DENY
        ), f"amount={bad_amount!r} should fail closed, got {decision.outcome}"
        assert decision.rule_id == "bounds-transfer-max-amount"


def test_INV_01_real_policy_set_denies_string_typed_over_cap_transfer() -> None:
    """End-to-end proof against the real, full policy set (not an isolated
    rule): before this fix, a `finance`-role call with `amount` as a
    numeric string over the 1000 cap was ALLOWED — the RBAC grant voted
    ALLOW and the two amount-bound DENY rules silently never matched a
    string-typed value. Independently reproduced against the real
    `policies/` directory before writing the fix (see ADR 0014)."""
    loaded = load_policy_set(REAL_POLICY_DIR)
    decision = evaluate_call(
        make_call(
            tool_name="transfer_funds",
            role="finance",
            args={"amount": "999999", "note": "legitimate-looking memo"},
        ),
        loaded,
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "bounds-transfer-max-amount"


def test_policy_bounds_transfer_non_negative_triggers_on_negative() -> None:
    loaded = _load_single_real_rule("bounds-transfer-non-negative")
    decision = evaluate_call(
        make_call(tool_name="transfer_funds", args={"amount": -50}), loaded
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "bounds-transfer-non-negative"


def test_policy_bounds_transfer_note_length() -> None:
    loaded = _load_single_real_rule("bounds-transfer-note-length")
    decision = evaluate_call(
        make_call(tool_name="transfer_funds", args={"note": "x" * 300}), loaded
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "bounds-transfer-note-length"


def test_policy_bounds_search_query_length() -> None:
    loaded = _load_single_real_rule("bounds-search-query-length")
    decision = evaluate_call(
        make_call(tool_name="search_web", args={"query": "x" * 600}), loaded
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "bounds-search-query-length"


def test_policy_bounds_search_query_suspicious_pattern() -> None:
    loaded = _load_single_real_rule("bounds-search-query-suspicious-pattern")
    decision = evaluate_call(
        make_call(
            tool_name="search_web", args={"query": "how to bypass firewall rules"}
        ),
        loaded,
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "bounds-search-query-suspicious-pattern"

    clean = evaluate_call(
        make_call(tool_name="search_web", args={"query": "python tutorials"}), loaded
    )
    assert clean.outcome == Outcome.DENY  # default (no allow rule in this isolated set)
    assert clean.rule_id is None  # proves the pattern rule itself did NOT match


def test_policy_bounds_send_email_subject_suspicious_pattern() -> None:
    loaded = _load_single_real_rule("bounds-send-email-subject-suspicious-pattern")
    decision = evaluate_call(
        make_call(
            tool_name="send_email", args={"subject": "URGENT wire transfer needed"}
        ),
        loaded,
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "bounds-send-email-subject-suspicious-pattern"


def test_INV_06_policy_bounds_pattern_catches_percent_encoded_obfuscation() -> None:
    """Real bug found by code review: _matches_parameter_bounds used to
    run its denylist regex directly against the raw value, never through
    canonical_text — so a percent-encoded space let a query sail straight
    past this exact rule. Must be caught now."""
    loaded = _load_single_real_rule("bounds-search-query-suspicious-pattern")
    decision = evaluate_call(
        make_call(
            tool_name="search_web", args={"query": "please bypass%20firewall now"}
        ),
        loaded,
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "bounds-search-query-suspicious-pattern"


def test_INV_06_policy_bounds_pattern_catches_zero_width_obfuscation() -> None:
    """Same bug, different obfuscation technique: a zero-width space
    hidden *inside* one of the denylisted words (not replacing the real
    space between them — a zero-width character is invisible, not a
    space, so it splits a word's letters apart while the phrase still
    reads as one word to a human)."""
    zwsp = chr(0x200B)
    loaded = _load_single_real_rule("bounds-search-query-suspicious-pattern")
    decision = evaluate_call(
        make_call(tool_name="search_web", args={"query": f"byp{zwsp}ass firewall"}),
        loaded,
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "bounds-search-query-suspicious-pattern"


def test_INV_06_policy_bounds_max_length_measured_after_canonicalization() -> None:
    """max_length must be checked against the canonicalized (decoded)
    length, not the raw encoded length — otherwise a percent-encoded
    payload could hide extra real content under an apparently-short raw
    string."""
    loaded = _load_single_real_rule("bounds-search-query-length")
    long_query = "a" * 600  # over the 500 max_length, and plain ASCII so
    # canonicalization doesn't change its length — isolates the max_length
    # check itself rather than the decoding step.
    decision = evaluate_call(
        make_call(tool_name="search_web", args={"query": long_query}), loaded
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "bounds-search-query-length"


def test_INV_06_policy_bounds_uncanonicalizable_value_fails_closed() -> None:
    """A value canonical_text itself rejects (here: residual/double
    percent-encoding) must be treated as a bounds violation, not silently
    passed through unmatched (INV-01 fail-closed applied to this path)."""
    loaded = _load_single_real_rule("bounds-search-query-suspicious-pattern")
    decision = evaluate_call(
        make_call(tool_name="search_web", args={"query": "hello%2520world"}), loaded
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "bounds-search-query-suspicious-pattern"


def test_policy_bounds_transfer_note_suspicious_pattern() -> None:
    """New rule added alongside the canonicalization fix: `note` had a
    length cap but no content denylist, unlike its query/subject siblings
    (found by code review)."""
    loaded = _load_single_real_rule("bounds-transfer-note-suspicious-pattern")
    decision = evaluate_call(
        make_call(
            tool_name="transfer_funds", args={"note": "urgent wire transfer please"}
        ),
        loaded,
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "bounds-transfer-note-suspicious-pattern"

    clean = evaluate_call(
        make_call(tool_name="transfer_funds", args={"note": "October rent"}), loaded
    )
    assert clean.rule_id != "bounds-transfer-note-suspicious-pattern"


# rbac
@pytest.mark.parametrize(
    "rule_id,tool_name,allowed_role,forbidden_role",
    [
        ("rbac-transfer-finance-and-admin", "transfer_funds", "finance", "intern"),
        ("rbac-read-file-analysts", "read_file", "analyst", "intern"),
        ("rbac-send-email-analysts", "send_email", "analyst", "intern"),
        ("rbac-search-web-everyone", "search_web", "intern", None),
        ("rbac-compose-draft-analysts", "compose_draft", "analyst", "intern"),
    ],
)
def test_policy_rbac_rules(
    rule_id: str, tool_name: str, allowed_role: str, forbidden_role: str | None
) -> None:
    loaded = _load_single_real_rule(rule_id)
    allowed = evaluate_call(make_call(tool_name=tool_name, role=allowed_role), loaded)
    assert allowed.outcome == Outcome.ALLOW
    if forbidden_role is not None:
        denied = evaluate_call(
            make_call(tool_name=tool_name, role=forbidden_role), loaded
        )
        assert denied.outcome == Outcome.DENY


def test_policy_rbac_compose_draft_intern_needs_approval() -> None:
    loaded = _load_single_real_rule("rbac-compose-draft-intern-needs-approval")
    decision = evaluate_call(
        make_call(tool_name="compose_draft", role="intern"), loaded
    )
    assert decision.outcome == Outcome.NEEDS_APPROVAL


# sequence
def test_policy_sequence_send_email_requires_draft_denies_without_history() -> None:
    loaded = _load_single_real_rule("sequence-send-email-requires-draft")
    decision = evaluate_call(
        make_call(tool_name="send_email"), loaded, session_history=()
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "sequence-send-email-requires-draft"


def test_policy_sequence_send_email_requires_draft_allows_with_history() -> None:
    loaded = _load_single_real_rule("sequence-send-email-requires-draft")
    history = (("compose_draft", datetime.now(timezone.utc) - timedelta(seconds=5)),)
    decision = evaluate_call(
        make_call(tool_name="send_email"),
        loaded,
        session_history=history[0:1] if False else history,
    )
    # sequence rule only ever *denies* — with the requirement satisfied it
    # doesn't match, so this isolated single-rule set falls through to
    # the default (deny), proving the rule itself did NOT fire.
    assert decision.rule_id != "sequence-send-email-requires-draft"


# rate
@pytest.mark.parametrize(
    "rule_id,tool_name,max_calls",
    [
        ("rate-transfer-funds", "transfer_funds", 3),
        ("rate-send-email", "send_email", 10),
        ("rate-search-web", "search_web", 30),
        ("rate-compose-draft", "compose_draft", 20),
        ("rate-read-file", "read_file", 50),
    ],
)
def test_policy_rate_limits(rule_id: str, tool_name: str, max_calls: int) -> None:
    loaded = _load_single_real_rule(rule_id)
    now = datetime.now(timezone.utc)
    history = tuple((tool_name, now - timedelta(seconds=1)) for _ in range(max_calls))

    under_limit_call = make_call(tool_name=tool_name, timestamp_utc=now)
    under = evaluate_call(under_limit_call, loaded, session_history=history[:-1])
    assert (
        under.rule_id != rule_id
    )  # one below the cap: the rate rule itself doesn't fire

    at_limit = evaluate_call(under_limit_call, loaded, session_history=history)
    assert at_limit.outcome == Outcome.DENY
    assert at_limit.rule_id == rule_id


# ---------------------------------------------------------------------------
# parameter_schema — INV-08 "unknown parameter -> DENY"
# ---------------------------------------------------------------------------


def test_INV_08_unknown_parameter_denied_when_schema_declared() -> None:
    """The core new behavior: a call carrying a parameter no
    parameter_schema rule declares for that tool is denied outright, even
    though every parameter it also carries would otherwise be fine."""
    loaded = _load_single_real_rule("schema-transfer-funds")
    decision = evaluate_call(
        make_call(
            tool_name="transfer_funds",
            args={
                "amount": 100,
                "note": "rent",
                "destination_account": "attacker-acct",
            },
        ),
        loaded,
    )
    assert decision.outcome == Outcome.DENY
    assert "destination_account" in decision.reason
    assert "unknown parameter" in decision.reason


def test_INV_08_known_parameters_pass_the_schema_check() -> None:
    loaded = _load_single_real_rule("schema-transfer-funds")
    decision = evaluate_call(
        make_call(tool_name="transfer_funds", args={"amount": 100, "note": "rent"}),
        loaded,
    )
    # No other rule in this isolated set votes ALLOW, so it falls through
    # to default — the point here is only that it does NOT get denied for
    # "unknown parameter", proving the schema check itself passed.
    assert "unknown parameter" not in decision.reason


def test_INV_08_schema_check_runs_before_any_other_rule() -> None:
    """An unknown parameter must deny the call even when a broader ALLOW
    rule (e.g. RBAC) would otherwise have let it through — the schema
    check is consulted first, not as just another vote."""
    schema_rule = ParameterSchemaRule.model_validate(
        {
            "type": "parameter_schema",
            "id": "schema-x",
            "tool": "x",
            "action": "allow",
            "known_parameters": ["a"],
        }
    )
    allow_rule = RbacRule.model_validate(
        {
            "type": "rbac",
            "id": "allow-r",
            "tool": "x",
            "action": "allow",
            "roles": ["admin"],
        }
    )
    loaded = _rules_loaded((schema_rule, allow_rule))
    decision = evaluate_call(
        make_call(tool_name="x", role="admin", args={"a": 1, "b": 2}), loaded
    )
    assert decision.outcome == Outcome.DENY
    assert "unknown parameter" in decision.reason


def test_INV_08_tool_without_any_schema_rule_is_not_checked() -> None:
    """Enforcement is opt-in per tool (documented in
    _check_unknown_parameters' docstring and LIMITATIONS.md): a tool with
    no parameter_schema rule declared in the loaded set isn't subject to
    this check at all, so pre-existing synthetic test scenarios that never
    declare one keep working unmodified."""
    allow_rule = RbacRule.model_validate(
        {
            "type": "rbac",
            "id": "allow-r",
            "tool": "x",
            "action": "allow",
            "roles": ["admin"],
        }
    )
    loaded = _rules_loaded((allow_rule,))
    decision = evaluate_call(
        make_call(tool_name="x", role="admin", args={"anything": "goes", "here": 1}),
        loaded,
    )
    assert decision.outcome == Outcome.ALLOW


@pytest.mark.parametrize(
    "rule_id,tool_name,known_args",
    [
        ("schema-read-file", "read_file", {"path": "notes.txt"}),
        (
            "schema-send-email",
            "send_email",
            {"to": "a@corp.example.com", "subject": "s", "body": "b"},
        ),
        (
            "schema-search-web",
            "search_web",
            {"query": "q", "target_host": "wikipedia.org"},
        ),
        ("schema-transfer-funds", "transfer_funds", {"amount": 10, "note": "n"}),
        (
            "schema-compose-draft",
            "compose_draft",
            {"subject": "s", "body": "b", "attachment_path": "sandbox/notes.txt"},
        ),
    ],
)
def test_policy_parameter_schema_rules(
    rule_id: str, tool_name: str, known_args: dict
) -> None:
    loaded = _load_single_real_rule(rule_id)
    ok = evaluate_call(make_call(tool_name=tool_name, args=known_args), loaded)
    assert "unknown parameter" not in ok.reason

    bad_args = dict(known_args)
    bad_args["totally_unexpected_field"] = "x"
    denied = evaluate_call(make_call(tool_name=tool_name, args=bad_args), loaded)
    assert denied.outcome == Outcome.DENY
    assert "unknown parameter" in denied.reason


def test_all_shipped_rules_have_at_least_one_test() -> None:
    """A structural guard, not a functional test: every rule id currently
    shipped in policies/ must be named somewhere in this file, so a new
    rule added later without a matching test fails CI immediately."""
    real = load_policy_set(REAL_POLICY_DIR)
    source = Path(__file__).read_text()
    missing = [rule.id for rule in real.policy_set.rules if rule.id not in source]
    assert missing == [], f"rules with no test coverage: {missing}"


def test_INV_05_no_unrestricted_allowlist_rule_can_bypass_an_rbac_rule() -> None:
    """Structural guard for the bug class first found via testing in
    Phase 4 (ADR 0012), then found TWICE more by a deliberate review pass
    on 2026-09-01 (ADR 0014) on rules ADR 0012 itself did not touch
    (path-compose-draft-attachment-sandbox, domain-search-web-reference-
    sites). A `path_scope`/`domain_allowlist` rule with `action: allow`,
    no `requires_approval`, and an empty `roles` field casts a plain
    ALLOW vote for ANY role string at all — including one no `rbac` rule
    for that tool ever named. Conflict resolution treats every matching
    ALLOW vote as independently sufficient (ADR 0009), so that
    unrestricted vote silently outvotes whatever restriction the tool's
    `rbac` rule(s) meant to impose, rather than composing with it — even
    when the `rbac` rule's own role list looks "complete" (e.g.
    rbac-search-web-everyone), because RBAC is a closed, enumerated
    allowlist (INV-08), not an open one, and an unrestricted allowlist
    rule doesn't check role at all.

    This walks every rule actually shipped in `policies/` and fails if a
    new rule (or an edit to an existing one) reintroduces the pattern,
    instead of relying on a human noticing during review — the exact
    structural guard ADR 0012's "Consequences" section named as a
    reasonable follow-up rather than something built at the time."""
    loaded = load_policy_set(REAL_POLICY_DIR)

    tools_with_an_rbac_rule = {
        rule.tool for rule in loaded.policy_set.rules if isinstance(rule, RbacRule)
    }

    violations = [
        rule.id
        for rule in loaded.policy_set.rules
        if isinstance(rule, (PathScopeRule, DomainAllowlistRule))
        and rule.action == RuleAction.ALLOW
        and not rule.requires_approval
        and not rule.roles
        and rule.tool in tools_with_an_rbac_rule
    ]

    assert violations == [], (
        f"these path_scope/domain_allowlist rules are unrestricted "
        f"(action: allow, no requires_approval, empty roles) despite an "
        f"rbac rule existing for the same tool — they will silently "
        f"outvote that rbac rule's role restriction instead of composing "
        f"with it (ADR 0012/0014): {violations}"
    )


# ---------------------------------------------------------------------------
# The benign-calls corpus (false-positive check)
# ---------------------------------------------------------------------------


def _load_benign_corpus() -> list[dict]:
    with BENIGN_CALLS_PATH.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


BENIGN_ENTRIES = _load_benign_corpus()


def test_benign_corpus_has_at_least_60_entries() -> None:
    assert len(BENIGN_ENTRIES) >= 60


@pytest.mark.parametrize("entry", BENIGN_ENTRIES, ids=[e["id"] for e in BENIGN_ENTRIES])
def test_benign_call_is_allowed(entry: dict, real_loaded: LoadedPolicySet) -> None:
    now = datetime.now(timezone.utc)
    history = tuple(
        (tool_name, now - timedelta(seconds=5))
        for tool_name in entry.get("session_history", [])
    )
    call = make_call(
        tool_name=entry["tool"],
        role=entry["role"],
        args=entry["args"],
        session_id=entry["id"],
        identity=entry["id"],
        timestamp_utc=now,
    )
    decision = evaluate_call(call, real_loaded, session_history=history)
    assert (
        decision.outcome == Outcome.ALLOW
    ), f"{entry['id']} expected ALLOW, got {decision.outcome} ({decision.reason})"


# ---------------------------------------------------------------------------
# INV-13 — determinism (Hypothesis property-based test)
# ---------------------------------------------------------------------------

_tool_names = st.sampled_from(
    [
        "read_file",
        "send_email",
        "search_web",
        "transfer_funds",
        "compose_draft",
        "unknown_tool",
    ]
)
_roles = st.sampled_from(["intern", "analyst", "finance", "admin", "nobody"])
_arg_values = st.one_of(
    st.text(max_size=20),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.integers(),
)
_args = st.dictionaries(
    st.sampled_from(
        ["path", "to", "amount", "query", "subject", "note", "target_host"]
    ),
    _arg_values,
    max_size=5,
)


@given(tool_name=_tool_names, role=_roles, args=_args)
@settings(max_examples=1000, deadline=None)
def test_INV_13_evaluate_call_is_pure_and_repeatable(
    tool_name: str, role: str, args: dict
) -> None:
    loaded = load_policy_set(REAL_POLICY_DIR)
    call = make_call(tool_name=tool_name, role=role, args=args)
    first = evaluate_call(call, loaded)
    second = evaluate_call(call, loaded)
    assert first == second


@given(tool_name=_tool_names, role=_roles, args=_args)
@settings(max_examples=200, deadline=None)
def test_INV_13_empty_policy_set_never_allows(
    tool_name: str, role: str, args: dict
) -> None:
    loaded = _rules_loaded(())  # default_action=DENY, no rules at all
    call = make_call(tool_name=tool_name, role=role, args=args)
    decision = evaluate_call(call, loaded)
    assert decision.outcome != Outcome.ALLOW


# ---------------------------------------------------------------------------
# PolicyEngine — the Evaluator-protocol adapter
# ---------------------------------------------------------------------------


def test_policy_engine_satisfies_evaluator_protocol() -> None:
    loaded = load_policy_set(REAL_POLICY_DIR)
    engine = PolicyEngine(loaded)
    decision = engine.evaluate(
        make_call(tool_name="read_file", role="analyst", args={"path": "notes.txt"})
    )
    assert decision.outcome == Outcome.ALLOW


def test_policy_engine_without_a_session_store_uses_empty_history() -> None:
    """Without a session_store (the default — this was PolicyEngine's only
    behavior through Phase 3), evaluate() always uses an empty history, so
    a sequence-gated tool is denied even with a "legitimate" prior call.
    Still real, tested, fail-closed-correct behavior for a caller that
    hasn't wired up session tracking — not a removed feature."""
    loaded = load_policy_set(REAL_POLICY_DIR)
    engine = PolicyEngine(loaded)
    decision = engine.evaluate(
        make_call(
            tool_name="send_email", role="analyst", args={"to": "a@corp.example.com"}
        )
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "sequence-send-email-requires-draft"


def test_INV_08_policy_engine_with_session_store_records_only_allowed_calls() -> None:
    """The Phase 4 integration: PolicyEngine records a call into the
    session store only when it was actually ALLOWED — a denied call must
    never count as "this happened" for a later sequence rule."""
    loaded = load_policy_set(REAL_POLICY_DIR)
    store = SessionStore()
    engine = PolicyEngine(loaded, session_store=store)

    denied = engine.evaluate(
        make_call(
            tool_name="send_email",
            role="analyst",
            session_id="s1",
            args={"to": "a@corp.example.com"},
        )
    )
    assert denied.outcome == Outcome.DENY
    assert store.get_history("s1") == ()  # the denied attempt was not recorded

    allowed = engine.evaluate(
        make_call(
            tool_name="read_file",
            role="analyst",
            session_id="s1",
            args={"path": "notes.txt"},
        )
    )
    assert allowed.outcome == Outcome.ALLOW
    assert [tool for tool, _ in store.get_history("s1")] == ["read_file"]


def test_INV_08_policy_engine_with_session_store_closes_the_sequence_gap() -> None:
    """The real, end-to-end proof: the sequence gate that was permanently
    denied through Phase 3 (see the test above) now correctly opens once
    the prerequisite tool has actually been allowed in the same session —
    exactly what firewall/session.py exists to make possible."""
    loaded = load_policy_set(REAL_POLICY_DIR)
    store = SessionStore()
    engine = PolicyEngine(loaded, session_store=store)

    draft = engine.evaluate(
        make_call(
            tool_name="compose_draft",
            role="analyst",
            session_id="s1",
            args={"subject": "s", "body": "b", "attachment_path": "sandbox/notes.txt"},
        )
    )
    assert draft.outcome == Outcome.ALLOW

    send = engine.evaluate(
        make_call(
            tool_name="send_email",
            role="analyst",
            session_id="s1",
            args={"to": "a@corp.example.com"},
        )
    )
    assert send.outcome == Outcome.ALLOW
    assert send.rule_id != "sequence-send-email-requires-draft"


def test_INV_10_policy_engine_with_audit_logger_shadow_logs_every_decision(
    tmp_path: Path,
) -> None:
    """INV-10/INV-11's "shadow logging": every decision gets a row, ALLOW
    included, not just denials."""
    loaded = load_policy_set(REAL_POLICY_DIR)
    with AuditLogger(
        tmp_path / "audit.db", policy_set_hash=loaded.policy_set_hash
    ) as logger:
        engine = PolicyEngine(loaded, audit_logger=logger)

        engine.evaluate(
            make_call(
                call_id="c1",
                tool_name="read_file",
                role="analyst",
                args={"path": "notes.txt"},
            )
        )
        engine.evaluate(
            make_call(
                call_id="c2",
                tool_name="read_file",
                role="intern",
                args={"path": "notes.txt"},
            )
        )

        with logger._session_factory() as session:
            rows = (
                session.execute(select(AuditLogRow).order_by(AuditLogRow.id))
                .scalars()
                .all()
            )

    assert len(rows) == 2
    assert rows[0].outcome == "ALLOW"
    assert rows[1].outcome == "DENY"
    assert rows[1].prev_hash == rows[0].entry_hash


# ---------------------------------------------------------------------------
# PolicyEngine — anomaly detection integration (firewall/anomaly.py, ADR 0013)
# ---------------------------------------------------------------------------


def test_policy_engine_enable_anomaly_detection_without_session_store_raises() -> None:
    """Three of the four detectors need real session history/declared-tools
    state — without a session_store they'd always see empty inputs and
    never fire, which is misleading enough to refuse outright."""
    loaded = load_policy_set(REAL_POLICY_DIR)
    with pytest.raises(ValueError, match="session_store"):
        PolicyEngine(loaded, enable_anomaly_detection=True)


def test_policy_engine_anomaly_detection_disabled_by_default() -> None:
    """A call that would trip the high-risk-sequence detector must sail
    through unaffected when enable_anomaly_detection is left at its
    default (False), even with a session_store present."""
    loaded = load_policy_set(REAL_POLICY_DIR)
    store = SessionStore()
    engine = PolicyEngine(loaded, session_store=store)

    draft = engine.evaluate(
        make_call(
            tool_name="compose_draft",
            role="analyst",
            session_id="s1",
            args={"subject": "s", "body": "b", "attachment_path": "sandbox/notes.txt"},
        )
    )
    assert draft.outcome == Outcome.ALLOW

    read = engine.evaluate(
        make_call(
            tool_name="read_file",
            role="analyst",
            session_id="s1",
            args={"path": "notes.txt"},
        )
    )
    assert read.outcome == Outcome.ALLOW

    send = engine.evaluate(
        make_call(
            tool_name="send_email",
            role="analyst",
            session_id="s1",
            args={"to": "a@corp.example.com"},
        )
    )
    assert send.outcome == Outcome.ALLOW


def test_INV_04_policy_engine_anomaly_detection_escalates_high_risk_sequence() -> None:
    """End-to-end: a call that policy alone would ALLOW gets escalated to
    NEEDS_APPROVAL once it matches a high-risk sequence — the anomaly
    layer folding in on top of an already-computed policy Decision,
    exactly as ADR 0013 describes."""
    loaded = load_policy_set(REAL_POLICY_DIR)
    store = SessionStore()
    engine = PolicyEngine(loaded, session_store=store, enable_anomaly_detection=True)

    draft = engine.evaluate(
        make_call(
            tool_name="compose_draft",
            role="analyst",
            session_id="s1",
            args={"subject": "s", "body": "b", "attachment_path": "sandbox/notes.txt"},
        )
    )
    assert draft.outcome == Outcome.ALLOW

    read = engine.evaluate(
        make_call(
            tool_name="read_file",
            role="analyst",
            session_id="s1",
            args={"path": "notes.txt"},
        )
    )
    assert read.outcome == Outcome.ALLOW

    send = engine.evaluate(
        make_call(
            tool_name="send_email",
            role="analyst",
            session_id="s1",
            args={"to": "a@corp.example.com"},
        )
    )
    assert send.outcome == Outcome.NEEDS_APPROVAL
    assert send.rule_id == "anomaly:high_risk_sequence"


def test_INV_08_policy_engine_anomaly_detection_halts_tool_outside_declared_set() -> (
    None
):
    """A call that policy alone would ALLOW gets denied outright once the
    session declared a narrower tool set than what's being called — HALT
    raises the outcome all the way to DENY, not just NEEDS_APPROVAL."""
    loaded = load_policy_set(REAL_POLICY_DIR)
    store = SessionStore()
    store.declare_session(
        "s1", identity="u1", role="intern", declared_tools=frozenset({"read_file"})
    )
    engine = PolicyEngine(loaded, session_store=store, enable_anomaly_detection=True)

    decision = engine.evaluate(
        make_call(
            tool_name="search_web",
            role="intern",
            session_id="s1",
            args={
                "query": "python list comprehension",
                "target_host": "docs.python.org",
            },
        )
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "anomaly:tool_outside_declared_set"


def test_policy_engine_anomaly_detection_never_records_a_halted_call_into_history() -> (
    None
):
    """A call HALTed by anomaly detection must not be recorded into
    session history — the same "only ALLOWed calls count" rule that
    already applies to a plain policy DENY."""
    loaded = load_policy_set(REAL_POLICY_DIR)
    store = SessionStore()
    store.declare_session(
        "s1", identity="u1", role="intern", declared_tools=frozenset({"read_file"})
    )
    engine = PolicyEngine(loaded, session_store=store, enable_anomaly_detection=True)

    engine.evaluate(
        make_call(
            tool_name="search_web",
            role="intern",
            session_id="s1",
            args={
                "query": "python list comprehension",
                "target_host": "docs.python.org",
            },
        )
    )
    assert store.get_history("s1") == ()
