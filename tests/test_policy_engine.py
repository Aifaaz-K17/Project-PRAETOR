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

from firewall.canonicalize import canonical_path
from firewall.interceptor import CallRecord, Outcome
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
    ParameterBoundsRule,
    PathScopeRule,
    PolicySet,
    RbacRule,
    RuleAction,
)

REAL_POLICY_DIR = Path(__file__).parent.parent / "policies"
BENIGN_CALLS_PATH = Path(__file__).parent / "fixtures" / "benign_calls.yaml"


def make_call(
    *,
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
        call_id="test-call",
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
    assert 20 <= len(loaded.policy_set.rules) <= 25
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
    real = load_policy_set(REAL_POLICY_DIR)
    rule = next(r for r in real.policy_set.rules if r.id == rule_id)
    compiled = {k: v for k, v in real.compiled_patterns.items() if k == rule_id}
    return LoadedPolicySet(
        policy_set=PolicySet(default_action=RuleAction.DENY, rules=(rule,)),
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


def test_all_shipped_rules_have_at_least_one_test() -> None:
    """A structural guard, not a functional test: every rule id currently
    shipped in policies/ must be named somewhere in this file, so a new
    rule added later without a matching test fails CI immediately."""
    real = load_policy_set(REAL_POLICY_DIR)
    source = Path(__file__).read_text()
    missing = [rule.id for rule in real.policy_set.rules if rule.id not in source]
    assert missing == [], f"rules with no test coverage: {missing}"


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


def test_policy_engine_evaluates_against_empty_session_history() -> None:
    """Documents the current, honest Phase 3 scope: PolicyEngine.evaluate()
    always uses an empty history, so a sequence-gated tool is denied even
    with a "legitimate" prior call, until Phase 4 wires up real session
    tracking (LIMITATIONS.md)."""
    loaded = load_policy_set(REAL_POLICY_DIR)
    engine = PolicyEngine(loaded)
    decision = engine.evaluate(
        make_call(
            tool_name="send_email", role="analyst", args={"to": "a@corp.example.com"}
        )
    )
    assert decision.outcome == Outcome.DENY
    assert decision.rule_id == "sequence-send-email-requires-draft"
