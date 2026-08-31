# Praetor — Project Progress Tracking

## Current Status: Phase 5 Complete (2026-09-01)

Phase plan below supersedes the earlier 0–8 outline: Phase 2 is now a
dedicated Canonicalization layer, built and tested before the policy
engine ever sees a raw argument.

---

## Phase Overview & Checklist

### [x] PHASE 0 — Scaffolding, Secret Protection, Threat Model
- **Completed**: 2026-08-30 · **Commit**: `4d5c5bf`
- Repo layout matches `CLAUDE.md` §1 (`firewall/`, `policies/`,
  `demo_agent/`, `dashboard/`, `tests/`, `docs/`, `scripts/`, `sandbox/`).
- Secrets-first tooling: `.gitignore`, `.gitattributes`,
  `.pre-commit-config.yaml` (gitleaks, detect-secrets,
  check-added-large-files, end-of-file-fixer, ruff, black, mypy, plus two
  local hooks: block `*.db`/`*.sqlite` commits, block non-interactive
  edits to `policies/`), `.secrets.baseline` (real `detect-secrets scan`
  run, 0 findings), `.env.example`, MIT `LICENSE`.
- `requirements.txt` pinned to exact versions; `requirements-dev.txt` added
  for lint/type/security tooling; `requirements.lock` is the full frozen
  closure from the actual dev venv.
- `.github/workflows/ci.yml`: ruff → black --check → mypy firewall/ →
  pytest (offline) → pip-audit → bandit -r firewall/ → gitleaks. Actions
  pinned to commit SHAs (not floating tags), `permissions: contents: read`
  at the top, no secrets used beyond GitHub's own auto-issued
  `GITHUB_TOKEN`. `.github/dependabot.yml` added.
- `conftest.py`: autouse fixture blocks `socket.socket` in every test
  (INV-14), with `test_INV_14_network_is_blocked` proving it.
- `docs/THREAT_MODEL.md`: assets, trust boundaries, adversary model,
  attack-class → control → evidence table, and an explicit non-goals /
  residual-risk section.
- `demo_agent/hello_world.py`: proves a LangChain `@tool` invokes directly,
  *and* proves a full mock-LLM → tool-call → execution round trip using
  `GenericFakeChatModel`, with zero API keys and zero network access.
- **Verified locally** (see phase summary in conversation for full pasted
  output): `ruff check .`, `black --check .`, `mypy firewall/`,
  `pytest -v` (6/6 passed), `pip-audit -r requirements.txt` (0 known
  vulns), `bandit -r firewall/` (0 issues), `gitleaks git --staged` (0
  leaks), `pre-commit run` (all hooks pass against the real staged diff).
- **Known issues**: see `LIMITATIONS.md` — no GitHub remote configured yet
  so CI has never actually executed on GitHub; gitleaks binary needs
  manual local install; several planning-doc source files referenced by
  the team were never added to the repo.

### [x] PHASE 1 — Interception Layer (Total Mediation)
- **Completed**: 2026-08-31
- `firewall/context.py`: `Principal` + `contextvars`-based binding
  (`bind_principal`/`get_current_principal`), fail-closed
  `PrincipalNotBoundError` when unbound (INV-05).
- `firewall/interceptor.py`: `CallRecord`, `Decision`, `Evaluator`
  (`Protocol` — the seam Phase 3 implements), `ToolCallDenied`,
  `GuardedTool`, `GuardedToolRegistry`, `firewall_guard` decorator.
  `_evaluate_call` is the single chokepoint every execution path
  (`invoke`/`ainvoke`/`run`/`arun`/`batch`/`abatch`, retries) funnels
  through — fail-closed on any exception (INV-01), TOCTOU-safe via two
  independent pre-evaluation deep copies (INV-07).
- 35 passing tests across `tests/test_context.py` and
  `tests/test_interceptor.py`, including the INV-02 bypass-audit headline
  test and two *honest negative* tests documenting the one real residual
  bypass (a direct reference to the undecorated original).
- `demo_agent/interception_demo.py`: console demo of allowed/denied calls.
- ADR [`0007-interceptor-enforcement-point`](docs/knowledge/decisions/0007-interceptor-enforcement-point.md).
- **Verified locally**: `ruff check .`, `black --check .`, `mypy firewall/`,
  `pytest -v` (35/35 passed), `pip-audit` (0 vulns), `bandit -r firewall/`
  (0 issues) — see phase summary in conversation for full pasted output.
- **Known issues**: see `LIMITATIONS.md` Phase 1 section — the documented
  R-1 residual bypass, `Evaluator` has no real implementation yet (Phase
  3), `_SequenceCounters` is a Phase-4-pending placeholder, and a real bug
  found and fixed in the INV-14 test fixture (it broke async tests on
  Windows by blocking `socket.socket` itself instead of just outbound
  connections).

### [x] PHASE 2 — Canonicalization Layer
- **Completed**: 2026-08-31 · **Commit**: `9938fcb`
- `firewall/canonicalize.py`: `Canonical[T]` wrapper; `canonical_path`
  (real `Path.resolve()` + `Path.is_relative_to` containment, never string
  manipulation), `canonical_host` (IDNA/punycode, NFKC, userinfo/port
  rejection) + `matches_domain_allowlist` (label-boundary matching),
  `canonical_email`/`canonical_email_list` (display-name-spoofing
  rejection, all-recipients-must-pass), `canonical_text` (NFKC, zero-
  width/bidi stripping, single percent-decode with residual-encoding
  rejection, reject-not-truncate length cap).
- `tests/fixtures/bypass_corpus.yaml`: 44 entries (path/host/email/text),
  deliberately excluding any input with a NUL byte, control character,
  CRLF, or zero-width/bidi character — those are explicit Python tests
  instead, for source auditability (same reasoning applied to
  `canonicalize.py`'s own zero-width character set, built from integer
  code points via `chr()` rather than literal/escaped characters).
- `tests/test_canonicalize.py`: the corpus runner plus ~25 additional
  dynamic tests (NUL/control/CRLF/zero-width cases, absolute-path escape,
  the exact `/data` vs `/data-evil` string-prefix bug, symlink-to-parent,
  Windows-only backslash traversal, UNC-prefix rejection). 69 tests in
  this file alone (68 passed + 1 skipped — symlink test needs Windows
  Developer Mode locally; runs for real in CI).
- ADR [`0008-canonicalization-before-matching`](docs/knowledge/decisions/0008-canonicalization-before-matching.md)
  (renumbered from the suggested 0007 — see the ADR's numbering note).
- Added `idna==3.18` as a new pinned direct dependency (was previously
  only a transitive one).
- **Real bug found and fixed during this phase**: `_single_percent_decode`
  called `urllib.parse.unquote(value, errors="strict")` without catching
  `UnicodeDecodeError` — a malformed percent-encoded byte (e.g. `%ff`,
  not valid standalone UTF-8) would crash the caller instead of cleanly
  denying. Fixed by catching it and treating it as a rejection.
- **Real bug found and fixed via bandit**: `canonical_email_list` used a
  bare `assert` to narrow a type for mypy — `assert` is stripped under
  `python -O`, silently removing that safeguard. Replaced with an
  explicit, non-optimizable `if ... raise RuntimeError(...)`.
- **Verified locally**: `ruff check .`, `black --check .`, `mypy firewall/`,
  `pytest -v` (103 passed, 1 skipped across the whole suite), `pip-audit`
  (0 vulns), `bandit -r firewall/` (0 issues) — see phase summary in
  conversation for full pasted output.
- **Known issues**: see `LIMITATIONS.md` Phase 2 section — email domains
  as IP-literals-in-brackets aren't supported, the symlink test's local
  skip on Windows, the Windows-only backslash-traversal test, and the
  scope of the homoglyph/zero-width coverage (specific verified cases,
  not exhaustive Unicode confusables coverage).

### [x] PHASE 3 — Policy Engine
- **Completed**: 2026-08-31 · **Commit**: `7bd719b` (code/tests/docs); `policies/*.yaml` pending a human commit from an interactive terminal (see below)
- `firewall/policy_schema.py`: Pydantic v2 models for six rule types
  (`parameter_bounds`, `path_scope`, `domain_allowlist`, `sequence`,
  `rbac`, `rate`), frozen, `extra="forbid"`, unique-rule-id validation,
  `requires_approval` only valid on `action: allow`.
- `firewall/policy_engine.py`: `load_policy_set` (yaml.safe_load only,
  sorted deterministic order, SHA-256 `policy_set_hash` — INV-03);
  `evaluate_call` — pure (INV-13), DENY > NEEDS_APPROVAL > ALLOW > default
  conflict resolution (INV-08); `PolicyEngine` adapter satisfying
  `firewall.interceptor.Evaluator`; INV-09 argument-size/nesting caps;
  ReDoS defense in two layers — load-time linting (best-effort) plus a
  runtime timeout via the third-party `regex` package (the actual hard
  guarantee, verified against a pattern confirmed to hang stdlib `re`
  indefinitely).
- `firewall/interceptor.py`: `Decision` extended to a real 3-state
  `Outcome` (ALLOW/DENY/NEEDS_APPROVAL) — additive and backward-compatible
  via the `.allowed` property, all 27 Phase 1 tests still pass unmodified.
- `policies/*.yaml`: 23 rules across 6 files (path_scope, domain_allowlist,
  parameter_bounds, rbac, sequence, rate_limits) for a 5-mocked-tool demo
  world (`read_file`, `send_email`, `search_web`, `transfer_funds`,
  `compose_draft` — ADR 0004's scope).
- `tests/fixtures/benign_calls.yaml`: 70 legitimate calls (Phase 7's
  false-positive-rate metric needs this to exist to be computable at all).
- `tests/test_policy_engine.py`: 135 tests — schema validation, load-time
  failures, INV-03 (`policies/` outside every allowed root, structural +
  concrete traversal check), conflict resolution, INV-09 bounds and ReDoS
  (both the linter AND the runtime timeout tested independently), one
  isolated test per shipped rule (`test_all_shipped_rules_have_at_least_one_test`
  guards against a future rule shipping untested), the full benign corpus,
  and a Hypothesis property test (1000 random calls) for INV-13.
- `scripts/verify_policies.py` (real implementation, replacing the Phase 0
  stub) and `docs/POLICY_GUIDE.md` (real guide, replacing the Phase 0
  stub).
- ADRs [`0009-policy-conflict-resolution`](docs/knowledge/decisions/0009-policy-conflict-resolution.md)
  and [`0010-policy-integrity-and-loading`](docs/knowledge/decisions/0010-policy-integrity-and-loading.md).
- New pinned dependencies: `regex==2026.8.31` (runtime); `hypothesis==6.167.1`,
  `types-PyYAML`, `types-regex` (dev).
- **Real bugs found and fixed while building this**: (1) my own ReDoS
  timeout test initially used an input with no non-matching suffix, so the
  catastrophic pattern matched instantly instead of backtracking — fixed
  the test input, not the engine. (2) `policies/parameter_bounds.yaml`'s
  suspicious-subject pattern used the awkward phrase order "wire transfer
  urgent" instead of "urgent wire transfer", which a natural-language test
  call didn't match — fixed the policy's phrasing.
- **Verified locally**: `ruff check .`, `black --check .`, `mypy firewall/`,
  `pytest -v` (238 passed, 1 skipped across the whole suite), `bandit -r firewall/`
  (0 issues), `pip-audit` (0 vulns) — see phase summary in conversation for
  full pasted output.
- **Known issues**: see `LIMITATIONS.md` Phase 3 section — chiefly that
  `sequence`/`rate` rules can't yet be exercised end-to-end through the
  live interceptor (needs Phase 4's session store), and the ReDoS linter's
  best-effort (not exhaustive) scope.

### [x] PHASE 4 — Session State, Audit Trail, Anomaly Detection
- **Completed**: 2026-09-01 · **Commits**: `eef9a98` + `6dc4dd8` (part 1 —
  session store, audit logger, RBAC-bypass fix); `1bcc6d3` (part 2 —
  anomaly detection, verify_chain/query_logs, logger tests, combined
  with the pre-Phase-5 security review below into one commit).
- `firewall/session.py`: `SessionStore` — append-only, one
  `threading.Lock` per session, TTL eviction with an injectable clock
  (INV-13).
- `firewall/logger.py`: `AuditLogger` — SHA-256 hash-chained rows over
  WAL-mode SQLite (INV-10), `redact_value` secret-pattern redaction
  (INV-11), context-manager `close()`; `verify_chain`/
  `ChainVerificationResult` — walks the chain, reports the first tampered
  row.
- `firewall/anomaly.py`: four pure-function detectors (call-volume spike,
  tool-outside-declared-set, high-risk sequence, argument-entropy jump),
  `apply_anomaly_findings` folding results into a `Decision` — never
  downgrades an existing DENY (INV-04: still zero LLM/heuristic scoring
  in the decision path). Wired into `PolicyEngine` as an opt-in
  `enable_anomaly_detection` flag requiring a `session_store`.
- `firewall/policy_engine.py`: `PolicyEngine` now takes optional
  `session_store`/`audit_logger`/`enable_anomaly_detection`; records every
  ALLOWed call's history, shadow-logs every decision with latency, closes
  Phase 3's "session history always empty" gap for `sequence`/`rate`
  rules.
- `scripts/verify_chain.py` and `scripts/query_logs.py`: real CLI
  implementations, replacing the Phase 0 stubs.
- `tests/test_session.py` (12 tests, incl. an 8-thread×200-call
  concurrency test), `tests/test_logger.py` (20 tests — tamper detection
  on an edited/deleted row, redaction end-to-end against a planted fake
  secret), `tests/test_anomaly.py` (25 tests), plus `PolicyEngine`
  session/audit/anomaly-integration tests and the RBAC-composition
  regression tests in `tests/test_policy_engine.py`.
- **Real bug found and fixed (Phase 4 part 1)**: `path_scope`/
  `domain_allowlist` rules were unconditional `action: allow` grants
  matching any role, silently outvoting a co-located `rbac` rule's role
  restriction on the same tool under conflict resolution — an `intern`
  could read any in-scope file / email the corp domain despite no RBAC
  grant. Fixed with an opt-in `roles` field on both rule types. See ADR
  [`0012-rbac-composition-with-allowlist-rules`](docs/knowledge/decisions/0012-rbac-composition-with-allowlist-rules.md).
- **Real bug found and fixed (Phase 4 part 2)**: `mypy firewall/` failed
  with 4 errors once `verify_chain` started reading attribute values off
  a queried `AuditLogRow` instance — the legacy `Column(...)`-style
  declarative model (no `Mapped[...]` typing, no SQLAlchemy mypy plugin)
  is invisible to mypy as returning a real `str`/`int` at the instance
  level. Fixed with four narrow, documented `cast(str, ...)` calls at the
  actual read sites.
- ADRs [`0012-rbac-composition-with-allowlist-rules`](docs/knowledge/decisions/0012-rbac-composition-with-allowlist-rules.md)
  and [`0013-rule-based-anomaly-detection`](docs/knowledge/decisions/0013-rule-based-anomaly-detection.md).
- New pinned dependency: `sqlalchemy==2.0.52` (previously only
  transitive).
- **Verified locally**: `ruff check .`, `black --check .`,
  `mypy firewall/`, `pytest -v` (318 passed, 1 skipped across the whole
  suite), `bandit -r firewall/` (0 issues), `pip-audit -r requirements.txt`
  (0 known vulns) — see phase summary in conversation for full pasted
  output.
- **Known issues**: see `LIMITATIONS.md` Phase 4 section — anomaly
  detection's thresholds/pattern lists are curated and example-scale, not
  general attack-shape coverage; the entropy threshold isn't yet
  calibrated against the benign-calls corpus; `demo_agent/` still doesn't
  wire up the real `PolicyEngine`/`SessionStore`/`AuditLogger`/anomaly
  detection (Phase 6's task); the RBAC-composition fix (ADR 0012) is
  opt-in per rule, not automatically enforced.

### Pre-Phase-5 security review pass
- **Completed**: 2026-09-01 · **Commit**: `1bcc6d3` (same commit as Phase
  4 part 2 above).
- User-requested bug/vulnerability/weakness pass before starting Phase 5,
  plus a standing architecture map (`docs/ARCHITECTURE_MAP.md`, new) so a
  session can orient without re-reading every file.
- **3 real bugs found, independently reproduced, and fixed**: (1) a
  numeric-string value (e.g. `"amount": "999999"`) silently bypassed
  `parameter_bounds`' `min`/`max` checks entirely, letting an over-cap
  `transfer_funds` call through — fixed with `_coerce_numeric`, fails
  closed on anything unparseable; (2) `path-compose-draft-attachment-
  sandbox` and (3) `domain-search-web-reference-sites` were both
  unrestricted `path_scope`/`domain_allowlist` rules — a second and third
  real instance of ADR 0012's RBAC-composition bug, on rules that fix
  didn't touch. Both fixed the same way (populate `roles`).
- **1 structural guard added**: `test_INV_05_no_unrestricted_allowlist_rule_can_bypass_an_rbac_rule`
  — the guard ADR 0012 named as a follow-up but didn't build; verified it
  actually catches the pre-fix pattern (synthetic reconstruction), not
  just passes trivially against the now-fixed files.
- **1 suspected issue checked and found already correct**:
  `SessionStore.declare_session`'s history-reset behavior was
  misread as a bug before finding it's deliberate, existing, tested
  behavior (`test_declare_session_resets_history_if_called_again`) —
  reverted the attempted fix; kept a one-line docstring clarification.
  Recorded so "was this checked" has an honest answer either way.
- ADR [`0014-phase4-security-review-findings`](docs/knowledge/decisions/0014-phase4-security-review-findings.md)
  — full writeup of all four items above.
- **Verified locally**: `ruff check .`, `black --check .`,
  `mypy firewall/`, `pytest -v` (325 passed, 1 skipped), `bandit -r firewall/`
  (0 issues), `pip-audit -r requirements.txt` (0 known vulns) — re-run
  after each individual fix, not just once at the end.
- **Known issues**: see `LIMITATIONS.md`'s new section — the structural
  guard doesn't cover a `requires_approval`-shaped unrestricted rule
  (e.g. `domain-send-email-partner-needs-approval`), and doesn't check
  for an analogous gap against `sequence`/`rate` rules.

### [x] PHASE 5 — HITL Approval
- **Completed**: 2026-09-01 · **Commit**: `aca15b7`.
- `firewall/hitl.py`: `sanitize_for_display` (strips ANSI/CR/LF,
  truncates, quotes — INV-12); `HitlChannel` protocol + real
  `CliApprovalChannel` (blocking terminal `y/n`, reader-thread + bounded
  `queue.Queue` for a cross-platform timeout — `select.select()` on
  stdin isn't reliable on Windows console input); `HitlApprover`
  (single-use `call_id` tracking under a lock, timeout→DENY, fails
  closed on a channel crash, logs the resolution as a second audit row
  suffixed `:hitl` rather than editing the original NEEDS_APPROVAL row —
  INV-10's hash chain makes editing an existing row structurally
  unsafe).
- `firewall/interceptor.py`: new `HitlResolver` protocol (structural
  typing, mirrors `Evaluator`) defined here specifically so this module
  never has to import `firewall.hitl` (which needs `CallRecord`/
  `Decision`/`Outcome` from here) — avoids a circular import.
  `_evaluate_call` consults it inside the same fail-closed try/except
  every decision already goes through, only when the evaluator returns
  NEEDS_APPROVAL; threaded through `GuardedTool`/`GuardedToolRegistry`/
  `firewall_guard` as an optional `hitl_resolver` parameter — default
  `None` keeps every existing Phase 1-4 caller's behavior unchanged.
- `tests/test_hitl.py` (31 tests): sanitized-display injection tests
  (ANSI escape + CR/LF stripping — threat model T-14), a real
  timeout-doesn't-hang test against a stream that never answers (T-15),
  single-use replay refusal (T-15), fail-closed on a crashing channel,
  the 2nd-audit-row proof, and full sync/async interceptor-wiring tests
  (registry + `firewall_guard`, approve→executes / deny→`ToolCallDenied`).
  New test double `NeedsApprovalEvaluator` added to `tests/_evaluators.py`.
- ADR [`0015-hitl-resolution-mechanics`](docs/knowledge/decisions/0015-hitl-resolution-mechanics.md)
  (the concrete engineering decisions — protocol placement, timeout
  mechanism, audit-row shape — that
  [`0005-hitl-approval-mechanism`](docs/knowledge/decisions/0005-hitl-approval-mechanism.md)
  was written too early to make); new concept note
  [`hitl-approval`](docs/knowledge/concepts/hitl-approval.md);
  `interception-layer` concept note and `docs/ARCHITECTURE_MAP.md`
  updated.
- **Verified locally**: `ruff check .`, `black --check .`,
  `mypy firewall/`, `pytest -v` (356 passed, 1 skipped), `bandit -r firewall/`
  (0 issues), a real end-to-end smoke test wiring `PolicyEngine` →
  `HitlApprover` → `CliApprovalChannel` together (not just mocks) against
  the real `compose_draft`-as-`intern` NEEDS_APPROVAL rule, confirming a
  scripted "y" answer produces `ALLOW`/`hitl:approved`.
- **Known issues**: see `LIMITATIONS.md` Phase 5 section — a timed-out
  reader thread is never cancelled (Python can't safely interrupt a
  blocked read); `_consumed_call_ids` is unbounded for the life of a
  `HitlApprover`; `scripts/query_logs.py` has no convenience filter
  showing both audit rows for one logical call together; no dashboard
  approve/deny button (ADR 0005's noted stretch goal); `demo_agent/`
  doesn't wire this up yet (Phase 6's task).

### [ ] PHASE 6 — Dashboard + Integration + Attack Scenarios
- Read-only Streamlit dashboard, `demo_agent/` with 5 mocked tools, 5
  attack scenarios with `--no-firewall` baselines, `run_bypass_suite.py`
  against the full bypass corpus, `run_all_demos.py`.

### [ ] PHASE 7 — Evaluation
- `tests/evaluation.py` → `EVALUATION_RESULTS.md`: block rate, false
  positive rate (from the Phase 3 benign corpus), latency (p50/p95/p99),
  environment stamp, threats-to-validity section.

### [ ] PHASE 8 — Packaging & Deployment
- `Dockerfile` + `docker-compose.yml`, FastAPI service (localhost-bound,
  auth on mutating endpoints), `DEPLOYMENT.md`.

### [ ] PHASE 9 — Documentation & Report Support
- `README.md` architecture diagram, `COMPARISON.md`, `ETHICS.md` (incl. AI
  assistance disclosure), consolidated `LIMITATIONS.md`,
  `CONTRIBUTIONS.md`, `VIVA_PREP.md` (30 Q&A).

---

## Known Issues / Resume Notes
- Phase 0 verification commands all re-run and passed for real this
  session (not assumed from the prior Phase 0 pass) — see command list
  above and `LIMITATIONS.md` for exactly what's still unverified.
- A GitHub remote (`Aifaaz-K17/Project-PRAETOR`) is now connected on
  `main`, merged with its pre-existing initial commit rather than
  force-pushed over. First real GitHub Actions run still needs to be
  checked by hand once the push completes.
- Phase 1 verification commands all actually run — see command list above.
- Phase 2 verification commands all actually run — see command list above.
- Phase 3 verification commands all actually run — see command list above.
- Phase 4 verification commands all actually run — see command list
  above. Part 2, plus the pre-Phase-5 security review, committed as
  `1bcc6d3`.
- Phase 5 verification commands all actually run — see command list
  above. Committed as `aca15b7`.
- Ready to proceed to Phase 6 (Dashboard + Integration + Attack
  Scenarios) upon confirmation.
