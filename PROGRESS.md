# Praetor — Project Progress Tracking

## Current Status: Phase 2 Complete (2026-08-31)

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
- **Completed**: 2026-08-31
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

### [ ] PHASE 3 — Policy Engine
- `firewall/policy_engine.py` + `firewall/policy_schema.py` (Pydantic v2).
- Conflict resolution: DENY > NEEDS_APPROVAL > ALLOW; no match → default
  `DENY` (INV-08). Policy-set hash pinning (INV-03). ReDoS-safe loader
  (INV-09). Hypothesis determinism test (INV-13).
- 20–25 policies, `benign_calls.yaml` fixture (60–100 legitimate calls).

### [ ] PHASE 4 — Session State, Audit Trail, Anomaly Detection
- `firewall/session.py`, `firewall/logger.py` (SQLite/WAL, hash-chained —
  INV-10, redaction — INV-11), `firewall/anomaly.py` (rule-based only).

### [ ] PHASE 5 — HITL Approval
- `firewall/hitl.py`: blocking CLI approval, sanitized rendering (INV-12),
  single-use call-ID with default-deny timeout.

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
- Ready to proceed to Phase 3 (Policy Engine) upon confirmation.
