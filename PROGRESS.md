# Praetor — Project Progress Tracking

## Current Status: Phase 0 Complete (2026-08-30)

Phase plan below supersedes the earlier 0–8 outline: Phase 2 is now a
dedicated Canonicalization layer, built and tested before the policy
engine ever sees a raw argument.

---

## Phase Overview & Checklist

### [x] PHASE 0 — Scaffolding, Secret Protection, Threat Model
- **Completed**: 2026-08-30
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

### [ ] PHASE 1 — Interception Layer (Total Mediation)
- `@firewall_guard` decorator + `GuardedToolRegistry`.
- Cover sync/async/`.invoke()`/`.ainvoke()`/`.run()`/batched/retried paths.
- Principal binding from `contextvars` (INV-05), freeze-after-evaluation
  (INV-07), fail-closed on exception (INV-01), bypass-audit test (INV-02).

### [ ] PHASE 2 — Canonicalization Layer
- `firewall/canonicalize.py`: `canonical_path`, `canonical_host`,
  `canonical_email`, `canonical_text`, all returning `Canonical[T]`.
- `tests/fixtures/bypass_corpus.yaml` (40+ entries), ADR
  0007-canonicalization-before-matching.

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
  above and `LIMITATIONS.md` for exactly what's still unverified (mainly:
  no live GitHub Actions run yet, since there's no remote configured).
- Ready to proceed to Phase 1 upon confirmation.
