# CHANGELOG — AI Agent Action Firewall

## 2026-08-13 — Phase 0: Project Scaffolding & Environment Setup
**Commit:** (initial — pre-git-init)
**Changed:** Created full project scaffold — directory structure (`/firewall`, `/policies`, `/demo_agent`, `/dashboard`, `/tests`, `/docs`), dependency manifest (`requirements.txt`), environment template (`.env.example`), `.gitignore`, `LICENSE` (MIT), `README.md` with architecture diagram, `PROGRESS.md`, GitHub Actions CI workflow, initial `tests/test_scaffold.py`, and Knowledge Vault (`/docs/knowledge/`) with concept notes and ADRs 0003–0006.
**Why:** Phase 0 deliverable — the team needs a clean, runnable scaffold they can clone and verify with `pip install -r requirements.txt && pytest` before any feature code is written.
**Files:** All files at repo root and under `/firewall`, `/policies`, `/demo_agent`, `/dashboard`, `/tests`, `/docs`, `/.github`
**Revert:** `git revert <hash>` (once initial commit is made)

## 2026-08-30 — Phase 0 hardening: secrets tooling, offline enforcement, real CI gate
**Commit:** `4d5c5bf`
**Changed:** Full `.pre-commit-config.yaml` (gitleaks, detect-secrets, check-added-large-files, end-of-file-fixer, ruff, black, mypy, plus two local hooks blocking `*.db`/`*.sqlite` commits and non-interactive `policies/` edits); real `.secrets.baseline` from an actual `detect-secrets scan`; `requirements.txt` pinned to exact versions + new `requirements-dev.txt`; rewritten `.github/workflows/ci.yml` with SHA-pinned actions, least-privilege `permissions:`, and a ruff→black→mypy→pytest→pip-audit→bandit→gitleaks gate; root `conftest.py` blocking real sockets in every test (INV-14) plus `tests/test_offline_enforcement.py`; `demo_agent/hello_world.py` rewritten to prove a mock-LLM → tool-call round trip with `GenericFakeChatModel` (no API key, no network); reorganized loose docs into `docs/`, `docs/planning/`, `docs/literature/` to match the full `CLAUDE.md` §1 tree; added `LIMITATIONS.md`.
**Why:** The initial Phase 0 scaffold (2026-08-13) had the directory shape but not the enforcement — no working secret-scan hooks, no offline-test guarantee, no real CI gate, no pinned dependencies. This pass makes every Phase 0 deliverable in `CLAUDE.md` §1/§2 and the detailed Phase 0 build prompt actually runnable and independently re-verifiable, not just present.
**Files:** `.pre-commit-config.yaml`, `.secrets.baseline`, `requirements.txt`, `requirements-dev.txt`, `requirements.lock`, `.github/workflows/ci.yml`, `.github/dependabot.yml`, `conftest.py`, `tests/test_offline_enforcement.py`, `demo_agent/hello_world.py`, `tests/test_scaffold.py`, `LIMITATIONS.md`, `PROGRESS.md`, `README.md`, `docs/**` (reorganized), `scripts/hooks/block_policy_commits.py`, `scripts/{safe_push.sh,verify_chain.py,verify_policies.py,query_logs.py}`, `sandbox/{fixtures,runtime}/.gitkeep`
**Revert:** `git revert 4d5c5bf`

## 2026-08-31 — Reconciled with GitHub remote (Aifaaz-K17/Project-PRAETOR)
**Commit:** `16c8f58`
**Changed:** Added `origin` remote and merged the repo's pre-existing GitHub-created history (an initial LICENSE + README commit) into local history via `git merge --allow-unrelated-histories`, rather than force-pushing over it. Resolved conflicts: kept the remote's LICENSE copyright holder ("Aifaaz Khan"); merged README.md into one file combining the remote's polished intro/tagline/disclaimer with the local Architecture/Directory/Quickstart sections, and pointed badges at the real repo.
**Why:** User asked to connect and push to the real GitHub repo. The repo already had content from GitHub's own repo-creation flow — merging preserves both histories instead of discarding one.
**Files:** `LICENSE`, `README.md`
**Revert:** `git revert 16c8f58` (note: this is a merge commit; reverting needs `-m 1`)

## 2026-08-31 — Phase 1: Interception Layer (Total Mediation)
**Commit:** (pending — see PROGRESS.md)
**Changed:** `firewall/context.py` (contextvars-based `Principal` binding, INV-05); `firewall/interceptor.py` (`CallRecord`, `Decision`, `Evaluator` protocol, `ToolCallDenied`, `GuardedTool`, `GuardedToolRegistry`, `firewall_guard` decorator, single fail-closed/TOCTOU-safe `_evaluate_call` chokepoint); `tests/_evaluators.py` (test-double evaluators); `tests/test_context.py` + `tests/test_interceptor.py` (35 tests, incl. the INV-02 bypass-audit headline test and two honest negative tests documenting the R-1 residual bypass); `demo_agent/interception_demo.py`; ADR `0007-interceptor-enforcement-point`. Also found and fixed a real bug in the Phase 0 INV-14 fixture: blocking `socket.socket` itself broke every async test on Windows (`ProactorEventLoop`'s self-pipe needs a real loopback socket pair) — fixed by blocking only non-loopback `connect`/`connect_ex`.
**Why:** Phase 1 deliverable per the detailed build prompt — total mediation (INV-02) is "the single claim the whole project rests on" (CLAUDE.md §2), so it needed to be provably true via one shared chokepoint and one comprehensive bypass-audit test, not asserted per-path.
**Files:** `firewall/context.py`, `firewall/interceptor.py`, `tests/_evaluators.py`, `tests/test_context.py`, `tests/test_interceptor.py`, `tests/test_offline_enforcement.py` (INV-14 fixture fix), `conftest.py` (INV-14 fixture fix), `demo_agent/interception_demo.py`, `docs/knowledge/decisions/0007-interceptor-enforcement-point.md`, `docs/knowledge/concepts/interception-layer.md`, `docs/knowledge/index.md`, `LIMITATIONS.md`, `PROGRESS.md`
**Revert:** `git revert <hash>` (once committed)
