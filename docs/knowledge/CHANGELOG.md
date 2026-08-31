# CHANGELOG — AI Agent Action Firewall

## 2026-08-13 — Phase 0: Project Scaffolding & Environment Setup
**Commit:** (initial — pre-git-init)
**Changed:** Created full project scaffold — directory structure (`/firewall`, `/policies`, `/demo_agent`, `/dashboard`, `/tests`, `/docs`), dependency manifest (`requirements.txt`), environment template (`.env.example`), `.gitignore`, `LICENSE` (MIT), `README.md` with architecture diagram, `PROGRESS.md`, GitHub Actions CI workflow, initial `tests/test_scaffold.py`, and Knowledge Vault (`/docs/knowledge/`) with concept notes and ADRs 0003–0006.
**Why:** Phase 0 deliverable — the team needs a clean, runnable scaffold they can clone and verify with `pip install -r requirements.txt && pytest` before any feature code is written.
**Files:** All files at repo root and under `/firewall`, `/policies`, `/demo_agent`, `/dashboard`, `/tests`, `/docs`, `/.github`
**Revert:** `git revert <hash>` (once initial commit is made)

## 2026-08-30 — Phase 0 hardening: secrets tooling, offline enforcement, real CI gate
**Commit:** (pending — awaiting explicit commit confirmation, see PROGRESS.md)
**Changed:** Full `.pre-commit-config.yaml` (gitleaks, detect-secrets, check-added-large-files, end-of-file-fixer, ruff, black, mypy, plus two local hooks blocking `*.db`/`*.sqlite` commits and non-interactive `policies/` edits); real `.secrets.baseline` from an actual `detect-secrets scan`; `requirements.txt` pinned to exact versions + new `requirements-dev.txt`; rewritten `.github/workflows/ci.yml` with SHA-pinned actions, least-privilege `permissions:`, and a ruff→black→mypy→pytest→pip-audit→bandit→gitleaks gate; root `conftest.py` blocking real sockets in every test (INV-14) plus `tests/test_offline_enforcement.py`; `demo_agent/hello_world.py` rewritten to prove a mock-LLM → tool-call round trip with `GenericFakeChatModel` (no API key, no network); reorganized loose docs into `docs/`, `docs/planning/`, `docs/literature/` to match the full `CLAUDE.md` §1 tree; added `LIMITATIONS.md`.
**Why:** The initial Phase 0 scaffold (2026-08-13) had the directory shape but not the enforcement — no working secret-scan hooks, no offline-test guarantee, no real CI gate, no pinned dependencies. This pass makes every Phase 0 deliverable in `CLAUDE.md` §1/§2 and the detailed Phase 0 build prompt actually runnable and independently re-verifiable, not just present.
**Files:** `.pre-commit-config.yaml`, `.secrets.baseline`, `requirements.txt`, `requirements-dev.txt`, `requirements.lock`, `.github/workflows/ci.yml`, `.github/dependabot.yml`, `conftest.py`, `tests/test_offline_enforcement.py`, `demo_agent/hello_world.py`, `tests/test_scaffold.py`, `LIMITATIONS.md`, `PROGRESS.md`, `README.md`, `docs/**` (reorganized), `scripts/hooks/block_policy_commits.py`, `scripts/{safe_push.sh,verify_chain.py,verify_policies.py,query_logs.py}`, `sandbox/{fixtures,runtime}/.gitkeep`
**Revert:** `git revert <hash>` (once committed)
