# CHANGELOG — AI Agent Action Firewall

## 2026-08-13 — Phase 0: Project Scaffolding & Environment Setup
**Commit:** (initial — pre-git-init)
**Changed:** Created full project scaffold — directory structure (`/firewall`, `/policies`, `/demo_agent`, `/dashboard`, `/tests`, `/docs`), dependency manifest (`requirements.txt`), environment template (`.env.example`), `.gitignore`, `LICENSE` (MIT), `README.md` with architecture diagram, `PROGRESS.md`, GitHub Actions CI workflow, initial `tests/test_scaffold.py`, and Knowledge Vault (`/docs/knowledge/`) with concept notes and ADRs 0003–0006.
**Why:** Phase 0 deliverable — the team needs a clean, runnable scaffold they can clone and verify with `pip install -r requirements.txt && pytest` before any feature code is written.
**Files:** All files at repo root and under `/firewall`, `/policies`, `/demo_agent`, `/dashboard`, `/tests`, `/docs`, `/.github`
**Revert:** `git revert <hash>` (once initial commit is made)
