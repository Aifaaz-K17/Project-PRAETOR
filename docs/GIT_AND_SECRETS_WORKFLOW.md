# Git, GitHub & Secrets Workflow — Praetor

Everything here is ready to paste. Set it up **before** the first line of firewall code:
protection has to exist before the thing it protects.

---

## 0. One-time setup (each team member, once)

```bash
# from the repo root
python -m venv venv && source venv/bin/activate     # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install pre-commit detect-secrets
pre-commit install                 # installs the commit-time hooks
pre-commit install --hook-type pre-push
detect-secrets scan > .secrets.baseline
```

Install gitleaks once per machine (`brew install gitleaks` / `winget install gitleaks` /
download the release binary). If it is missing, `safe_push.sh` refuses to push — that is
deliberate, not a bug.

Turn on **GitHub push protection** in the repo: Settings → Code security → Secret scanning →
Push protection. It is free on public repos and it is your last line of defence if a hook
gets skipped.

---

## 1. `.gitignore`

```gitignore
# --- secrets & config ---
.env
.env.*
!.env.example
*.pem
*.key
credentials.json
secrets.yaml

# --- data & runtime artefacts (audit logs can contain captured arguments) ---
*.db
*.sqlite
*.sqlite3
*.db-wal
*.db-shm
audit*.log
sandbox/runtime/
evaluation_output/

# --- python ---
venv/
.venv/
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
htmlcov/
dist/
build/
*.egg-info/

# --- editors / OS ---
.vscode/
.idea/
.DS_Store
Thumbs.db

# --- obsidian vault local state (keep the notes, drop the cruft) ---
docs/knowledge/.obsidian/
```

> **Why `*.db` is ignored:** the audit trail records tool arguments. Even redacted, an audit
> DB is the wrong thing to publish. Ship a script that generates a synthetic one instead.

## 2. `.gitattributes`

```gitattributes
* text=auto eol=lf
*.ps1 text eol=crlf
*.png binary
*.gif binary
*.mp4 binary
```

Three machines, at least one on Windows — without this you will get spurious whole-file
diffs and merge pain in week 7.

---

## 3. `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ["--baseline", ".secrets.baseline"]

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: check-added-large-files
        args: ["--maxkb=2000"]
      - id: check-merge-conflict
      - id: check-yaml
      - id: end-of-file-fixer
      - id: trailing-whitespace
      - id: detect-private-key

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.8.4
    hooks:
      - id: ruff
        args: ["--fix"]
      - id: ruff-format

  - repo: local
    hooks:
      - id: no-database-files
        name: block committing database files
        entry: bash -c 'echo "Refusing: database files must never be committed."; exit 1'
        language: system
        files: '\.(db|sqlite3?|db-wal|db-shm)$'

      - id: no-env-file
        name: block committing .env
        entry: bash -c 'echo "Refusing: .env must never be committed. Use .env.example."; exit 1'
        language: system
        files: '^\.env$'

      - id: policy-change-notice
        name: warn on policy file changes
        entry: bash -c 'echo "NOTE: policies/ changed — policies are security controls. Confirm this is intentional and add an ADR if the rule model changed."'
        language: system
        files: '^policies/.*\.ya?ml$'
        verbose: true
```

Pin the `rev` values; do not use `main`. Bump them deliberately, in their own commit.

---

## 4. `.env.example`

```dotenv
# Copy to .env and fill in. .env is gitignored — never commit it.

# --- LLM provider (OPTIONAL: the whole test suite runs offline with MockLLM) ---
# ANTHROPIC_API_KEY=
# OPENAI_API_KEY=
LLM_PROVIDER=mock

# --- firewall behaviour ---
FIREWALL_MODE=enforce          # enforce | shadow (log-only, never used for demo claims)
FAIL_SAFE_MODE=fail_closed     # fail_closed | fail_open  (INV-01: fail_closed is the only supported value)
POLICY_DIR=./policies
POLICY_HASH_PIN=               # set after `python scripts/verify_policies.py --print-hash`

# --- audit ---
AUDIT_DB_PATH=./sandbox/runtime/audit.db
LOG_LEVEL=INFO
REDACT_ARGS=true
MAX_LOGGED_ARG_CHARS=256

# --- HITL ---
HITL_ENABLED=true
HITL_TIMEOUT_SECONDS=120       # on timeout: DENY (INV-12)

# --- service ---
API_HOST=127.0.0.1             # never bind 0.0.0.0 for the viva demo
API_PORT=8000
API_RATE_LIMIT_PER_MIN=60
```

Rule: **the moment a new config key is introduced in code, it is added here in the same commit.**

---

## 5. CI — `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read          # least privilege; nothing here needs write

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  quality:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
        with:
          fetch-depth: 0        # gitleaks needs history

      - uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b  # v5.3.0
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install ruff black mypy pytest pip-audit bandit

      - name: Lint
        run: ruff check . && black --check .

      - name: Type check
        run: mypy firewall/

      - name: Tests (offline)
        run: pytest -q --maxfail=1

      - name: Dependency vulnerabilities
        run: pip-audit --strict

      - name: Static security scan
        run: bandit -r firewall/ -ll

      - name: Secret scan
        uses: gitleaks/gitleaks-action@83373cf2f8c4db6e24b41c1a9b086bb9619e9cd3  # v2.3.7
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Two things a panel notices: the explicit `permissions:` block and SHA-pinned actions.
Both are cheap and both are real supply-chain hygiene. Replace the SHAs with the current
ones for those versions when you set this up — **verify them, don't trust a pasted hash.**

Add `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: pip
    directory: "/"
    schedule: { interval: weekly }
  - package-ecosystem: github-actions
    directory: "/"
    schedule: { interval: weekly }
```

---

## 6. `scripts/safe_push.sh` — the only sanctioned way to push

```bash
#!/usr/bin/env bash
# Gate every push behind secret scanning and a green suite.
# Usage: ./scripts/safe_push.sh [branch]
set -euo pipefail

BRANCH="${1:-$(git rev-parse --abbrev-ref HEAD)}"
say() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
die() { printf '\n\033[31mABORTED: %s\033[0m\n' "$1" >&2; exit 1; }

say "1/6 refusing to push tracked secrets"
git ls-files | grep -E '(^\.env$|\.(db|sqlite3?|pem|key)$)' && \
  die "sensitive file is tracked by git. Untrack it (git rm --cached <file>) before pushing." || true

say "2/6 gitleaks (working tree + full history)"
command -v gitleaks >/dev/null || die "gitleaks not installed."
gitleaks detect --no-banner --redact || die "gitleaks found a potential secret. DO NOT PUSH. Rotate the credential first, then clean history."

say "3/6 detect-secrets"
detect-secrets scan --baseline .secrets.baseline || die "detect-secrets flagged new findings. Review, then update the baseline deliberately."

say "4/6 test suite"
pytest -q || die "tests failing — main must stay green."

say "5/6 dependency audit"
pip-audit --strict || die "vulnerable dependency. Fix or document before pushing."

say "6/6 pushing to origin/$BRANCH"
git push origin "$BRANCH"
printf '\n\033[32mPushed cleanly.\033[0m\n'
```

`chmod +x scripts/safe_push.sh`. Windows: run it from Git Bash, or ask the coding agent for
a `safe_push.ps1` twin.

---

## 7. Commit conventions

```
<type>(<scope>): <imperative summary>

<what changed, in one or two lines>
Why: <the reason, not a restatement of the diff>
Invariants: INV-02, INV-06
Refs: ADR 0007
```

Types: `feat` `fix` `test` `docs` `refactor` `chore` `sec`.
Scopes: `interceptor` `policy` `canon` `logger` `anomaly` `hitl` `dashboard` `demo` `eval` `ci`.

One logical change per commit. This history *is* your revert mechanism and it is also the
evidence behind `CONTRIBUTIONS.md` — `git shortlog -sn --no-merges` at the end will show
who actually did what, so commit under your own identity from day one.

---

## 8. Branch protection on `main`

Settings → Branches → add a rule for `main`:
- Require a pull request before merging (1 approval — you are three people, this is easy)
- Require status checks to pass: the `quality` job
- Require branches to be up to date before merging
- Block force pushes and deletions

Work on `phase-N-<slug>` branches. The PR trail is genuinely useful evidence of process
when a marker looks at the repo.

---

## 9. If a secret is ever committed

Do these **in order**. Reversing them is the common mistake.

1. **Rotate the credential immediately.** Revoke the key at the provider. Assume it is
   burned the moment it touched a git object — including in a PR, a branch you deleted, or
   a commit you amended.
2. Only then clean history: `git filter-repo --path .env --invert-paths` (or BFG). This
   rewrites hashes; coordinate with the other two before force-pushing, and get explicit
   human approval — the coding agent must never do this on its own.
3. Re-scan: `gitleaks detect --no-banner`.
4. Record it in `docs/knowledge/CHANGELOG.md` — a documented, correctly-handled incident is
   a positive signal, not an embarrassment. Panels ask "what went wrong during the project?"

---

## 10. Rules for the coding agent (also in `CLAUDE.md` §4)

- Never `git add -A` or `git add .` — always explicit paths.
- Never `git push --force`, `git reset --hard`, rewrite history, or delete branches without
  explicit human approval.
- Never commit `.env`, `*.db`, `venv/`, or anything under `sandbox/runtime/`.
- Push only via `scripts/safe_push.sh`.
- On any detected secret: stop, do not push, report, and instruct the human to rotate first.
- Update `.env.example` in the same commit that introduces a new config key.
