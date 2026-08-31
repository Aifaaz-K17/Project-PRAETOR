#!/usr/bin/env bash
# safe_push.sh — the only sanctioned way to push (CLAUDE.md §4).
#
# Runs, in order: gitleaks detect -> detect-secrets scan -> pytest -q ->
# pip-audit -> git push. Any failure aborts the push and prints why.
set -euo pipefail

step() { echo; echo "==> $*"; }

step "1/5 gitleaks detect"
if command -v gitleaks >/dev/null 2>&1; then
    gitleaks detect --no-banner
else
    echo "ABORT: gitleaks is not installed. Install it before pushing." >&2
    exit 1
fi

step "2/5 detect-secrets scan (against .secrets.baseline)"
if command -v detect-secrets >/dev/null 2>&1; then
    detect-secrets scan --baseline .secrets.baseline
    detect-secrets audit --report --fail-on-unaudited .secrets.baseline >/dev/null
else
    echo "ABORT: detect-secrets is not installed. Install it before pushing." >&2
    exit 1
fi

step "3/5 pytest -q"
pytest -q

step "4/5 pip-audit"
if command -v pip-audit >/dev/null 2>&1; then
    pip-audit
else
    echo "ABORT: pip-audit is not installed. Install it before pushing." >&2
    exit 1
fi

step "5/5 git push"
git push "$@"

echo
echo "safe_push.sh: all checks passed, push complete."
