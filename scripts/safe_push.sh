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
    # `detect-secrets audit --fail-on-unaudited` doesn't exist in the
    # pinned detect-secrets==1.5.0 (requirements-dev.txt) — that flag
    # was never valid for this version's `audit` subcommand (confirmed
    # via `detect-secrets audit --help`), so the original one-liner here
    # always failed with an argparse error, on every version of this
    # script. Replaced with a direct read of the baseline JSON: any
    # finding missing an `is_secret` label (i.e. never triaged by a
    # human via `detect-secrets audit .secrets.baseline`) fails the
    # push — the same intent `--fail-on-unaudited` was going for.
    python -c "
import json, sys
with open('.secrets.baseline', encoding='utf-8') as f:
    baseline = json.load(f)
unaudited = [
    f'{filename}:{finding.get(\"line_number\")} ({finding.get(\"type\")})'
    for filename, findings in baseline.get('results', {}).items()
    for finding in findings
    if 'is_secret' not in finding
]
if unaudited:
    print('ABORT: unaudited findings in .secrets.baseline:', file=sys.stderr)
    for entry in unaudited:
        print(f'  - {entry}', file=sys.stderr)
    print('Run: detect-secrets audit .secrets.baseline', file=sys.stderr)
    sys.exit(1)
print('No unaudited findings in .secrets.baseline.')
"
else
    echo "ABORT: detect-secrets is not installed. Install it before pushing." >&2
    exit 1
fi

step "3/5 pytest -q"
# `python -m pytest`, not the bare `pytest` shim: the shim .exe proved
# unreliable under this shell (silently swallowed output and returned an
# inconsistent exit code across two consecutive identical runs, with no
# real test failure — `python -m pytest -q` reported the correct "356
# passed, 1 skipped" every time). `python -m X` always runs X in-process
# under the interpreter this script is already using, sidestepping
# whatever the shim-resolution issue was.
python -m pytest -q

step "4/5 pip-audit"
if python -c "import pip_audit" >/dev/null 2>&1; then
    python -m pip_audit -r requirements.txt
else
    echo "ABORT: pip-audit is not installed. Install it before pushing." >&2
    exit 1
fi

step "5/5 git push"
git push "$@"

echo
echo "safe_push.sh: all checks passed, push complete."
