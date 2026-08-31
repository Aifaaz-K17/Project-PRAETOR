"""Pre-commit local hook: refuse to commit changes under policies/ from a
non-interactive session (INV-03 — policies are treated as code, and are
never meant to be edited by an automated/scripted process, only by a human
at a keyboard).

Pre-commit only runs this hook when a staged file matches `files: ^policies/`
in .pre-commit-config.yaml, so by the time this script runs we already know
a policy file is being committed.

Honest limitation (recorded in LIMITATIONS.md): TTY detection is a
heuristic, not a hard security boundary. git's own hook invocation
environment varies by platform and git version, so this can have false
positives/negatives. It is a defense-in-depth speed bump against an
automated agent silently rewriting policy — the real enforcement of INV-03
(no agent-reachable code path can read or write policies/ at runtime) lives
in the interceptor, not here.
"""

import os
import sys


def is_noninteractive() -> bool:
    # A human running `git commit` at a real terminal has a TTY on stdin.
    # A script, bot, or CI runner invoking git non-interactively typically
    # does not — and CI itself sets the CI env var as a stronger signal.
    if os.environ.get("CI"):
        return True
    try:
        return not sys.stdin.isatty()
    except (AttributeError, ValueError):
        # No stdin at all (e.g. some IDE integrations) — treat as
        # non-interactive and block, per fail-closed spirit (INV-01).
        return True


def main() -> int:
    if is_noninteractive():
        print(
            "BLOCKED: this commit touches policies/ and was run from what "
            "looks like a non-interactive session (no TTY on stdin, or "
            "CI=1).\n"
            "Policy files are treated as code and must be reviewed and "
            "committed by a human at a real terminal (INV-03). If this is "
            "a false positive, run the commit again from an interactive "
            "shell.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
