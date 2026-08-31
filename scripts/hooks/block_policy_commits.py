"""Pre-commit local hook: refuse to commit changes under policies/ when
running in CI (INV-03 — policies are treated as code, and are never meant
to be edited by an automated/scripted process, only by a human at a
keyboard).

Pre-commit only runs this hook when a staged file matches `files: ^policies/`
in .pre-commit-config.yaml, so by the time this script runs we already know
a policy file is being committed.

History (see LIMITATIONS.md and the CHANGELOG for the full story): this
hook originally also tried to detect "no human is at a terminal" via
`sys.stdin.isatty()`. That check was removed after a real run proved it
false-positived on a genuinely interactive commit — reading pre-commit's
own source (`pre_commit/util.py`'s `cmd_output_p`) confirmed why: for
every `language: system` hook, pre-commit unconditionally opens
`os.devnull` and passes it as the subprocess's `stdin`, regardless of
whether the human running `git commit` has a real terminal or not. That
means `sys.stdin.isatty()` is *always* `False` inside any pre-commit hook
— it carries no signal at all here, only false positives. This hook now
checks only the `CI` environment variable, which real CI systems set and
a normal local dev shell does not — a narrower, but honest and actually
functional, defense-in-depth signal. It cannot, and does not claim to,
distinguish "a human ran this command" from "an automated agent with
local shell access ran this command" — nothing at the git-hook layer can
make that distinction once pre-commit strips stdin. The real enforcement
of INV-03 (no agent-reachable code path can read or write policies/ at
runtime) lives in the interceptor, not here.
"""

import os
import sys


def is_running_in_ci() -> bool:
    return bool(os.environ.get("CI"))


def main() -> int:
    if is_running_in_ci():
        print(
            "BLOCKED: this commit touches policies/ and the CI environment "
            "variable is set.\n"
            "Policy files are treated as code and must be reviewed and "
            "committed by a human from a local clone, not an automated CI "
            "job (INV-03).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
