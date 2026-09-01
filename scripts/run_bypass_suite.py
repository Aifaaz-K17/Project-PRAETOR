"""Replay the Phase 2 bypass corpus (tests/fixtures/bypass_corpus.yaml)
and print a human-readable pass/fail report — Phase 6.

`tests/test_canonicalize.py` already runs this exact corpus, exhaustively,
as 44 parametrized pytest cases — that remains the authoritative,
CI-enforced check. This script exists alongside it for a different job:
a fast, readable summary someone can run live during a demo or viva
without pytest's verbosity, sharing the identical logic so the two can
never silently drift apart (this script imports the same corpus loader
and canonicalizer functions `test_canonicalize.py` uses, not a
reimplementation of the checks).

Run with: python scripts/run_bypass_suite.py
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

# Run standalone (`python scripts/run_bypass_suite.py`), not as a package
# — put the repo root on sys.path so `import firewall...` resolves
# regardless of the caller's current directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml

from firewall.canonicalize import (
    canonical_email,
    canonical_email_list,
    canonical_host,
    canonical_path,
    canonical_text,
    matches_domain_allowlist,
)

CORPUS_PATH = (
    Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "bypass_corpus.yaml"
)


def _load_corpus() -> list[dict]:
    with CORPUS_PATH.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _make_sandbox_tree(base: Path) -> Path:
    """Same fixture shape tests/test_canonicalize.py's `sandbox` fixture
    builds — a contained sandbox/ root plus a sibling outside/ directory
    that must never be reachable from it."""
    sandbox_root = base / "sandbox"
    sandbox_root.mkdir()
    (sandbox_root / "notes.txt").write_text("sandboxed contents")
    (sandbox_root / "subdir").mkdir()
    (sandbox_root / "subdir" / "file.txt").write_text("sandboxed contents")

    outside_root = base / "outside"
    outside_root.mkdir()
    (outside_root / "secret.txt").write_text("must never be reachable")

    return sandbox_root


def _check_entry(entry: dict, sandbox_root: Path) -> str | None:
    """Returns None if the entry passed, or a failure description."""
    canonicalizer = entry["canonicalizer"]

    if canonicalizer == "path":
        result = canonical_path(
            entry["input"], allowed_roots=[sandbox_root], base_dir=sandbox_root
        )
        if entry["expect"] == "deny":
            if result.ok:
                return f"expected deny, got accepted as {result.value}"
            return None
        if entry["expect"] == "allow_contained":
            if not result.ok:
                return f"expected allow, got denied: {result.rejected_reason}"
            if result.value is None or not result.value.is_relative_to(sandbox_root):
                return f"REAL BYPASS: resolved outside the sandbox root: {result.value}"
            return None
        return f"unknown expect value for a path entry: {entry['expect']!r}"

    if canonicalizer == "host":
        host_result = canonical_host(entry["input"])
        scalar_failure = _check_scalar(
            entry, host_result.ok, host_result.rejected_reason
        )
        if scalar_failure is not None:
            return scalar_failure
        if host_result.ok and "check_allowlist_against" in entry:
            if host_result.value is None:
                raise RuntimeError(
                    "canonical_host reported ok=True but returned no value — this is a bug"
                )
            actual_match = matches_domain_allowlist(
                host_result.value, entry["check_allowlist_against"]
            )
            if actual_match != entry["expect_allowlist_match"]:
                return (
                    f"matches_domain_allowlist mismatch: got {actual_match}, "
                    f"expected {entry['expect_allowlist_match']}"
                )
        return None

    if canonicalizer == "email":
        email_result = canonical_email(entry["input"])
        return _check_scalar(entry, email_result.ok, email_result.rejected_reason)

    if canonicalizer == "email_list":
        email_list_result = canonical_email_list(entry["input"])
        if entry["expect"] == "deny":
            if email_list_result.ok:
                return f"expected deny, got accepted as {email_list_result.value}"
            return None
        if entry["expect"] == "allow":
            if not email_list_result.ok:
                return (
                    f"expected allow, got denied: {email_list_result.rejected_reason}"
                )
            return None
        return f"unknown expect value: {entry['expect']!r}"

    if canonicalizer == "text":
        text_result = canonical_text(entry["input"])
        return _check_scalar(entry, text_result.ok, text_result.rejected_reason)

    return f"unknown canonicalizer: {canonicalizer!r}"


def _check_scalar(entry: dict, ok: bool, rejected_reason: str | None) -> str | None:
    if entry["expect"] == "deny":
        if ok:
            return "expected deny, got accepted"
        return None
    if entry["expect"] == "allow":
        if not ok:
            return f"expected allow, got denied: {rejected_reason}"
        return None
    return f"unknown expect value: {entry['expect']!r}"


def run_bypass_suite(*, quiet: bool = False) -> tuple[int, int, list[tuple[str, str]]]:
    """Public entry point — used by this script's own `main()` and by
    `scripts/run_all_demos.py`, so the two never need to duplicate the
    corpus-walking logic or reach into each other's private functions.
    Returns `(passed, total, failures)`.
    """
    corpus = _load_corpus()
    failures: list[tuple[str, str]] = []

    with tempfile.TemporaryDirectory() as tmp:
        sandbox_root = _make_sandbox_tree(Path(tmp))
        for entry in corpus:
            failure = _check_entry(entry, sandbox_root)
            if failure is not None:
                failures.append((entry["id"], failure))
                print(f"FAIL {entry['id']}: {failure}")
            elif not quiet:
                print(
                    f"ok   {entry['id']} ({entry['canonicalizer']}, {entry['expect']})"
                )

    return len(corpus) - len(failures), len(corpus), failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print failures and the final summary line.",
    )
    args = parser.parse_args()

    passed, total, failures = run_bypass_suite(quiet=args.quiet)
    print(f"\n{passed}/{total} bypass corpus entries passed.")
    if failures:
        print(f"{len(failures)} FAILED — see above.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
