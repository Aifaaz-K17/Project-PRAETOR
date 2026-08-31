"""Tests for firewall/canonicalize.py — Phase 2 (INV-06).

Two halves:
1. A parametrized run of tests/fixtures/bypass_corpus.yaml — 44 entries
   covering path/host/email/text canonicalization and domain-allowlist
   label-boundary matching.
2. Explicit Python tests for anything involving a NUL byte, other control
   character, CR/LF, or zero-width/bidi character — deliberately kept out
   of the YAML corpus (see that file's header) and built here with
   Python's own unambiguous \\x00/\\r\\n/chr() escapes instead.
"""

import os
from pathlib import Path

import pytest
import yaml

from firewall.canonicalize import (
    Canonical,
    canonical_email,
    canonical_email_list,
    canonical_host,
    canonical_path,
    canonical_text,
    matches_domain_allowlist,
)

CORPUS_PATH = Path(__file__).parent / "fixtures" / "bypass_corpus.yaml"


def _load_corpus() -> list[dict]:
    with CORPUS_PATH.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


CORPUS_ENTRIES = _load_corpus()


@pytest.fixture
def sandbox(tmp_path: Path) -> dict[str, Path]:
    """A standard fixture tree every path-canonicalizer corpus entry is
    evaluated against: `sandbox/` is the allowed root, `outside/` is a
    sibling directory that must never be reachable from it."""
    sandbox_root = tmp_path / "sandbox"
    sandbox_root.mkdir()
    (sandbox_root / "notes.txt").write_text("sandboxed contents")
    (sandbox_root / "subdir").mkdir()
    (sandbox_root / "subdir" / "file.txt").write_text("sandboxed contents")

    outside_root = tmp_path / "outside"
    outside_root.mkdir()
    (outside_root / "secret.txt").write_text("must never be reachable")

    return {
        "tmp_path": tmp_path,
        "sandbox_root": sandbox_root,
        "outside_root": outside_root,
    }


# ---------------------------------------------------------------------------
# The corpus itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry", CORPUS_ENTRIES, ids=[e["id"] for e in CORPUS_ENTRIES])
def test_bypass_corpus_entry(entry: dict, sandbox: dict[str, Path]) -> None:
    canonicalizer = entry["canonicalizer"]

    if canonicalizer == "path":
        result = canonical_path(
            entry["input"],
            allowed_roots=[sandbox["sandbox_root"]],
            base_dir=sandbox["sandbox_root"],
        )
        if entry["expect"] == "deny":
            assert not result.ok, f"expected deny, got accepted as {result.value}"
        elif entry["expect"] == "allow_contained":
            assert result.ok, f"expected allow, got denied: {result.rejected_reason}"
            assert result.value is not None
            assert result.value.is_relative_to(sandbox["sandbox_root"]), (
                f"REAL BYPASS: {entry['id']} resolved outside the sandbox root: "
                f"{result.value}"
            )
        else:
            raise AssertionError(
                f"unknown expect value for a path entry: {entry['expect']!r}"
            )
        return

    if canonicalizer == "host":
        result = canonical_host(entry["input"])
        _assert_scalar_result(entry, result)
        if result.ok and "check_allowlist_against" in entry:
            actual_match = matches_domain_allowlist(
                result.value, entry["check_allowlist_against"]
            )
            assert actual_match == entry["expect_allowlist_match"], (
                f"{entry['id']}: matches_domain_allowlist({result.value!r}, "
                f"{entry['check_allowlist_against']!r}) == {actual_match}, "
                f"expected {entry['expect_allowlist_match']}"
            )
        return

    if canonicalizer == "email":
        result = canonical_email(entry["input"])
        _assert_scalar_result(entry, result)
        return

    if canonicalizer == "email_list":
        result = canonical_email_list(entry["input"])
        if entry["expect"] == "deny":
            assert not result.ok, f"expected deny, got accepted as {result.value}"
        elif entry["expect"] == "allow":
            assert result.ok, f"expected allow, got denied: {result.rejected_reason}"
            assert list(result.value) == entry["expected_canonical"]
        return

    if canonicalizer == "text":
        result = canonical_text(entry["input"])
        _assert_scalar_result(entry, result)
        return

    raise AssertionError(f"unknown canonicalizer in corpus entry: {canonicalizer!r}")


def _assert_scalar_result(entry: dict, result: Canonical) -> None:
    if entry["expect"] == "deny":
        assert not result.ok, f"expected deny, got accepted as {result.value!r}"
    elif entry["expect"] == "allow":
        assert result.ok, f"expected allow, got denied: {result.rejected_reason}"
        if "expected_canonical" in entry:
            assert result.value == entry["expected_canonical"]
    else:
        raise AssertionError(f"unknown expect value: {entry['expect']!r}")


def test_corpus_has_at_least_40_entries() -> None:
    assert len(CORPUS_ENTRIES) >= 40


def test_corpus_ids_are_unique() -> None:
    ids = [e["id"] for e in CORPUS_ENTRIES]
    assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Dynamic tests: NUL bytes, control characters, CR/LF, zero-width/bidi
# ---------------------------------------------------------------------------


def test_INV_06_path_nul_byte_truncation_denied(sandbox: dict[str, Path]) -> None:
    """Classic NUL-byte truncation attempt: some C-based APIs would treat
    everything after the NUL as absent, letting "notes.txt\\0.png" pass an
    extension check while actually opening "notes.txt"."""
    result = canonical_path(
        "notes.txt\x00.png",
        allowed_roots=[sandbox["sandbox_root"]],
        base_dir=sandbox["sandbox_root"],
    )
    assert not result.ok


def test_INV_06_path_nul_byte_in_traversal_denied(sandbox: dict[str, Path]) -> None:
    result = canonical_path(
        "../outside/secret.txt\x00.jpg",
        allowed_roots=[sandbox["sandbox_root"]],
        base_dir=sandbox["sandbox_root"],
    )
    assert not result.ok


def test_INV_06_path_control_char_denied(sandbox: dict[str, Path]) -> None:
    result = canonical_path(
        "notes.txt\x01",
        allowed_roots=[sandbox["sandbox_root"]],
        base_dir=sandbox["sandbox_root"],
    )
    assert not result.ok


def test_INV_06_host_nul_byte_denied() -> None:
    result = canonical_host("evil.com\x00.trusted.com")
    assert not result.ok


def test_INV_06_host_control_char_denied() -> None:
    result = canonical_host("evil.com\x01")
    assert not result.ok


def test_INV_06_email_crlf_header_injection_denied() -> None:
    """An attacker-controlled email field trying to inject a fake header
    (here, a forged Bcc:) via embedded CRLF must be rejected outright."""
    result = canonical_email("user@example.com\r\nBcc: attacker@evil.com")
    assert not result.ok


def test_INV_06_email_nul_byte_denied() -> None:
    result = canonical_email("user@example.com\x00")
    assert not result.ok


def test_INV_06_text_crlf_header_injection_stripped() -> None:
    """canonical_text strips (rather than rejects) control characters, so
    the CRLF a downstream header-injection attempt depends on is gone from
    the canonical value."""
    result = canonical_text("Meeting notes\r\nBcc: attacker@evil.com")
    assert result.ok
    assert "\r" not in result.value
    assert "\n" not in result.value
    assert result.value == "Meeting notesBcc: attacker@evil.com"


def test_INV_06_text_control_char_stripped() -> None:
    result = canonical_text("hello\x01world")
    assert result.ok
    assert result.value == "helloworld"


def test_INV_06_text_zero_width_joiner_split_stripped() -> None:
    """A denylisted word split by an invisible zero-width joiner, meant to
    look like ordinary text to a human but read as one word by naive
    substring matching after the invisible character is stripped."""
    zwj = chr(0x200D)
    result = canonical_text(f"de{zwj}lete")
    assert result.ok
    assert result.value == "delete"
    assert zwj not in result.value


def test_INV_06_text_bidi_override_stripped() -> None:
    """A right-to-left override character can make text render in an order
    different from its actual character sequence — stripped so both the
    canonical value and anything rendered from it are unambiguous."""
    rlo = chr(0x202E)
    result = canonical_text(f"safe{rlo}evil")
    assert result.ok
    assert rlo not in result.value


def test_INV_06_text_too_long_denied() -> None:
    too_long = "a" * 5000
    result = canonical_text(too_long, max_length=4096)
    assert not result.ok


def test_INV_06_text_at_max_length_allowed() -> None:
    exactly_max = "a" * 4096
    result = canonical_text(exactly_max, max_length=4096)
    assert result.ok


# ---------------------------------------------------------------------------
# Dynamic tests: values that need a real, runtime-known filesystem path
# ---------------------------------------------------------------------------


def test_INV_06_path_absolute_escape_denied(sandbox: dict[str, Path]) -> None:
    """An absolute path pointing straight at a location outside every
    allowed root — the value can't be a static YAML string because the
    "outside" directory's absolute path is only known at test time
    (tmp_path varies per run)."""
    absolute_target = str(sandbox["outside_root"] / "secret.txt")
    result = canonical_path(
        absolute_target,
        allowed_roots=[sandbox["sandbox_root"]],
        base_dir=sandbox["sandbox_root"],
    )
    assert not result.ok


def test_INV_06_path_data_dash_evil_does_not_pass_data_check(tmp_path: Path) -> None:
    """The exact bug string-prefix containment checks fall for: a sibling
    directory whose name starts with the allowed root's name as a string
    prefix (`/data-evil` vs `/data`) must not pass a `Path.is_relative_to`
    check, because that compares path *segments*, not string prefixes."""
    allowed_root = tmp_path / "data"
    allowed_root.mkdir()
    sibling_with_prefix_name = tmp_path / "data-evil"
    sibling_with_prefix_name.mkdir()
    (sibling_with_prefix_name / "secret.txt").write_text("must never be reachable")

    result = canonical_path(
        str(sibling_with_prefix_name / "secret.txt"),
        allowed_roots=[allowed_root],
    )
    assert not result.ok


def test_INV_06_path_symlink_to_parent_denied(sandbox: dict[str, Path]) -> None:
    """A symlink inside the allowed root pointing outside it — resolving
    symlinks (not just lexically normalizing `..`) is what INV-06 requires
    and what a naive lexical-only path check would miss.

    Creating a symlink on Windows requires Developer Mode or admin
    privileges (documented in LIMITATIONS.md); this test skips gracefully
    rather than failing the whole suite when that's unavailable. It runs
    for real in CI (ubuntu-latest), which is where it matters most.
    """
    link_path = sandbox["sandbox_root"] / "link_to_outside"
    try:
        link_path.symlink_to(sandbox["outside_root"], target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"cannot create symlinks in this environment: {exc}")

    result = canonical_path(
        "link_to_outside/secret.txt",
        allowed_roots=[sandbox["sandbox_root"]],
        base_dir=sandbox["sandbox_root"],
    )
    assert not result.ok


@pytest.mark.skipif(
    os.name != "nt", reason="backslash is only a path separator on Windows"
)
def test_INV_06_path_windows_backslash_traversal_denied(
    sandbox: dict[str, Path],
) -> None:
    """On Windows, backslash is a path separator, so this is a real
    traversal attempt there. On POSIX it is not (backslash is just a
    literal character in a filename), so this is Windows-only — see
    LIMITATIONS.md for the cross-platform note."""
    result = canonical_path(
        "..\\outside\\secret.txt",
        allowed_roots=[sandbox["sandbox_root"]],
        base_dir=sandbox["sandbox_root"],
    )
    assert not result.ok


def test_INV_06_path_unc_prefix_denied(sandbox: dict[str, Path]) -> None:
    result = canonical_path(
        "\\\\attacker-server\\share\\file.txt",
        allowed_roots=[sandbox["sandbox_root"]],
        base_dir=sandbox["sandbox_root"],
    )
    assert not result.ok


# ---------------------------------------------------------------------------
# Canonical[T] wrapper and other unit-level behavior
# ---------------------------------------------------------------------------


def test_canonical_accept_is_ok() -> None:
    result = Canonical.accept("raw", "value")
    assert result.ok
    assert result.value == "value"
    assert result.rejected_reason is None


def test_canonical_reject_is_not_ok() -> None:
    result = Canonical.reject("raw", "some reason")
    assert not result.ok
    assert result.value is None
    assert result.rejected_reason == "some reason"


def test_canonical_path_no_allowed_roots_denied(tmp_path: Path) -> None:
    result = canonical_path("notes.txt", allowed_roots=[])
    assert not result.ok


def test_canonical_email_list_accepts_a_sequence_not_just_a_string() -> None:
    result = canonical_email_list(["alice@example.com", "bob@example.com"])
    assert result.ok
    assert result.value == ("alice@example.com", "bob@example.com")


def test_canonical_host_idna_error_denied() -> None:
    # A label exceeding IDNA's 63-octet limit is a real IDNAError, not a
    # crash — proving canonical_host fails closed rather than propagating
    # an exception.
    result = canonical_host("a" * 300 + ".com")
    assert not result.ok
