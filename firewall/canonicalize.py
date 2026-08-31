"""Canonicalization layer — Phase 2.

INV-06 (canonicalize, then decide): the policy engine (Phase 3) must never
evaluate a raw argument value. Every value used in a decision is normalized
and validated here first. A value that fails validation is a `Canonical`
carrying a `rejected_reason` — which the policy engine (and, for now, the
tests in this phase) must treat as a DENY. There is no fallback to the raw
form: a rejected value is not "canonicalized as-is", it simply cannot be
used.

Four canonicalizers, one per value shape the demo tools in Phase 6 will
need: `canonical_path`, `canonical_host`, `canonical_email` (+
`canonical_email_list` for cc/bcc), `canonical_text`.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Generic, TypeVar
from urllib.parse import unquote

import idna

T = TypeVar("T")

# ---------------------------------------------------------------------------
# The Canonical[T] result wrapper
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Canonical(Generic[T]):
    """The result of canonicalizing one value.

    `original` is kept for audit logging (INV-11 will redact/truncate it
    before persisting). `value` is the canonical form, present only when
    `rejected_reason` is None. Checking `.ok` is the only thing calling
    code should need — never branch on `value is not None` alone, since a
    canonicalizer could in principle produce a falsy-but-valid value.
    """

    original: str
    value: T | None
    rejected_reason: str | None

    @property
    def ok(self) -> bool:
        return self.rejected_reason is None

    @staticmethod
    def accept(original: str, value: T) -> Canonical[T]:
        return Canonical(original=original, value=value, rejected_reason=None)

    @staticmethod
    def reject(original: str, reason: str) -> Canonical[T]:
        return Canonical(original=original, value=None, rejected_reason=reason)


# ---------------------------------------------------------------------------
# Shared primitives
# ---------------------------------------------------------------------------

# C0 controls (0x00-0x1F) plus DEL (0x7F). Never legitimate in a path, host,
# or email — a NUL byte truncates C-string-based filesystem APIs, and CR/LF
# enable header/log injection.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

# A single percent-encoded byte, e.g. %2F. Used both to decode and, after
# decoding once, to detect residual (double) encoding.
_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")

# Zero-width and bidi formatting characters that have no legitimate role in
# policy-relevant text and are a known technique for hiding characters from
# a human reviewer or splitting a denylisted word across an invisible
# boundary (e.g. splitting "delete" with an invisible character in between).
#
# Built from explicit integer code points via chr(), not from characters
# (escaped or literal) embedded in this file's source: an invisible
# character sitting directly in a security tool's source is exactly the
# kind of thing that could be pasted in wrong, rendered wrong by an editor,
# or hidden from a reviewer without anyone noticing. Listing the code
# points as plain integers keeps this auditable at a glance.
_ZERO_WIDTH_AND_BIDI_CODE_POINT_RANGES: tuple[tuple[int, int], ...] = (
    (0x200B, 0x200F),  # ZWSP, ZWNJ, ZWJ, LRM, RLM
    (0x2060, 0x2069),  # word joiner, invisible math operators, bidi isolates
    (0x202A, 0x202E),  # LRE, RLE, PDF, LRO, RLO
    (0xFEFF, 0xFEFF),  # BOM / zero-width no-break space
)
_ZERO_WIDTH_AND_BIDI_CHARS = "".join(
    chr(code_point)
    for start, end in _ZERO_WIDTH_AND_BIDI_CODE_POINT_RANGES
    for code_point in range(start, end + 1)
)
_ZERO_WIDTH_AND_BIDI_RE = re.compile(f"[{_ZERO_WIDTH_AND_BIDI_CHARS}]")


def _single_percent_decode(value: str) -> str | None:
    """Decode exactly one layer of percent-encoding. Returns None if the
    input contains a malformed percent-encoded byte sequence (e.g. `%ff`,
    which is not valid standalone UTF-8) or if the decoded result still
    contains a percent-encoded byte — that's residual (double) encoding,
    and the caller must reject rather than decode again. Decoding in a
    loop is exactly the bug that lets `..%252f` slip through a filter that
    only checks for `../` once (INV-06).
    """
    try:
        decoded = unquote(value, errors="strict")
    except UnicodeDecodeError:
        return None
    if _PERCENT_ENCODED_RE.search(decoded):
        return None
    return decoded


# ---------------------------------------------------------------------------
# canonical_path
# ---------------------------------------------------------------------------

# Windows UNC prefix (\\server\share\...) — a network-share access attempt
# has no business inside a local sandbox root, on any platform this code
# runs on, so it's rejected as a string pattern rather than relying on
# platform-specific path parsing to catch it.
_UNC_PREFIX_RE = re.compile(r"^\\\\")


def canonical_path(
    value: str,
    *,
    allowed_roots: Sequence[str | Path],
    base_dir: str | Path | None = None,
) -> Canonical[Path]:
    """Canonicalize a filesystem path and confirm it stays within one of
    `allowed_roots`.

    - Single percent-decode, rejecting residual encoding.
    - Rejects NUL bytes and other control characters.
    - Rejects Windows UNC prefixes.
    - Resolves symlinks and normalizes `.`/`..` via `Path.resolve()` (real
      filesystem resolution, not string manipulation — the class of bug
      this defeats is a sanitizer that strips the literal substring `../`
      once and can be bypassed with `....//`, which this design was never
      vulnerable to in the first place since nothing here does string
      stripping).
    - A relative `value` is resolved against `base_dir` (default: the
      first entry of `allowed_roots`) before the containment check.
    - Containment is checked with `Path.is_relative_to`, never a string
      prefix comparison — `/data-evil` must never pass a `/data` check.
    """
    if not allowed_roots:
        return Canonical.reject(value, "no allowed roots configured")

    if _CONTROL_CHAR_RE.search(value):
        return Canonical.reject(value, "path contains a NUL byte or control character")

    if _UNC_PREFIX_RE.match(value):
        return Canonical.reject(value, "UNC network-share paths are not allowed")

    decoded = _single_percent_decode(value)
    if decoded is None:
        return Canonical.reject(
            value,
            "invalid or residual percent-encoding (malformed byte sequence, or still percent-encoded after one decode pass)",
        )

    if _CONTROL_CHAR_RE.search(decoded):
        return Canonical.reject(
            value, "decoded path contains a NUL byte or control character"
        )

    resolved_roots = [Path(root).expanduser().resolve() for root in allowed_roots]
    base = (
        Path(base_dir).expanduser().resolve()
        if base_dir is not None
        else resolved_roots[0]
    )

    candidate = Path(decoded)
    if not candidate.is_absolute():
        candidate = base / candidate

    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        return Canonical.reject(value, f"could not resolve path: {exc}")

    for root in resolved_roots:
        if resolved.is_relative_to(root):
            return Canonical.accept(value, resolved)

    return Canonical.reject(
        value, f"path resolves outside all allowed roots: {resolved}"
    )


# ---------------------------------------------------------------------------
# canonical_host
# ---------------------------------------------------------------------------

# canonical_host validates a *bare hostname* only — no scheme, userinfo,
# port, path, query, or fragment. Any of those characters appearing means
# either the caller extracted the wrong substring from a URL, or an
# attacker is attempting exactly the userinfo/port confusion tricks this
# function exists to reject (e.g. "trusted.com:secret@evil.com").
_DISALLOWED_HOST_CHARS_RE = re.compile(r"[@:/\\?#\s]")


def canonical_host(value: str) -> Canonical[str]:
    """Canonicalize a bare hostname to its IDNA (punycode) ASCII form.

    Deliberately does NOT try to "fix" homoglyph domains — a Cyrillic
    lookalike of `evil.com` punycode-encodes to a different `xn--...`
    string than the ASCII original, and simply won't match an ASCII
    allowlist entry. That's the correct outcome (fail closed / no match),
    not a bug to work around.

    Domain-allowlist matching (`notevil.com` must never match a rule for
    `evil.com`; neither must `evil.com.attacker.net`) is label-boundary
    matching, implemented in `matches_domain_allowlist` below — this
    function's job is only to produce a comparable canonical form.
    """
    if _CONTROL_CHAR_RE.search(value):
        return Canonical.reject(value, "host contains a NUL byte or control character")

    stripped = value.strip()
    if not stripped:
        return Canonical.reject(value, "empty host")

    if _DISALLOWED_HOST_CHARS_RE.search(stripped):
        return Canonical.reject(
            value,
            "host must be a bare hostname (no userinfo, port, path, or whitespace)",
        )

    normalized = unicodedata.normalize("NFKC", stripped)
    normalized = normalized.rstrip(".")  # trailing-dot FQDN
    if not normalized:
        return Canonical.reject(value, "empty host after normalization")

    try:
        encoded = idna.encode(normalized, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        return Canonical.reject(value, f"invalid host: {exc}")

    return Canonical.accept(value, encoded.lower())


def matches_domain_allowlist(canonical_host_value: str, allowed_domain: str) -> bool:
    """Label-boundary domain match: `canonical_host_value` matches
    `allowed_domain` only if it equals it exactly or is a proper
    subdomain of it. `notevil.com` and `evil.com.attacker.net` must never
    match a rule for `evil.com` — both fail this check.

    Both arguments are expected to already be canonical (i.e. already
    passed through `canonical_host`); this function does not re-validate.
    """
    allowed = allowed_domain.strip().lower().rstrip(".")
    host = canonical_host_value.strip().lower().rstrip(".")
    return host == allowed or host.endswith("." + allowed)


# ---------------------------------------------------------------------------
# canonical_email / canonical_email_list
# ---------------------------------------------------------------------------


def canonical_email(value: str) -> Canonical[str]:
    """Canonicalize a single email address to `local@idna-encoded-domain`,
    lowercased.

    Uses `email.utils.parseaddr` to separate a display name from the real
    address — `"admin@corp.com" <attacker@evil.com>` correctly yields
    `attacker@evil.com`, never the display name. If the display name
    itself contains an `@`, that's a strong spoofing signal (there is no
    legitimate reason for a display name to look like an email address)
    and the whole value is rejected rather than silently trusting
    parseaddr's split.
    """
    if _CONTROL_CHAR_RE.search(value):
        return Canonical.reject(value, "email contains a NUL byte or control character")

    display_name, addr_spec = parseaddr(value)

    if not addr_spec or "@" not in addr_spec:
        return Canonical.reject(value, "could not parse a valid email address")

    if "@" in display_name:
        return Canonical.reject(
            value, "display name contains an email-like string (possible spoofing)"
        )

    local_part, _, domain_part = addr_spec.rpartition("@")
    if not local_part or not domain_part:
        return Canonical.reject(value, "email address missing local or domain part")

    domain_result = canonical_host(domain_part)
    if not domain_result.ok:
        return Canonical.reject(
            value, f"invalid email domain: {domain_result.rejected_reason}"
        )

    canonical_address = f"{local_part.lower()}@{domain_result.value}"
    return Canonical.accept(value, canonical_address)


def canonical_email_list(value: str | Sequence[str]) -> Canonical[tuple[str, ...]]:
    """Canonicalize a to/cc/bcc field that may carry multiple recipients.
    Every recipient must individually pass `canonical_email` — one bad
    address fails the whole field (INV-06: a rejection is a DENY, not a
    partial allow with the bad one silently dropped).

    Accepts either a single comma-separated string or a sequence of
    address strings, and uses `email.utils.getaddresses` to split a
    comma-separated string correctly (it understands quoted display names
    that themselves contain commas, unlike a naive `.split(",")`).
    """
    raw_list = [value] if isinstance(value, str) else list(value)
    parsed_pairs = getaddresses(raw_list)

    if not parsed_pairs:
        return Canonical.reject(str(value), "no recipients found")

    canonical_addresses: list[str] = []
    for display_name, addr_spec in parsed_pairs:
        # Reassemble a single-address string so canonical_email applies
        # its own (identical) parsing and spoofing checks uniformly.
        single = f'"{display_name}" <{addr_spec}>' if display_name else addr_spec
        result = canonical_email(single)
        if not result.ok:
            return Canonical.reject(
                str(value),
                f"recipient {addr_spec!r} rejected: {result.rejected_reason}",
            )
        if result.value is None:
            # Unreachable in practice (result.ok already checked above), but
            # `assert` is stripped under `python -O` (bandit B101) — this
            # stays a real, non-optimizable safeguard rather than relying
            # on that invariant silently holding forever.
            raise RuntimeError(
                "canonical_email reported ok=True but returned no value — this is a bug"
            )
        canonical_addresses.append(result.value)

    return Canonical.accept(str(value), tuple(canonical_addresses))


# ---------------------------------------------------------------------------
# canonical_text
# ---------------------------------------------------------------------------


def canonical_text(value: str, *, max_length: int = 4096) -> Canonical[str]:
    """Canonicalize a short free-text field (e.g. an email subject, a
    search query) for safe policy matching and safe display.

    - NFKC normalize.
    - Strip zero-width and bidi control characters (they hide content from
      a human reviewer without being visible).
    - Single percent-decode, rejecting residual encoding.
    - Strip all remaining C0 control characters, including CR/LF — a
      short-text field has no legitimate need for embedded newlines, and
      stripping them here is what stops a value from smuggling a fake
      header line into anything that later embeds this text into headers
      or logs.
    - Reject (not silently truncate) values over `max_length`: truncating
      would mean only the first N characters are ever checked against a
      policy pattern, which is itself a bypass vector for a payload placed
      after the cutoff.
    """
    if len(value) > max_length:
        return Canonical.reject(
            value, f"text exceeds max length of {max_length} characters"
        )

    normalized = unicodedata.normalize("NFKC", value)
    normalized = _ZERO_WIDTH_AND_BIDI_RE.sub("", normalized)

    decoded = _single_percent_decode(normalized)
    if decoded is None:
        return Canonical.reject(
            value,
            "invalid or residual percent-encoding (malformed byte sequence, or still percent-encoded after one decode pass)",
        )

    cleaned = _CONTROL_CHAR_RE.sub("", decoded)
    return Canonical.accept(value, cleaned)
