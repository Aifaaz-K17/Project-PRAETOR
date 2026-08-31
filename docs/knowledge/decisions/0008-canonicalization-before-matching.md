---
tags: [decision, canonicalization, security]
status: accepted
date: 2026-08-31
---

# 0008 — Canonicalize Before Matching

## Status
Accepted.

> Numbering note: the master build prompt originally suggested this ADR be
> 0007. It's 0008 because Phase 1's interceptor decision claimed 0007 first
> — see [[0007-interceptor-enforcement-point]] for the renumbering
> rationale. Phase 3's ADRs become 0009/0010, Phase 4's becomes 0011.

## Context
INV-06 requires that every value is normalized before the policy engine
(Phase 3) ever compares it against a rule — matching on raw input is, per
CLAUDE.md, "the #1 real-world way allowlists fail." Four value shapes need
this: filesystem paths, hostnames, email addresses, and short free text.
Each has a well-known family of bypass techniques (encoding tricks,
homoglyphs, string-prefix confusion, header injection) that a naive
implementation of "just check if it matches" falls for.

## Decision
1. **Real filesystem resolution for paths, never string manipulation.**
   `canonical_path` uses `Path.resolve()` (which resolves symlinks and
   lexically normalizes `.`/`..`) and checks containment with
   `Path.is_relative_to`, never a string prefix comparison. This is a
   structural choice, not a rule added to catch a specific bypass: the
   `....//` trick that defeats a sanitizer stripping the literal substring
   `../` once doesn't apply here at all, because nothing here does string
   stripping. `tests/test_canonicalize.py::test_bypass_corpus_entry
   [path_quad_dot_slash_trick]` demonstrates this by expecting
   `allow_contained`, not `deny` — the honest claim is "this class of
   attack doesn't reach the code that would be vulnerable to it," not "we
   added a check for it."
2. **Single percent-decode, reject on residual encoding, never loop.**
   Decoding in a loop is exactly the bug that lets `..%252f` slip past a
   filter that only checks for `../` once. `_single_percent_decode` decodes
   exactly once and rejects if the result still matches `%[0-9A-Fa-f]{2}` —
   applied identically in `canonical_path` and `canonical_text`.
3. **Domain-allowlist matching is label-boundary, and lives here (not
   deferred to Phase 3).** `matches_domain_allowlist(host, allowed_domain)`
   checks `host == allowed_domain or host.endswith("." + allowed_domain)`.
   It's implemented in Phase 2 — ahead of the policy engine that will
   actually call it — because the corpus needed a home for `notevil.com`
   vs `evil.com` and `evil.com.attacker.net` vs `evil.com` *now*, and
   because canonicalization and matching are inseparable for hosts: a
   canonical host with no correct way to compare it against a rule isn't
   useful yet.
4. **Homoglyph domains are not "fixed" — they're left to correctly not
   match.** `canonical_host` IDNA-encodes to punycode and stops there. A
   Cyrillic lookalike of `apple.com` encodes to a *different* `xn--...`
   string than the ASCII original (verified:
   `аpple.com` → `xn--pple-43d.com`), so it fails an `apple.com` allowlist
   rule by simply not being equal to it — not because of a homoglyph
   detector. This is a smaller, more honest surface than trying to
   normalize lookalikes together, which can itself become a bypass vector
   if the normalization is ever incomplete.
5. **A rejected display name is a DENY, not a fallback to `addr_spec`.**
   `email.utils.parseaddr` already correctly extracts the real address out
   of `"admin@corp.com" <attacker@evil.com>` — the danger isn't parsing,
   it's a human (or a log line) trusting the display name. If the display
   name itself contains `@`, `canonical_email` rejects the whole value
   rather than silently proceeding with the (correctly parsed) real
   address, because downstream trust in the display name is the actual
   risk this exists to cut off.
6. **`canonical_text` strips rather than rejects control/zero-width/bidi
   characters; every other canonicalizer rejects on them.** A path, host,
   or email containing a control character is essentially always
   malicious intent (NUL truncation, CRLF header injection) with no
   legitimate reading — reject outright. Free text (a subject line, a
   search query) can legitimately have been typed on a device that
   inserted one, so stripping preserves the value's substance while still
   removing the character that enabled the attack (e.g. a CRLF that would
   otherwise inject a fake header if this text is later embedded in one).
7. **Cap violations are a DENY, never a silent truncation.** Truncating a
   too-long value would mean only the first N characters are ever checked
   against a policy pattern — placing a malicious payload after the cutoff
   would then bypass matching entirely while still executing in full.
   Rejecting is both simpler and closes that gap.
8. **Invisible/control characters never appear literally in source or test
   fixtures — only as explicit `chr()`/`\xNN` constructions.** Applied to
   both `firewall/canonicalize.py` itself (the zero-width/bidi character
   set is built from a table of integer code points via `chr()`, not typed
   as literal or escaped characters) and to
   `tests/fixtures/bypass_corpus.yaml` (which explicitly excludes any
   input containing a NUL byte, other control character, CR/LF, or
   zero-width/bidi character — those live in
   `tests/test_canonicalize.py` as plain Python string literals instead).
   An invisible character sitting directly in a security tool's source or
   fixture file is unauditable at a glance and exactly the kind of thing
   that could be pasted in wrong or silently mangled by an editor.

## Consequences
**Positive:**
- The bypass corpus (44 YAML entries + ~25 dynamic Python tests, 103
  passing total across the whole suite) is now the strongest evaluation
  asset for "can't an attacker just craft a call that looks legitimate?" —
  and it's auditable in a plain-text diff without a hex viewer.
- `canonical_path`'s containment check is proven against the exact
  `/data` vs `/data-evil` string-prefix bug via
  `test_INV_06_path_data_dash_evil_does_not_pass_data_check`.
- Phase 3's policy engine can call `canonical_*` + `matches_domain_allowlist`
  directly; nothing about matching semantics is still undecided.

**Negative / tradeoffs:**
- `canonical_email`'s domain canonicalization goes through `canonical_host`,
  which rejects IP-literal-in-brackets email domains (`user@[192.168.1.1]`,
  valid per RFC 5321) — an honest, narrow limitation rather than
  unverified RFC-completeness, recorded in `LIMITATIONS.md`.
- The symlink-to-parent test
  (`test_INV_06_path_symlink_to_parent_denied`) skips on this Windows dev
  machine without Developer Mode enabled (`os.symlink` needs elevated
  privileges there) — it runs for real in CI (`ubuntu-latest`), which is
  where it matters most, but that means the strongest evidence for this
  specific control is currently CI-only, not locally reproducible by every
  team member out of the box.
- Backslash-as-path-separator traversal
  (`test_INV_06_path_windows_backslash_traversal_denied`) is Windows-only
  by construction (`os.name != "nt"` skip) — backslash isn't a separator
  on POSIX, so it isn't a meaningful attack there either; this is a
  genuine platform asymmetry, not a gap.

## Alternatives considered
- **Regex-based traversal detection** (deny if the string contains `../`
  or similar patterns anywhere). Rejected: this is exactly the class of
  filter the `....//`-style bypass corpus entries defeat, and it doesn't
  compose with encoding — real path resolution subsumes it entirely.
- **Normalize homoglyph domains toward their ASCII lookalike** (e.g. via a
  confusables table) so `аpple.com` reads as `apple.com`. Rejected: this
  is a much larger surface (Unicode's confusables data changes over time,
  and an incomplete table is itself a bypass), for no benefit over the
  simpler "IDNA-encode and let it correctly not match."

## Related
- [[interception-layer]]
- [[0007-interceptor-enforcement-point]]
- [[policy-engine]] — Phase 3 will consume `Canonical[T]` and
  `matches_domain_allowlist` directly.
