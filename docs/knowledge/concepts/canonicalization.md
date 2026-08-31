---
tags: [architecture, canonicalization, security]
status: implemented
---

# Canonicalization

`firewall/canonicalize.py` (Phase 2). Four functions —
`canonical_path`, `canonical_host`, `canonical_email`/`canonical_email_list`,
`canonical_text` — each normalizes one value shape and returns a
`Canonical[T]` (`original`, `value`, `rejected_reason`, `.ok`). A rejection
is a DENY, never a fallback to the raw form (INV-06).

Also provides `matches_domain_allowlist(host, allowed_domain)` — label-
boundary domain matching (`notevil.com` and `evil.com.attacker.net` never
match a rule for `evil.com`) — implemented here rather than deferred to
Phase 3, since a canonical host with no correct way to compare it against a
rule isn't useful yet.

Key design choices (see [[0008-canonicalization-before-matching]] for the
full reasoning):
- `canonical_path` resolves real filesystem paths (`Path.resolve()` +
  `Path.is_relative_to`) rather than manipulating strings — immune by
  construction to sanitizer-stripping bypasses like `....//`.
- Percent-decoding happens exactly once; residual encoding (double
  encoding) is a DENY, never decoded again in a loop.
- Homoglyph domains aren't "fixed" — they're IDNA-encoded and correctly
  fail to match their ASCII lookalike's allowlist rule.
- Invisible/control characters never appear literally in this file's
  source or in the bypass corpus fixture — only as explicit `chr()`/`\xNN`
  constructions, for auditability.

Backed by `tests/fixtures/bypass_corpus.yaml` (44 entries) plus ~25
dynamic Python tests in `tests/test_canonicalize.py` covering NUL bytes,
control characters, CRLF injection, zero-width/bidi splitting, absolute-
path escapes, and symlink-to-parent traversal.

## Depends on
- [[interception-layer]] — Sits between the interceptor's raw `CallRecord.raw_args` and the policy engine.

## Used by
- [[policy-engine]] — Will only ever evaluate canonical values (Phase 3).

## Key decisions
- [[0008-canonicalization-before-matching]]
