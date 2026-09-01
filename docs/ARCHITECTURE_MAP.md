# Praetor — Architecture Map

> Maintained alongside each phase (see `PROGRESS.md`) — update this file
> when a phase adds, removes, or meaningfully changes what a file does.
> This is the fast-orientation document: what exists, what depends on
> what, and one line on what each file actually does. For *why* a design
> looks the way it does, follow the links into `docs/knowledge/` — this
> file deliberately doesn't repeat that reasoning.

## How a call actually flows

```mermaid
flowchart TD
    LLM["LLM agent decides to call a tool"] --> GT["GuardedTool / firewall_guard\n(firewall/interceptor.py)"]
    GT --> CTX["get_current_principal()\n(firewall/context.py) — INV-05"]
    GT --> EVC["_evaluate_call — the one chokepoint\n(firewall/interceptor.py) — INV-02, INV-07"]
    EVC --> PE["PolicyEngine.evaluate()\n(firewall/policy_engine.py)"]
    PE --> SS["SessionStore.get_history/get_declared_tools\n(firewall/session.py)"]
    PE --> CAN["canonical_path / canonical_host / canonical_email / canonical_text\n(firewall/canonicalize.py) — INV-06"]
    PE --> RULES["evaluate_call() over policies/*.yaml\n(loaded via load_policy_set) — INV-08, INV-13"]
    PE --> ANOM["detect_anomalies + apply_anomaly_findings\n(firewall/anomaly.py) — opt-in, INV-04"]
    PE --> LOG["AuditLogger.log_call\n(firewall/logger.py) — INV-10, INV-11"]
    PE -- Decision --> EVC
    EVC -- "outcome == NEEDS_APPROVAL?" --> HITL["HitlResolver.resolve_approval\n(firewall/hitl.py, if wired in) — INV-12"]
    HITL --> CHAN["CliApprovalChannel — blocking y/n prompt\n(sanitized rendering, timeout -> DENY)"]
    HITL --> LOG2["AuditLogger.log_call again\ncall_id suffixed :hitl — a 2nd row, never an edit"]
    HITL -- "final ALLOW/DENY" --> EVC
    EVC -- ALLOW --> TOOL["the real tool executes"]
    EVC -- "DENY (or NEEDS_APPROVAL, no resolver wired in)" --> DENIED["ToolCallDenied raised"]
    SS -. "record_call, only if ALLOW" .-> SS
```

`firewall/hitl.py` (Phase 5) resolves `NEEDS_APPROVAL` into a final
`ALLOW`/`DENY` via a blocking terminal prompt — see [[hitl-approval]].
Without a `hitl_resolver` wired into `GuardedToolRegistry`/
`firewall_guard` (the default), `Decision.allowed` still treats
`NEEDS_APPROVAL` the same as `DENY`, exactly as it did through Phase 4.

## `firewall/` — the library itself

| File | Lines | What it does | Depends on |
|---|---|---|---|
| `context.py` | 84 | `Principal` + `contextvars`-based binding (INV-05). `bind_principal`/`get_current_principal`; fail-closed `PrincipalNotBoundError` if nothing is bound. | — (no intra-package deps) |
| `interceptor.py` | 519 | The enforcement point (INV-02). `CallRecord`, `Decision`/`Outcome`, `Evaluator` + `HitlResolver` protocols, `GuardedTool`/`GuardedToolRegistry` (wraps a LangChain tool at registration time), `firewall_guard` decorator, `_evaluate_call` — the single fail-closed (INV-01), TOCTOU-safe (INV-07) chokepoint every execution path funnels through, including the optional Phase 5 HITL resolution step. | `context.py` |
| `canonicalize.py` | 398 | INV-06: normalize-then-decide. `Canonical[T]` result wrapper; `canonical_path` (real `Path.resolve()`, UNC/NUL/percent-encoding rejection), `canonical_host` + `matches_domain_allowlist` (IDNA/punycode, label-boundary matching), `canonical_email`/`canonical_email_list` (spoofing-resistant), `canonical_text` (NFKC, zero-width/bidi stripping, single percent-decode). | — (no intra-package deps) |
| `policy_schema.py` | 202 | Pydantic v2 models for the 7 rule types (`parameter_bounds`, `path_scope`, `domain_allowlist`, `sequence`, `rbac`, `rate`, `parameter_schema`), frozen, `extra="forbid"`, `PolicySet` with unique-rule-id validation. | — (no intra-package deps) |
| `policy_engine.py` | 709 | The decision core. `load_policy_set` (INV-03: load-once, SHA-256-hashed); `evaluate_call` — pure (INV-13), conflict resolution DENY>NEEDS_APPROVAL>ALLOW>default (INV-08); `_check_argument_scope` — a structural gate closing a severe bug where an `rbac` rule's blanket ALLOW vote bypassed `path_scope`/`domain_allowlist` scoping entirely (ADR 0017); INV-09 bounds + ReDoS defense (static lint + `regex` runtime timeout); `PolicyEngine` adapter wiring in session history, audit logging, and opt-in anomaly detection. | `interceptor.py`, `canonicalize.py`, `policy_schema.py`, `session.py`, `logger.py`, `anomaly.py` |
| `session.py` | 177 | `SessionStore` — real per-session call history (INV-13: injectable clock), one lock per session, TTL eviction, append-only via `record_call`. `declare_session` optionally registers a session's expected tool set (consulted by `anomaly.py`). | — (no intra-package deps) |
| `logger.py` | 391 | `AuditLogger` — SHA-256 hash-chained rows over WAL-mode SQLite (INV-10), `redact_value` secret-pattern redaction (INV-11). `verify_chain`/`ChainVerificationResult` — walks the chain, reports the first tampered row (shared by `scripts/verify_chain.py`). | `interceptor.py` (for `CallRecord`/`Decision` types) |
| `anomaly.py` | 294 | Second deterministic layer (INV-04): 4 pure detectors (call-volume spike, tool-outside-declared-set, high-risk sequence, argument-entropy jump) over `(call, session_history, declared_tools)`. `apply_anomaly_findings` folds results into an already-computed `Decision`, never downgrading it. | `interceptor.py`, `session.py` |
| `hitl.py` | 368 | Human-in-the-loop approval (INV-12). `sanitize_for_display` (strips ANSI/CR/LF, truncates, quotes); `HitlChannel` protocol + `CliApprovalChannel` (blocking `y/n` prompt, reader-thread+queue timeout, per-instance lock serializing concurrent requests — T-19); `HitlApprover` (single-use call-ID tracking, timeout→DENY, records an approved call into an optional `session_store`, logs a 2nd audit row suffixed `:hitl`). Implements `interceptor.py`'s `HitlResolver` protocol structurally — never imported by `interceptor.py` itself (avoids a circular import). | `interceptor.py`, `logger.py`, `session.py` |

## `policies/` — the rules themselves (YAML, never agent-writable — INV-03)

| File | Rule type | What it does |
|---|---|---|
| `rbac.yaml` | `rbac` | Who may call which tool at all — the base grant every other allowlist rule must compose with, not bypass (ADR 0012/0014). |
| `path_scope.yaml` | `path_scope` | `read_file`/`compose_draft` file-path containment inside `sandbox/`, scoped by role. |
| `domain_allowlist.yaml` | `domain_allowlist` | `send_email`/`search_web` destination-domain allowlists, scoped by role. |
| `parameter_bounds.yaml` | `parameter_bounds` | Numeric bounds (`transfer_funds.amount`), length caps, and suspicious-content denylist patterns. |
| `parameter_schema.yaml` | `parameter_schema` | Per-tool known-parameter sets — closes INV-08's "unknown parameter → DENY" gap (ADR 0011). |
| `sequence.yaml` | `sequence` | `send_email` requires a prior `compose_draft` in the same session. |
| `rate_limits.yaml` | `rate` | Per-tool call-count caps per rolling window, all 5 tools. |

29 rules total across the 7 files. `scripts/verify_policies.py` prints a
live summary (rule count, hash, tools covered) against whatever's
currently on disk — faster than reading all 7 files by hand.

## `scripts/` — operational CLIs (never part of the decision path)

| File | What it does |
|---|---|
| `verify_policies.py` | Loads `policies/` and prints a validation summary + integrity hash (INV-03). |
| `verify_chain.py` | Thin CLI wrapper over `firewall.logger.verify_chain` — walks an audit DB, reports OK or the first tampered row, sets exit code. |
| `query_logs.py` | Read-only CLI over the audit DB — filters by session/tool/outcome/role. Safe by construction: every row was already redacted at write time. |
| `run_bypass_suite.py` | Phase 6 — replays the 44-entry bypass corpus against the real canonicalizers, sharing `tests/test_canonicalize.py`'s exact loading/checking logic (imported, not reimplemented). Exposes a public `run_bypass_suite()` function. |
| `run_all_demos.py` | Phase 6 — orchestrates the policy-load check, the bypass suite, and all 5 attack scenarios into one unattended run with a summary/exit code. Excludes `demo_agent/full_demo.py` (blocks on real interactive input). |
| `hooks/block_policy_commits.py` | Local pre-commit hook: refuses a `policies/*.yaml` commit when the `CI` env var is set (defense-in-depth for INV-03, not itself the enforcement — that's the interceptor never exposing `policies/` to agent-reachable code). |

## `tests/` — 389 passed, 1 skipped (as of 2026-09-01)

| File | Lines | Covers |
|---|---|---|
| `test_context.py` | 97 | `firewall/context.py` — INV-05 binding/isolation. |
| `test_interceptor.py` | 483 | `firewall/interceptor.py` — the INV-02 bypass-audit headline test, INV-01/INV-07 fail-closed/TOCTOU tests. |
| `test_canonicalize.py` | 407 | `firewall/canonicalize.py` — the 44-entry bypass corpus (`fixtures/bypass_corpus.yaml`) + ~25 dynamic tests. |
| `test_policy_engine.py` | 1926 | `firewall/policy_engine.py` + `policy_schema.py` — by far the largest file: schema validation, load-time failures, per-rule-type isolated tests, conflict resolution, INV-09 bounds/ReDoS, the 70-entry benign-calls corpus, a Hypothesis determinism property test, `PolicyEngine` integration (session/audit/anomaly), the structural RBAC-composition guard (covering `requires_approval`-shaped rules too), and the argument-scope-gate regression tests (ADR 0017). |
| `test_session.py` | 173 | `firewall/session.py` — incl. an 8-thread×200-call concurrency test. |
| `test_logger.py` | 319 | `firewall/logger.py` — hash-chain tamper detection (edited row, deleted row, first-break-only reporting), redaction end-to-end. |
| `test_anomaly.py` | 348 | `firewall/anomaly.py` — each detector in isolation, orchestration order/determinism, every fold-in case. |
| `test_hitl.py` | 691 | `firewall/hitl.py` + the interceptor's `hitl_resolver` wiring — sanitized-display injection tests (T-14: ANSI/CR stripping), CLI-channel timeout (T-15), concurrent-approval serialization (T-19), `HitlApprover` single-use/timeout/crash-fails-closed, session-history recording, the 2nd-audit-row logging, and end-to-end registry/`firewall_guard` wiring (sync + async) against both test doubles and the real `PolicyEngine` + real `policies/`. |
| `test_offline_enforcement.py` | 47 | `conftest.py`'s INV-14 network-blocking fixture. |
| `test_scaffold.py` | 35 | Phase 0 scaffold sanity. |
| `_evaluators.py` | 93 | Test-double `Evaluator` implementations (incl. `NeedsApprovalEvaluator` for Phase 5) used by `test_interceptor.py`/`test_hitl.py` (not a real policy engine). |
| `fixtures/bypass_corpus.yaml` | — | 44 path/host/email/text bypass-attempt entries. |
| `fixtures/benign_calls.yaml` | — | 70 legitimate calls (false-positive-rate corpus for Phase 7). |
| `test_attack_scenarios.py` | 96 | `demo_agent/attack_scenarios.py` — every scenario's baseline must succeed unmediated and must be blocked when guarded; scenario 3 is RBAC-specific (not the amount bound); scenario 5's rate limit allows exactly 3 before blocking. |
| `test_demo_wiring.py` | 107 | `demo_agent/wiring.py` — all 5 tools register, `.guarded()` lookup, a real call goes through the full stack and gets recorded, `fresh_db=True` actually starts clean, the context manager closes the audit logger. |

## `demo_agent/` and `dashboard/` — Phase 6

| File | Status |
|---|---|
| `demo_agent/hello_world.py` | Phase 0 smoke test — proves a LangChain tool + a mock LLM round trip works, zero firewall code involved. |
| `demo_agent/interception_demo.py` | Phase 1 demo — real `GuardedToolRegistry`, but `_DemoEvaluator` is an illustrative stand-in ("deny anything containing 'delete'"), not `PolicyEngine`. |
| `demo_agent/tools.py` | Phase 6 — the 5 real mocked tools (`read_file`, `send_email`, `search_web`, `transfer_funds`, `compose_draft`), deliberately with no built-in argument validation of their own (naive, like a real unprotected integration) — `--no-firewall` attack-scenario baselines rely on this to demonstrate the vulnerability is real. `read_file` is the one that touches a real filesystem, resolved relative to `sandbox/`. |
| `demo_agent/wiring.py` | Phase 6 — `build_firewall()` assembles the real, full stack (policy engine + session store + audit logger + HITL approver + registry) with all 5 tools registered — the first code in this project to combine every phase's piece together and actually run a call through all of them. Returns a `DemoFirewall` (context manager, `.guarded(name)` lookup). |
| `demo_agent/attack_scenarios.py` | Phase 6 — 5 scenarios matching `docs/THREAT_MODEL.md`'s own "Scenario 1"–"Scenario 5" (T-1, T-3, T-6, T-8, T-9), each run both without and with the firewall. Building this found the severe bug fixed in ADR 0017. |
| `demo_agent/full_demo.py` | Phase 6 — the interactive end-to-end walkthrough with a real HITL approval prompt (blocks on real stdin — verified with a piped answer, bounded by a timeout). |
| `dashboard/app.py` | Phase 6 — real, read-only Streamlit dashboard over the audit database (replaces the Phase 0 static placeholder). Verified headless against real populated data + a health-endpoint check, not merely written and assumed to work. |

## Where the design reasoning lives (not repeated here)

- `CLAUDE.md` — the 15 numbered invariants (INV-01..INV-15) every file
  above is cited against.
- `docs/knowledge/index.md` — Map of Content: one concept note per
  component (`action-firewall`, `interception-layer`, `canonicalization`,
  `policy-engine`, `session-state-and-audit-trail`, `anomaly-detection`,
  `hitl-approval`, `demo-integration`), each with `Depends on`/`Used by`/
  `Key decisions`.
- `docs/knowledge/decisions/*.md` — ADRs 0003–0017, each a full
  Context/Decision/Consequences/Alternatives writeup.
- `docs/DEMO_GUIDE.md` — how to run every Phase 6 demo/verification script.
- `LIMITATIONS.md` — every knowingly-unhandled case, by phase.
- `PROGRESS.md` — phase-by-phase build log with commit hashes and what
  was actually verified.
