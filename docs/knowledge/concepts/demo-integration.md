---
tags: [architecture, demo, integration, phase-6]
status: implemented
---

# Demo & Integration Layer

`demo_agent/` (`tools.py`, `wiring.py`, `attack_scenarios.py`,
`full_demo.py`) + `dashboard/app.py` + `scripts/run_bypass_suite.py` +
`scripts/run_all_demos.py` — Phase 6. The first code in this project to
assemble every earlier phase's piece together and run real calls through
all of it — every prior phase tested its own component in isolation.

**`demo_agent/tools.py`** — the 5 mocked tools
(`read_file`/`send_email`/`search_web`/`transfer_funds`/`compose_draft`,
ADR 0004's scope), deliberately with **no built-in argument validation**
of their own — naive, like a typical unprotected tool integration would
be. This is what makes `attack_scenarios.py`'s `--no-firewall` baselines
meaningful: the same payload that's blocked with the firewall genuinely
succeeds without it, because nothing inside the tool itself would have
stopped it either. `read_file` is the one tool that touches a real
filesystem (`sandbox/notes.txt`); the other four are pure mocks (INV-14).

**`demo_agent/wiring.py`** — `build_firewall()` assembles the real stack:
`load_policy_set` → [[session-state-and-audit-trail]]'s `SessionStore` →
`AuditLogger` → [[hitl-approval]]'s `HitlApprover` → [[policy-engine]]'s
`PolicyEngine` → [[interception-layer]]'s `GuardedToolRegistry`, with all
5 tools registered. Returns a `DemoFirewall` (itself a context manager,
closing the audit logger on exit) exposing `.guarded(name)` for
convenient lookup.

**`demo_agent/attack_scenarios.py`** — 5 scenarios, not arbitrary picks:
they're exactly what `docs/THREAT_MODEL.md` already names "Scenario 1"
through "Scenario 5" as evidence for T-1 (path traversal), T-3
(exfiltration), T-6 (privilege escalation), T-8 (out-of-order action),
and T-9 (rate exhaustion). Each runs twice — once through
`demo_agent.tools` directly (unmediated baseline) and once through the
real `build_firewall()` stack — so the *comparison* is the evidence.
Finding real bugs while building this is what led to [[0017-argument-scope-gate]] —
see that ADR for the incident.

**`demo_agent/full_demo.py`** — the interactive walkthrough: a realistic
multi-step `analyst` session (read → draft → send, with the anomaly
detector escalating the read-then-send sequence to a real human approval
prompt), then an `intern` search and a `finance` transfer, then a denied
traversal attempt. Blocks on real stdin for its approval prompt (INV-12)
— unlike `attack_scenarios.py`, which uses a non-interactive
auto-approve channel since no scenario's *attack* step is designed to
ever reach HITL.

**`dashboard/app.py`** — read-only Streamlit dashboard over the real
audit database (replaces the Phase 0 static-placeholder shell). Verified
headless (`streamlit run --server.headless true`, health-checked,
against a real populated database) rather than merely written and
assumed to work. Shows the hash-chain integrity status
(`firewall.logger.verify_chain`) in the sidebar, top-line ALLOW/DENY/
NEEDS_APPROVAL counts, a per-tool outcome chart, and a filterable audit
trail table — never writes to the database, never imports
`AuditLogger`/`PolicyEngine`/`firewall.interceptor`.

**`scripts/run_bypass_suite.py`** — replays the Phase 2 bypass corpus
(44 entries) and prints a human-readable pass/fail report, sharing the
exact corpus-loading and canonicalizer-calling logic
`tests/test_canonicalize.py` uses (imported, not reimplemented) so the
two can never silently drift apart. Exposes a public
`run_bypass_suite()` function `scripts/run_all_demos.py` calls directly.

**`scripts/run_all_demos.py`** — orchestrates the policy-load check, the
bypass suite, and all 5 attack scenarios (baseline + firewall) into one
unattended run with a consolidated summary and exit code. Deliberately
excludes `full_demo.py`, which blocks on a real interactive prompt.

## Depends on
- [[interception-layer]], [[policy-engine]], [[canonicalization]], [[session-state-and-audit-trail]], [[anomaly-detection]], [[hitl-approval]] — every earlier phase's piece, assembled here for the first time.

## Used by
- [[action-firewall]] — The concrete, runnable demonstration of the whole system.

## Key decisions
- [[0004-tool-scale-scope]] — Why 5 mocked tools.
- [[0017-argument-scope-gate]] — The severe bug this integration work found and fixed, and the broader lesson: prior phases' rule-isolated tests couldn't have caught it.
