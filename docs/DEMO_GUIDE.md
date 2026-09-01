# DEMO_GUIDE — How to Run Praetor's Phase 6 Demos

> All commands assume the repo root as the working directory and the
> project's venv activated (`pip install -r requirements.txt`). Every
> script here is offline (INV-14) — nothing makes a real network call.

## Quick start: run everything unattended

```
python scripts/run_all_demos.py
```

Runs, in order: a policy-load sanity check, the 44-entry bypass corpus
(`scripts/run_bypass_suite.py`), and all 5 attack scenarios
(`demo_agent/attack_scenarios.py`), each shown both without and with the
firewall. Prints a consolidated summary and exits non-zero if anything
unexpected happened. Nothing here blocks on interactive input.

## The 5 attack scenarios, on their own

```
python -m demo_agent.attack_scenarios
```

Each scenario maps directly to a row in `docs/THREAT_MODEL.md`:

| Scenario | Threat row | What it shows |
|---|---|---|
| 1 | T-1 | `read_file('../requirements.txt')` escapes `sandbox/` when unmediated; blocked when guarded. |
| 2 | T-3 | `send_email` to `attacker@evil.com` succeeds unmediated; blocked (argument-scope gate) when guarded. |
| 3 | T-6 | An `intern` with zero RBAC grant moves funds unmediated; blocked (RBAC, `default_action: deny`) when guarded. |
| 4 | T-8 | `send_email` with no prior `compose_draft` succeeds unmediated; blocked (sequence gate) when guarded. |
| 5 | T-9 | 4 rapid `transfer_funds` calls all succeed unmediated; the 4th is blocked (rate limit) when guarded. |

Each line of output is prefixed `[OK ...]` if the scenario behaved as
expected, `[UNEXPECTED ...]` if not — that prefix, not the human-readable
detail text, is what to check first.

## The interactive full demo (real approval prompt)

```
python -m demo_agent.full_demo
```

The only script here that blocks on real stdin — step 3 (an `analyst`
sending an email right after reading a file) is escalated to a live
human approval prompt by the anomaly detector, exactly as it would be in
a real deployment. Type `y` to approve, anything else (or wait 120s) to
deny. Every other step resolves immediately.

## The bypass corpus, on its own

```
python scripts/run_bypass_suite.py
```

Replays all 44 `tests/fixtures/bypass_corpus.yaml` entries (path
traversal, encoded/unicode tricks, domain allowlist near-misses, email
spoofing, control-character smuggling) against the real canonicalizers,
sharing the exact logic `tests/test_canonicalize.py` uses. Add `--quiet`
to only see failures and the summary line.

## The read-only audit dashboard

```
streamlit run dashboard/app.py
```

Opens in a browser (default `http://localhost:8501`). Reads from
`sandbox/runtime/demo_audit.db` by default (the sidebar lets you point
it at a different database) — run `full_demo.py` or
`attack_scenarios.py` first to populate one. Shows the hash-chain
integrity status, ALLOW/DENY/NEEDS_APPROVAL counts, a per-tool chart,
and a filterable table of every real audit row. Never writes anything.

## Inspecting the audit trail directly

```
python scripts/query_logs.py --db sandbox/runtime/demo_audit.db
python scripts/verify_chain.py --db sandbox/runtime/demo_audit.db
```

`query_logs.py` supports `--session-id`, `--tool-name`, `--outcome`, and
`--role` filters. `verify_chain.py` walks the hash chain and reports the
first tampered row, if any (INV-10).

## Verifying the policy set on its own

```
python scripts/verify_policies.py
```

Loads `policies/` and prints the rule count, default action, and
integrity hash — useful to confirm which policy version a demo run
actually used.

## What's mocked, and what isn't

`demo_agent/tools.py`'s 5 tools are deliberately naive — no path
containment, no domain allowlist, no amount cap, no role check of their
own (see that module's docstring for why). `read_file` genuinely reads
from disk (`sandbox/notes.txt`, or wherever a payload resolves to); the
other four never touch the network or a real ledger — every "sent" or
"transferred" result is a canned mock string. Every attack payload used
in this project stays inside the repository — never a real
external/system path, never a real network destination
(`conftest.py`'s INV-14 fixture blocks the latter outright in tests; the
demos simply never attempt it).
