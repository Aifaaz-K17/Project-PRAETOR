# Senior Review: Gaps in v1, and the Revised 12-Week Plan

## Part A — What your v1 prompt already gets right

Keep these; they are better than most student projects manage.

- Phase gating with explicit stop-and-confirm
- ADRs with alternatives-considered and honest tradeoffs (0003–0006 are genuinely good)
- The knowledge vault with wikilinks and a changelog tied to commit hashes
- Scope discipline — 5 tools, in-process engine, Streamlit, local Docker primary
- The defensive-only boundary, stated up front
- Fail-closed already chosen in the Phase 0 report

## Part B — The gaps

Each row: what's missing, why a panel or an attacker finds it, and where the v2 prompt closes it.

| # | Gap in v1 | Why it matters | Closed in |
|---|-----------|----------------|-----------|
| 1 | **No threat model.** No stated adversary, assumptions, or non-goals. | The first hostile question is "what does this *not* stop?" Without a written answer you improvise, and improvising sounds like you never considered it. | `THREAT_MODEL.md`, Phase 0e |
| 2 | **No canonicalization layer.** Policies would match on raw strings. | This is *the* way allowlists fail in the real world. `..%252f`, `notevil.com` passing a `startswith("evil.com")` check, punycode homoglyphs, display-name-spoofed emails. Your firewall would demo perfectly and fall to a five-character change. | New Phase 2 + bypass corpus |
| 3 | **No principal binding.** Session ID and role were captured but their source was unspecified. | If they can come from tool arguments, the agent grants itself a role and RBAC is theatre. | INV-05, Phase 1 |
| 4 | **TOCTOU unaddressed.** Nothing pinned the checked args to the executed args. | Classic check-then-use race; also arises naturally from Pydantic coercion happening after evaluation. | INV-07, Phase 1 |
| 5 | **Policy files are agent-reachable.** The demo agent has `read_file` (and scenario 3 chains toward `write_file`) in a repo that contains `policies/`. | Injection rewrites the rules. This is the most embarrassing possible finding in a firewall project, and it's latent in the v1 design. | INV-03, Phase 3 |
| 6 | **No policy integrity or versioning.** | You can't reproduce a decision without knowing which rule set produced it. `policy_set_hash` on every audit row fixes it cheaply. | INV-03, Phase 3 |
| 7 | **No conflict-resolution rule.** With 15–20 policies, two will match the same call. | "Which rule wins?" is a certain viva question and currently has no answer. | INV-08, ADR 0008 |
| 8 | **Interception tested only on the happy path.** "3 tools, 100% of calls" misses async, batched/parallel calls, retries, exceptions, and `.invoke()` vs `.run()`. | The central claim of the project is total mediation. It needs to be proven at registry level, not decorator level. | INV-02, Phase 1 |
| 9 | **No ReDoS / resource bounds.** YAML policies imply regex; unbounded regex on attacker-controlled strings is a DoS on the firewall. | A hang is a fail-open in practice. | INV-09, Phase 3 |
| 10 | **`yaml.load` risk unstated**, and no schema validation of policy files. | v1 mentions malformed-YAML handling as an afterthought bullet. Unsafe deserialization is a real CVE class. | Phase 3 (Pydantic + `safe_load`) |
| 11 | **Audit log is not tamper-evident.** | Anyone with file access can edit SQLite rows. A hash chain costs ~20 lines and turns "we have logs" into "we have *evidence*". | INV-10, Phase 4 |
| 12 | **No log redaction.** Shadow logging + `read_file` means file contents land in the DB. | Your audit DB becomes the exfiltration channel, and it can't safely be attached to the report. | INV-11, Phase 4 |
| 13 | **HITL prompt renders untrusted text.** | ANSI/CR injection in an argument can redraw the operator's terminal and forge the approval line. Also: no timeout semantics, no single-use binding. | INV-12, Phase 5 |
| 14 | **No benign corpus — so no false-positive rate.** v1's Phase 6 promises an FPR with only 5 attack scenarios as input. | You would either report FPR = 0% (meaningless, and the panel will say so) or fabricate one. | Phase 3 builds it; Phase 7 uses it |
| 15 | **Latency reported as a mean.** | Means hide tail behaviour. p50/p95/p99 with a warm-up discard is the defensible version, and it's the same amount of work. | Phase 7 |
| 16 | **No adaptive-adversary evaluation.** 5 scripted scenarios that your own policies were written to catch. | This is the weakest part of the evaluation as designed. Running a 40-entry bypass corpus end-to-end and honestly reporting failures is what separates a 2:1 from a first. | Phase 6 `run_bypass_suite.py` |
| 17 | **No consolidated limitations register.** | Gaps discovered mid-build get forgotten by week 11. `LIMITATIONS.md` maintained continuously means the report writes itself and nothing ambushes you. | Cross-cutting |
| 18 | **Secrets protection lands mid-Phase-0**, alongside code. | Order matters: `.gitignore` and hooks must exist before there's anything to leak. Also no pre-commit, no secret scanning in CI, no push protection. | Phase 0a, `GIT_AND_SECRETS_WORKFLOW.md` |
| 19 | **CI has no security jobs and no least-privilege `permissions`.** | `pip-audit` is listed as a pre-submission checkbox rather than a gate. Add bandit, gitleaks, SHA-pinned actions. | Phase 0c |
| 20 | **No offline-test enforcement.** | One stray real API call in a test breaks reproducibility, costs money, and undermines the "sandboxed only" ethics claim. A socket-blocking fixture makes it structural. | INV-14, Phase 0d |
| 21 | **No anti-hallucination clause for the agent.** | The single biggest practical risk: a coding agent that reports passing tests it never ran, or writes a plausible latency number into `EVALUATION_RESULTS.md` that reaches your report. | `CLAUDE.md` §3 |
| 22 | **No AI-assistance disclosure.** | Increasingly required. Volunteering it is safe; being asked about it is not. | Phase 9 `ETHICS.md` |
| 23 | **Novelty claims unbounded.** "Generalizes across frameworks" from two frameworks; "prevents prompt injection" from bounded action control. | ADR 0006 already flags this instinct — apply it everywhere. Precise claims survive cross-examination. | `CLAUDE.md` §6 |
| 24 | **Numbering collision.** Your ADRs start at 0003 with 0001/0002 absent. | A panel will ask. Either write them (0001 fail-closed, 0002 action-layer-vs-text-layer — both are real decisions you made) or note the numbering origin in `index.md`. | Do this in week 4 |

---

## Part C — Revised 12-week plan

Same shape as your existing plan, same weekly effort. The hardening work replaces low-value
time (over-building policies, polishing the dashboard), it doesn't stack on top.

| Week | v1 focus | Revised focus | What changed |
|------|----------|---------------|--------------|
| 1 | Python + LLM foundations | Unchanged | — |
| 2 | LangChain basics | Unchanged | — |
| 3 | Attack reproduction + literature | + **Draft `THREAT_MODEL.md` §1–3 as a team** | The adversary model is a thinking exercise, not a coding one — do it while learning, not later |
| 4 | Scaffolding + component split | **Phase 0 hardened**: secrets-first commit, pre-commit, CI with security jobs, offline fixture, threat model finished. Write missing ADRs 0001–0002. | One extra session, pays for itself |
| 5 | Component build (parallel) | P1: interceptor + **total-mediation test**. P2: **canonicalization layer + bypass corpus** (before any policy work). P3: log schema + **hash chain**. | Canonicalization moves ahead of the policy engine — the order in v1 was backwards |
| 6 | Finish components + anomaly | P2: policy engine, schema validation, conflict resolution, **20–25 policies + 60–100 benign calls**. P3: redaction + anomaly detectors with documented thresholds. | Benign corpus is built here, not improvised in week 9 |
| 7 | Integration | Unchanged, plus **principal binding and policy-dir isolation tests** as part of wiring | These only become testable once integrated |
| 8 | Remaining 4 scenarios | + **`run_bypass_suite.py`** (Friday) | The highest-value single artefact in the build |
| 9 | Evaluation | Attack block rate, **FPR against the benign corpus**, **p50/p95/p99 latency**, environment stamp, threats-to-validity paragraph | Methodology, not just numbers |
| 10 | Deployment + docs | + `LIMITATIONS.md` consolidation, `ETHICS.md` with AI-assistance disclosure, hardened Dockerfile | — |
| 11 | Report writing | Unchanged. Threat model → Design chapter; limitations register → Discussion chapter; bypass suite → Evaluation chapter | Three chapters are now largely pre-written |
| 12 | Demo prep + buffer | + **`VIVA_PREP.md` mock viva using the hostile question list** | — |

**Where the time comes from:** v1 allocates a full week to "finish components" with slack,
and the dashboard is deliberately minimal. The canonicalization layer is roughly two evenings.
The hash chain is one. The benign corpus is one, and it's the kind of task that splits well
across three people.

---

## Part D — The seven questions to be ready for

Test yourselves against these in the week-12 mock viva. If any of the three of you can't
answer one, that's the gap to close.

1. **"How would *you* bypass your own firewall?"** — the correct answer is a confident,
   specific list (residual risk R-1, non-goals 1–3 in the threat model), not "you couldn't".
2. **"Two policies match the same call and disagree. What happens?"** — DENY > NEEDS_APPROVAL > ALLOW, no match → explicit `default_action: DENY`. Point at ADR 0008.
3. **"What stops the agent from editing the policy file?"** — `policies/` outside every tool's allowed root, load-once, hash-pinned, and `test_INV_03_*` proves it.
4. **"Your false-positive rate is 0%. Is your benign corpus just easy?"** — describe how the 60–100 benign calls were constructed, name the near-miss cases in it, and concede the threat to validity.
5. **"What's genuinely novel here versus Progent?"** — zero-LLM-trust in the decision path, sequence-aware state machines rather than argument-level narrowing, tamper-evident audit, and near-zero deterministic latency. Then say what Progent does better: adaptive per-task least privilege that static policy cannot express.
6. **"Does the firewall add unusable latency?"** — p50/p95/p99 numbers, and the honest framing that microseconds of policy evaluation sit next to seconds of LLM inference.
7. **"What does Praetor not protect against?"** — read straight from §5 of the threat model. Answering this one *well* is worth more than any demo.
