# CLAUDE.md — Persistent Project Context

> **Where this file goes:** repository root (`/CLAUDE.md`).
> Claude Code loads it automatically at the start of every session, so the rules
> below apply to every task without being re-pasted. Keep it under ~400 lines.
> If a rule here conflicts with a chat instruction, **ask before proceeding** —
> do not silently pick one.

---

## 1. Project identity

**Name:** Praetor — a Deterministic Action Firewall for LLM Agents
**Type:** Final-year university project (3-person beginner team, 12-week timeline, viva + written report)
**One-line:** A middleware library that intercepts every tool call an LLM agent makes and evaluates it against static, human-authored policy *before* execution.

**The thesis:** the security boundary for agentic AI must move from the network/text layer to the **action layer**. Text filters are probabilistic and lose the arms race against paraphrase and encoding; a structured tool call is a concrete artifact that can be checked deterministically.

**Stack:** Python 3.11+ · LangChain (primary) · PyYAML · Pydantic v2 · SQLite (SQLAlchemy) · FastAPI · Streamlit · pytest · Docker · GitHub Actions

**Repo layout:**
```
firewall/      core library (interceptor, policy engine, canonicalizer, logger, anomaly, hitl)
policies/      YAML policy files — TREATED AS CODE, never agent-writable
demo_agent/    LangChain agent + mocked tools + attack scenarios
dashboard/     Streamlit read-only monitoring UI
tests/         pytest suite + evaluation harness
docs/          report material + knowledge/ (Obsidian vault: concepts, decisions, CHANGELOG)
scripts/       safe_push.sh, query_logs.py, verify_chain.py
sandbox/       throwaway fixture filesystem for file-tool tests (gitignored except fixtures)
```

---

## 2. Non-negotiable security invariants

Every invariant has an ID. Cite the ID in code comments, test names (`test_INV_06_percent_encoded_traversal_denied`), ADRs, and the report. **If you cannot satisfy one, stop and say so — do not silently weaken it.**

| ID | Invariant | Why it exists |
|----|-----------|---------------|
| **INV-01** | **Fail closed.** Any exception, timeout, missing policy, or unparseable input inside the firewall results in `DENY`, never `ALLOW`. | A firewall that fails open is a vulnerability, not a control. |
| **INV-02** | **Total mediation.** No reachable execution path to a guarded tool bypasses the interceptor — sync, async, batched/parallel, retried, or nested. Enforced at *registration* time, not by hoping every dev adds a decorator. | This is the single claim the whole project rests on. |
| **INV-03** | **Policy immutability at runtime.** Policies are loaded and hashed once at startup. The running process never reloads from disk on agent input, and no agent-accessible tool can read or write `policies/`. | Otherwise injection just rewrites the rules. |
| **INV-04** | **Zero LLM in the decision path.** No model call, no embedding, no heuristic scoring inside `evaluate()`. Pure functions over the call + policy + session state. | This is the project's novelty vs. Progent. Breaking it destroys the contribution. |
| **INV-05** | **Principal binding.** Session ID, agent identity and RBAC role come from a trusted server-side context (`contextvars` set at session creation), **never** from tool arguments or LLM output. | Otherwise the agent grants itself admin. |
| **INV-06** | **Canonicalize, then decide.** Every value is normalized before matching: `realpath` + symlink resolution for paths, Unicode NFKC, IDNA/punycode + lowercase for hosts, single percent-decode with rejection on residual encoding, whitespace/control-char stripping. Matching on raw input is a bug. | Parser-differential bypass is the #1 real-world way allowlists fail. |
| **INV-07** | **Decide on final arguments (no TOCTOU).** The exact argument object evaluated is the exact object passed to the tool. Deep-copy + freeze after evaluation; evaluate *after* Pydantic coercion, not before. | Prevents check-then-mutate races. |
| **INV-08** | **Deny by default.** Unknown tool → DENY. Unknown parameter → DENY. No matching rule → the policy set's explicit `default_action` (which ships as `DENY`). Never an implicit allow. | |
| **INV-09** | **Bounded evaluation.** Regex compiled at load with complexity linting and a per-evaluation timeout; caps on argument size, string length, nesting depth, and rule count. | A ReDoS in the firewall is a DoS on the whole agent. |
| **INV-10** | **Tamper-evident audit.** Each log row stores `prev_hash` and `entry_hash` (SHA-256 over canonical JSON), forming a hash chain. `scripts/verify_chain.py` detects any deletion or edit. | Cheap to build, very strong in a viva. |
| **INV-11** | **Log hygiene.** Never persist secrets, full file contents, or full email bodies. Store truncated previews plus SHA-256 of the full value. Redact `.env` keys and anything matching secret patterns before write. | The audit DB must be safe to attach to a report. |
| **INV-12** | **Out-of-band HITL.** The approval channel is not reachable by any agent tool. Agent-controlled text shown to the approver is escaped (strip ANSI/CR/LF, truncate, quote). Approval timeout → DENY. Approval is bound to a call-ID and single-use. | Otherwise injection writes the approval prompt the human reads. |
| **INV-13** | **Determinism.** Same (call, policy set, session state) → same decision, always. Property-tested. No wall-clock dependence except explicitly declared time windows, which are injected via a clock interface for testability. | |
| **INV-14** | **No live targets, ever.** All tools mocked. No outbound network in tests or demos (CI runs offline; a fixture blocks socket creation). Attack payloads only ever touch `sandbox/`. | Ethics, and it makes the demo reproducible. |
| **INV-15** | **No secrets in the repo.** Enforced by `.gitignore` + pre-commit (gitleaks + detect-secrets) + CI scanning + GitHub push protection. | |

---

## 3. Rules for the coding agent

### Honesty (highest priority)
- **Never report a test as passing without running it.** Paste the real `pytest` output.
- **Never invent numbers.** Latency, block rates, false-positive rates come from an actual harness run or they don't get written down. No placeholder metrics that could survive into the report.
- **Never invent citations, papers, CVEs, or version numbers.** If unsure, write `TODO(verify)` and say so in the phase summary.
- If something is broken, half-done, or you took a shortcut, put it in the phase summary under **Known Issues** and in `LIMITATIONS.md`. Silent gaps are what lose vivas.
- If a request would violate an invariant or seems offensive rather than defensive, refuse, explain, and propose the defensive alternative.

### Working style
- **Phase gating:** finish one phase, stop, summarize, wait for explicit "continue". Never batch phases.
- Every phase produces **runnable code plus passing tests**. No pseudocode.
- Tests are written alongside code, not after. Every policy rule and every invariant has at least one test.
- Small decisions: pick a sensible default, state the assumption in one line, move on. Expensive-to-reverse decisions: stop and ask.
- Code is written to teach capable beginners — clear names, short functions, a comment explaining *why* on anything non-obvious. No clever one-liners, no unexplained magic.
- Type hints everywhere; `ruff` + `black` clean; `mypy` on `firewall/` only.

### Definition of done (a phase is not done until all are true)
1. Code runs from a clean clone with documented commands.
2. `pytest` green; paste the output.
3. `ruff check . && black --check . && mypy firewall/` clean.
4. Invariant tests for anything this phase touched are present and named `test_INV_XX_*`.
5. `PROGRESS.md`, the relevant `docs/knowledge/concepts/*.md` note (with `[[wikilinks]]`), and `CHANGELOG.md` updated.
6. An ADR added if a real design decision was made.
7. `LIMITATIONS.md` updated with anything knowingly not handled.
8. Atomic git commit made; commit hash recorded in the CHANGELOG entry.

### Forbidden actions
- `git add -A` / `git add .` — always add explicit paths.
- `git push --force`, `git reset --hard`, history rewriting, or deleting branches without explicit human approval.
- Committing `.env`, `*.db`, `*.sqlite`, `venv/`, real API keys, or anything under `sandbox/runtime/`.
- `yaml.load` (use `yaml.safe_load`), `eval`, `exec`, `pickle` on any externally-influenced data.
- `shell=True` in subprocess calls.
- Network calls during tests.
- Writing outside the repo root or into `policies/` from any agent-reachable code path.
- Adding an LLM call anywhere inside the policy decision path (INV-04).
- Unpinned dependencies, or upgrading a pinned dependency without saying why.

---

## 4. Git and GitHub protocol

- **First commit of the repo** is `.gitignore` + `.gitattributes` + `.pre-commit-config.yaml`, before any code. Secrets protection precedes the thing being protected.
- One atomic commit per meaningful step. Conventional Commits format:
  `feat(policy): add sequence-rule evaluator` / `test(interceptor): cover async bypass path` / `docs(adr): 0009 canonicalization order`
- Commit body includes: what changed, why, and the invariant IDs touched.
- **Push only via `scripts/safe_push.sh`.** It runs, in order: `gitleaks detect` → `detect-secrets scan` → `pytest -q` → `pip-audit` → `git push`. Any failure aborts the push and prints why.
- Branch model: `main` is protected and always green. Work on `phase-N-<slug>` branches, merge via PR so the history shows review — useful evidence for the contribution-breakdown requirement.
- If a secret is ever detected in staged content or history: **stop immediately**, do not push, tell the human, and instruct them to rotate the credential first. Removing it from the working tree is not sufficient.

---

## 5. Knowledge vault protocol

Maintained continuously in `docs/knowledge/`, not batched at the end.

- `concepts/*.md` — one note per component. Frontmatter (`tags`, `status`), 1–3 sentence description, `## Depends on`, `## Used by`, `## Key decisions`. Every new note links to at least one existing note via `[[wikilinks]]`.
- `decisions/NNNN-*.md` — ADRs, sequentially numbered (0003–0006 already exist; the next new one is 0007). Format: Status / Context / Decision / Consequences (positive + negative) / Alternatives considered / Related.
- `CHANGELOG.md` — one entry per meaningful change: date, title, commit hash, changed, why, files, `git revert <hash>`.
- `index.md` — Map of Content linking every note.
- Never delete or overwrite a superseded note. Mark it `Superseded by [[new-note]]` and keep the history.

---

## 6. Team and audience context

Three beginners, ~1–1.5 hrs on weekdays plus one longer weekend session. Component ownership: **P1 interception · P2 policy engine · P3 logging/dashboard**, but *every member must be able to answer viva questions on every component* — so explanations matter as much as code.

The panel will probe: novelty vs. prior art (Progent, CaMeL, Rebuff, LLM Guard, NeMo Guardrails), bypass resistance, false positives, latency, and whether claims are honest and bounded. Write everything so it can be defended, and **bound every claim precisely** — "generalizes across two frameworks", not "across any framework"; "blocks the attack classes we modeled", not "prevents prompt injection".

---

## 7. Standing answers (keep consistent everywhere)

- **Fail mode:** fail-closed (INV-01), configured via `FAIL_SAFE_MODE=fail_closed`.
- **Policy engine:** in-process Python evaluator over YAML (ADR 0003); OPA/Rego is a documented stretch, not a claim.
- **HITL:** blocking CLI prompt, out-of-band from the agent (ADR 0005); dashboard button is a stretch.
- **Framework:** LangChain primary, optional small AutoGen demo (ADR 0006).
- **Tool count:** ~5 mocked tools, generic key-based schema (ADR 0004).
- **What Praetor does NOT stop:** a malicious action that is *within* policy; exfiltration through an allowlisted channel; a compromised LLM provider; anything outside the wrapped tool surface. Say this proactively — see `docs/THREAT_MODEL.md`.
