---
tags: [security, architecture, report]
status: draft
---

# Threat Model — Praetor Action Firewall

> **Why this file exists.** A security project without a threat model cannot say what it
> protects, from whom, under what assumptions. It is also the single highest-leverage viva
> document: most hostile questions are answered by pointing at a row in one of these tables.
> Fill the `TODO` markers as the build progresses; do not leave them in the submitted version.

---

## 1. System under protection

An LLM agent (LangChain) that ingests untrusted content and calls tools. Praetor sits at
the boundary between *"the model emitted a tool call"* and *"the tool executes"*.

```
untrusted content ──▶ LLM (untrusted output) ──▶ [ PRAETOR ] ──▶ tool execution
                                                     │
                                          policy · state · audit · HITL
```

**Trust boundaries:**

| # | Boundary | Left side | Right side |
|---|----------|-----------|------------|
| TB-1 | Content → LLM context | Fully attacker-controlled | Untrusted |
| TB-2 | LLM → tool call | Untrusted (may be attacker-steered) | **Praetor's input — the enforcement point** |
| TB-3 | Praetor → tool | Trusted, policy-approved | Executes with real effect |
| TB-4 | Praetor → audit log | Trusted writer | Append-only, tamper-evident |
| TB-5 | Praetor → human approver | Sanitized rendering | Human decision |

**Core design premise:** everything left of TB-2 is untrusted, including the model's own
reasoning. Praetor never asks the model whether an action is safe (INV-04).

---

## 2. Assets

| ID | Asset | Impact if compromised |
|----|-------|----------------------|
| A-1 | Local filesystem reachable by `read_file` | Confidentiality — data disclosure |
| A-2 | Outbound communication channel (`send_email`) | Confidentiality — exfiltration |
| A-3 | Financial action (`transfer_funds`) | Integrity — unauthorized value transfer |
| A-4 | Policy files (`policies/*.yaml`) | **Total control loss** — rules define the control |
| A-5 | Audit log | Non-repudiation — attacker erases evidence |
| A-6 | Human approval channel | Control bypass — attacker forges consent |
| A-7 | Session state / RBAC role | Privilege escalation |

---

## 3. Adversary model

**Capabilities (assumed):**
- Full control of any content the agent ingests (web pages, files, emails, API responses)
- Knowledge of Praetor's design and source (it is public — no security through obscurity)
- Ability to author arbitrarily encoded, normalized, or homoglyph-laden argument values
- Unlimited attempts within a session, and multi-turn/multi-step attack construction

**Explicitly NOT assumed:**
- Code execution on the host
- Write access to the repository, the policy files, or the running process
- Ability to modify the interceptor or the audit DB directly
- Compromise of the LLM provider itself
- Physical/insider access

> If any of these are in your real deployment, Praetor is not sufficient — say so.

---

## 4. Attack classes → controls → evidence

| ID | Attack | Control | Invariant | Test evidence |
|----|--------|---------|-----------|---------------|
| T-1 | Path traversal to read outside allowed roots | `canonical_path` + `path_scope` rule | INV-06, INV-08 | Scenario 1 + bypass corpus |
| T-2 | Encoded / double-encoded / unicode traversal | Single-decode with residual rejection, NFKC | INV-06 | Bypass corpus (`..%252f`, homoglyph dots) |
| T-3 | Exfiltration to attacker domain | `domain_allowlist` on canonical host | INV-06 | Scenario 2 |
| T-4 | Allowlist near-miss (`notevil.com`, `evil.com.attacker.net`, punycode) | Label-boundary matching, IDNA | INV-06 | Bypass corpus |
| T-5 | Display-name / bcc / CRLF smuggling in email args | `canonical_email`, all-recipients-must-pass | INV-06 | Bypass corpus |
| T-6 | Privilege escalation via chained tool calls | RBAC scope from bound principal | INV-05 | Scenario 3 |
| T-7 | Agent self-elevation (passing `role`/`session_id` as tool args) | `contextvars` principal binding | INV-05 | `test_INV_05_*` |
| T-8 | Out-of-order action (`send_email` with no draft/approval) | Sequence state machine | INV-13 | Scenario 4 |
| T-9 | Resource exhaustion / rapid-fire calls | Rate + volume anomaly detectors | — | Scenario 5 |
| T-10 | Policy tampering via the agent's own file tools | `policies/` outside every allowed root; load-once + hash pinning | INV-03 | `test_INV_03_*` |
| T-11 | TOCTOU — mutate args after the check | Evaluate-then-freeze, evaluate post-coercion | INV-07 | `test_INV_07_*` |
| T-12 | Crash the firewall to fail open | Global deny-on-exception | INV-01 | Crashing-policy test |
| T-13 | ReDoS via crafted argument against a policy regex | Regex linting + evaluation timeout → DENY | INV-09 | ReDoS pattern test |
| T-14 | Forge the human approval prompt (ANSI/CR injection) | Control-char stripping, truncation, call-ID binding | INV-12 | `test_INV_12_*` |
| T-15 | Approval replay / reuse | Single-use call-ID, timeout defaults to DENY | INV-12 | HITL tests |
| T-16 | Erase or edit audit evidence | SHA-256 hash chain + `verify_chain.py` | INV-10 | Tamper-detection test |
| T-17 | Secret leakage into the audit DB or the repo | Redaction before write; pre-commit + CI secret scanning | INV-11, INV-15 | Planted-key test, gitleaks in CI |
| T-18 | Unguarded execution path (async, batch, retry, direct ref) | Registry-level wrapping + bypass audit test | INV-02 | `test_INV_02_*` (+ documented residual, see §5) |

---

## 5. Non-goals — what Praetor does NOT protect against

State these proactively. A panel that has to extract them will assume you didn't know.

1. **Harmful actions that are within policy.** If policy permits emailing `@corp.com` and the
   attacker steers the agent to email the right domain with the wrong content, Praetor allows
   it. Action-layer enforcement bounds *capability*, not *intent*.
2. **Exfiltration through an allowlisted channel.** Data can leave inside a permitted call.
   Mitigation is narrower policy and content-level DLP — out of scope here.
3. **A developer holding a reference to the undecorated function.** Registry wrapping covers
   the framework's execution paths; it cannot stop code that deliberately reaches around it.
   Production mitigation: ship tools behind a module boundary that only exposes guarded ones.
4. **A compromised or backdoored LLM provider**, or a malicious tool implementation.
5. **Anything outside the wrapped tool surface** — raw shell, direct network from other code,
   filesystem access by non-agent processes. Praetor is a library, not a sandbox or an MMU.
6. **Policy authoring errors.** A wrong rule is a wrong control. Praetor enforces faithfully;
   it does not validate that your policy expresses your intent.
7. **Scale behavior.** Untested beyond ~5 tools and ~25 rules (ADR 0004).
8. **Production hardening of the FastAPI service** — localhost-bound development posture only.

---

## 6. Residual risk register

| ID | Residual risk | Severity | Status | Note |
|----|---------------|----------|--------|------|
| R-1 | Direct reference to undecorated tool function | Medium | Accepted | Documented; production mitigation stated |
| R-2 | Policy correctness is human-dependent | High | Accepted | Inherent to deterministic policy systems |
| R-3 | Bypass corpus is authored by the defenders | Medium | Accepted | Threat to validity; stated in evaluation |
| R-4 | `TODO` — record any bypass the Phase 6 suite fails to block | — | Open | Must be filled honestly before submission |

---

## 7. Assumptions to re-check before submission

- [ ] `policies/` is genuinely outside every tool's allowed root on all three machines
- [ ] No demo or test performs real network I/O (INV-14 fixture active)
- [ ] The audit DB shipped with the repo (if any) contains only synthetic data
- [ ] Every "we block X" claim in the README maps to a passing named test
- [ ] Section 5 is reflected verbatim in the report's Limitations chapter
