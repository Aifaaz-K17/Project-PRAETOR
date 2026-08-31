---
tags: [literature, report, research]
status: active
location: docs/literature/LITERATURE.md
---

# LITERATURE.md — Praetor Literature Review Index

**Purpose.** One entry per source, with a stable citation ID, an honest summary, and — the
part that matters for the report — **what it covers, what it does not, and how Praetor
relates to it**. Cite these IDs from ADRs (`[[literature]]`), `COMPARISON.md`,
`THREAT_MODEL.md`, and the report.

**How to use it.** Read the tier your chapter needs, not all fifteen. Tier 1 is the prior
art you must be able to discuss under cross-examination. Tier 2 gives you citable
vocabulary for the problem statement. Tier 3 is the text-layer baseline you position
against. Tier 4 is context. Tier 5 is filed for honesty, not for the review.

> **PDFs are not committed** (`docs/literature/pdfs/` is gitignored — published papers are
> copyrighted). Keep shared copies in the team Zotero library and export `references.bib`
> from there. What is committed: this file, `references.bib`, and `notes/<ID>.md`.

---

## Citation index

| ID | Source | Year | Type | Tier | Report chapter |
|----|--------|------|------|------|----------------|
| L-01 | Progent: Programmable Privilege Control for LLM Agents (Shi et al., UC Berkeley / UCSB) | 2025 | Paper | 1 | Lit review, Comparison, Discussion |
| L-02 | CaMeL: Defeating Prompt Injections by Design (Debenedetti et al., Google/DeepMind/ETH) | 2025 | Paper | 1 | Lit review, Comparison |
| L-03 | SoK: The Attack Surface of Agentic AI (Dehghantanha & Homayoun) | 2025 | SoK | 1 | Intro, Threat model, Evaluation metrics |
| L-04 | OWASP Top 10 for LLM Apps & Gen AI — Agentic Security Initiative v1.0 | 2025 | Standard | 2 | Intro, Threat model, Scenario justification |
| L-05 | NIST AI 100-2e2025 — Adversarial ML: Taxonomy and Terminology | 2025 | Standard | 2 | Lit review, Terminology |
| L-06 | MITRE SAFE-AI — A Framework for Securing AI-Enabled Systems (+ ATLAS) | 2025 | Framework | 2 | Threat model, Controls mapping |
| L-07 | Cisco Integrated AI Security and Safety Framework Report | 2025 | Industry | 2 | Intro, Framework-gap argument |
| L-08 | NeMo Guardrails: A Toolkit for Controllable and Safe LLM Applications (NVIDIA) | 2023 | Paper/tool | 3 | Comparison |
| L-09 | Guardrails for LLMs: A Review of Techniques and Challenges (Akheel) | 2025 | Survey | 3 | Lit review, Comparison |
| L-10 | RAG-Guardrails Integration for AI Content Control (More) | 2025 | Paper | 3 | Comparison (brief) |
| L-11 | Mitigating the OWASP Top 10 for LLM Applications using Intelligent Agents (Fasha et al.) | 2024 | Paper | 3 | Lit review (contrast) |
| L-12 | Perceive, Plan, Act, Self-Correct: Architectural Framework for Goal-Directed Agentic AI (Mahdi) | 2026 | Preprint | 4 | Background, System design |
| L-13 | From LLM Reasoning to Autonomous AI Agents: A Comprehensive Review (Ferrag et al., IEEE Access) | 2026 | Survey | 4 | Background, Evaluation framing |
| L-14 | Constitutional AI: Harmlessness from AI Feedback (Bai et al., Anthropic) | 2022 | Paper | 5 | Defence-in-depth framing only |
| L-15 | Claude's Constitution (Anthropic) | 2026 | Doc | 5 | Not a research source — see §6 |

---

## Tier 1 — Closest prior art (know these cold)

### L-01 — Progent: Programmable Privilege Control for LLM Agents

**What it is.** The first dedicated privilege-control mechanism for LLM agents. A
domain-specific language expresses fine-grained constraints over tool calls — when a call is
permitted, and what fallback applies when it is not — enforced deterministically during
agent execution. Policies are generated automatically by an LLM from the user's query and
updated dynamically as the task proceeds. Integration is modular and does not require
changing agent internals.

**Reported results.** Attack success rate on AgentDojo falls from 41.2% to 2.2%, with
utility preserved across AgentDojo, ASB and AgentPoison; the authors also analyse resilience
of automated policy generation under adaptive attack.

**Why it matters to Praetor.** This is your nearest neighbour and the paper the panel is
most likely to have read. You share the core insight — enforce at the tool-call layer,
deterministically, without modifying the agent. **Do not claim the action layer as your
novelty; Progent established it.** Your claim must be about *where policy comes from and
how much trust the LLM holds in the decision path*.

**The honest contrast** (also in `WHY_PRAETOR.pdf`, keep the two consistent):

| | Progent (L-01) | Praetor |
|---|---|---|
| Policy origin | LLM-generated from the user task, updated at runtime | Human-authored YAML, fixed at load |
| Trust in LLM | LLM proposes rules; solver constrains them | Zero — no model in the decision path (INV-04) |
| Adaptivity | Per-task least privilege, dynamically narrowed | Static; unspecified cases fall to DENY / approval |
| Overhead | Additional LLM and solver passes | Local evaluation only |
| Auditability | Policy varies per task | One pinned, hash-verified rule set per decision |

**What Progent does better, and you must say so:** adaptive per-task least privilege
expresses constraints static YAML cannot, and it is evaluated on published benchmarks
against a real attack corpus. Praetor is evaluated on a self-authored corpus. Concede this
in Discussion before the panel raises it.

**What it does not cover** (your openings): tamper-evidence of the decision record;
sequence/state-machine constraints across a session as a first-class rule type; the
canonicalization problem — a policy is only as good as the normalization applied to the
values it matches; and the operational surface (audit trail, live observability, HITL
ergonomics).

---

### L-02 — CaMeL: Defeating Prompt Injections by Design

**What it is.** A protective system layer around the LLM that borrows from classical
software security — control-flow integrity, access control, and information-flow control.
CaMeL extracts control and data flow from the *trusted* user query, so untrusted retrieved
data can never influence program flow. Values carry capability metadata, and security
policies are enforced at tool-call time to prevent exfiltration of private data over
unauthorized flows.

**Reported results.** Solves 77% of AgentDojo tasks with provable security, against 84%
for an undefended system. Released open-source.

**Why it matters.** CaMeL is the strongest *design-level* answer to prompt injection in the
literature and the right citation for "why not just filter the text?" It is also the
strongest argument that a defence should not depend on the model being robust.

**Contrast with Praetor.** CaMeL constrains **information flow** — which values may reach
which sinks — and requires restructuring how the agent executes (a trusted interpreter
around the LLM's plan). Praetor constrains **actions** — which call, with which
canonicalized arguments, in which session state — and is a decorator/registry wrapper with
no change to agent internals. CaMeL is the stronger guarantee; Praetor is the lighter
integration. State that tradeoff plainly: **strength of guarantee versus cost of adoption**
is your positioning, not superiority.

**What it does not cover:** operational tooling (audit chain, dashboard, HITL), and the
utility cost is real (77% vs 84%) — worth citing when you discuss your own false-positive
tradeoff.

---

### L-03 — SoK: The Attack Surface of Agentic AI

**What it is.** A systematization mapping trust boundaries and risks across agentic LLM
systems, synthesizing 2023–2025 evidence from 20+ studies, industry reports and standards.
Taxonomy spans prompt-level injection, knowledge-base poisoning, tool/plug-in exploits, and
multi-agent emergent threats. It defines attacker models and threat scenarios, proposes
evaluation metrics, and assesses defences including input sanitization, retrieval filters,
sandboxes, access control and guardrails — explicitly noting where protection remains
lacking. It also gives a phased deployment checklist (design-time hardening, runtime
monitoring, incident response).

**Why it matters — this is your most useful single source.** Three concrete uses:

1. **Threat model vocabulary.** Its trust-boundary framing maps directly onto `docs/THREAT_MODEL.md` §1. Cite it for TB-1…TB-5 rather than inventing terminology.
2. **Evaluation metrics.** It proposes *Unsafe Action Rate* and *Privilege Escalation Distance*. **Adopt these in Phase 7 alongside your own metrics** — using metrics defined in the literature rather than only self-invented ones materially strengthens the evaluation chapter, and Privilege Escalation Distance is a natural fit for scenario 3.
3. **Gap evidence.** Its finding that protection is still lacking in specific areas is the citable basis for your motivation section — use it rather than asserting the gap yourself.

---

## Tier 2 — Standards and taxonomies (citable framing)

### L-04 — OWASP Agentic Security Initiative: Agentic AI Threats and Mitigations v1.0

Threat taxonomy T1–T15 for agentic systems, including **T2 Tool Misuse**, **T3 Privilege
Compromise**, **T4 Resource Overload**, **T1 Memory Poisoning**, **T8 Repudiation**,
**T13 Rogue Agents**, and **T15 Human-in-the-Loop** concerns. It relates these to the LLM
Top 10 (LLM01 Prompt Injection, LLM06 Excessive Agency, LLM08 Vector and Embedding
Weaknesses, and others). CC BY-SA 4.0.

**Highest-value use: map your five attack scenarios onto OWASP threat IDs.** This converts
"we picked five attacks" into "we cover an externally-defined threat taxonomy", which is a
much better answer to *"why these five?"* Suggested mapping — verify each against the
document before it goes in the report:

| Praetor scenario | OWASP agentic threat | LLM Top 10 |
|---|---|---|
| 1. Path traversal | T2 Tool Misuse | LLM01, LLM06 |
| 2. Data exfiltration | T2 Tool Misuse | LLM01 |
| 3. Privilege escalation via chaining | T3 Privilege Compromise | LLM06 Excessive Agency |
| 4. Sequence/state violation | T3 / T7 Misalignment | LLM06 |
| 5. Volume anomaly | T4 Resource Overload | — |
| Audit hash chain (INV-10) | **T8 Repudiation** | — |
| HITL gate (INV-12) | **T15 Human-in-the-Loop** | — |

The last two rows are worth noticing: T8 and T15 are threats your design addresses that
your five scenarios do not currently test. Consider a sixth scenario for tamper-detection —
it is cheap (`verify_chain.py` already exists in Phase 4) and it closes a taxonomy gap.

### L-05 — NIST AI 100-2e2025: Adversarial Machine Learning Taxonomy

The US federal reference taxonomy for adversarial ML attacks and mitigations. Use it for
**precise, defensible terminology** — say "indirect prompt injection" and "evasion" the way
NIST defines them rather than inventing your own labels. A NIST citation in the terminology
section is inexpensive credibility. Note the scope: it is broad adversarial ML (poisoning,
evasion, privacy), so agentic tool-call abuse is one slice, not the focus.

### L-06 — MITRE SAFE-AI (and ATLAS)

A framework for selecting and assessing security controls for AI-enabled systems, built on
NIST standards and the ATLAS adversarial-threat knowledge base. Emphasizes risk-proportionate
control selection and flags supply-chain and model-provenance risk.

**Use it as the control-mapping frame**: present Praetor's invariants as *security controls
selected in proportion to assessed risk*, rather than as a list of features you happened to
build. That framing is exactly what a security-literate examiner is listening for. ATLAS
technique IDs can also be referenced alongside the OWASP mapping above.

### L-07 — Cisco Integrated AI Security and Safety Framework

An industry lifecycle-aware taxonomy spanning content safety, model/data integrity, runtime
manipulations (prompt injection, tool and agent misuse) and ecosystem risks. **Its central
argument is directly useful to you:** existing frameworks — ATLAS, NIST AI 100-2, the OWASP
Top 10s — each cover only slices of a multi-dimensional space.

Use this as the citable justification for your motivation paragraph: the frameworks
*describe* the risk landscape; they do not supply a runtime enforcement mechanism at the
tool-call boundary. Praetor is an implementation of one control that these taxonomies name
but do not provide.

---

## Tier 3 — Text-layer guardrails (the baseline you position against)

### L-08 — NeMo Guardrails (NVIDIA)

An open-source toolkit adding *programmable* rails to LLM conversational applications, using
a dialogue-management-inspired runtime. Rails are user-defined, independent of the underlying
model, and interpretable — explicitly contrasted with rails embedded into a model at training
time through alignment.

**The comparison to make in `COMPARISON.md`:** you and NeMo share the programmable,
model-independent, interpretable philosophy. You differ in **what is constrained**. NeMo
constrains conversational behaviour — topics, dialogue paths, output style. Praetor
constrains structured tool invocations with canonicalized arguments and session state. Be
precise: NeMo is not a weaker version of Praetor, it is a control at a different layer, and
a real deployment would run both. That is a stronger and more credible claim than "we beat
NeMo."

### L-09 — Guardrails for LLMs: A Review (Akheel)

A multi-layer taxonomy of guardrail approaches covering real-time content filtering,
privacy-preserving techniques, adversarial and jailbreaking strategies, and practices for
robust domain-specific guardrails, synthesizing toolkits including NeMo, Guardrails AI and
Llama Guard, and identifying open questions.

**Best single citation for "the guardrail ecosystem is input/output-focused."** Its
multi-layer taxonomy is the natural place to insert your layer diagram: use its layers as
the x-axis and show that the action layer is thin. Also cite its open-questions section
rather than claiming the gap on your own authority.

### L-10 — RAG-Guardrails Integration for AI Content Control

Combines retrieval-augmented generation with NeMo Guardrails; RAG grounds outputs in trusted
retrieved sources to reduce hallucination, while guardrails enforce domain safety and
compliance policies. Reports a 30–45% reduction in hallucinated content across enterprise
use cases.

**Relevance is limited and mostly by contrast.** Its target failure mode is *hallucination
and unsafe content*, not adversarial tool abuse. One paragraph in the review, used to make
the point that grounding and content policy do not address an attacker who supplies
well-formed instructions the model faithfully follows. Do not overweight it.

### L-11 — Mitigating the OWASP Top 10 for LLM Applications using Intelligent Agents

Proposes a framework using LLM-enabled intelligent agents (AutoGen + RAG) to identify,
assess and counteract OWASP Top 10 threats in real time.

**Use it as the explicit foil for INV-04.** This paper places LLM agents *inside* the
security control loop; Praetor deliberately excludes the model from the decision path. That
is a genuine, citable design disagreement, and articulating it — with the tradeoff stated
fairly (their approach adapts to novel threats; yours cannot be hallucinated or injected) —
is exactly the kind of positioning that earns marks in a literature review. This is the best
"related work I disagree with" entry you have.

---

## Tier 4 — Agent architecture and background

### L-12 — Perceive, Plan, Act, Self-Correct (PPAS)

A four-phase canonical agent loop grounded in classical agent theory (BDI, OODA, SOAR),
with an 8-layer technology stack from foundation models through orchestration, memory, tool
integration, inter-agent protocols, planning, applications and observability, mapping 15+
open-source frameworks onto it. Validated through benchmark meta-analysis, design-pattern
comparison (including Human-in-the-Loop), and inter-agent protocol analysis.

**Use it in System Design.** Name the layer Praetor occupies — between Act and tool
integration — using an existing published architecture rather than only your own diagram.
It also gives you a defensible framing for the AutoGen generalization argument (ADR 0006):
if the loop is canonical across frameworks, an interception point at the Act boundary is
too. Note it is a preprint, not peer-reviewed — say so when citing.

### L-13 — From LLM Reasoning to Autonomous AI Agents (IEEE Access)

A comprehensive review consolidating ~60 benchmarks (2019–2025) across reasoning, maths,
code generation, factual grounding, domain-specific, multimodal/embodied, task orchestration
and interactive assessment, plus frameworks and collaboration protocols.

**Two uses.** In the introduction, as the citation for how fast the agent landscape has
grown. In Phase 7, as a source for *how agentic systems are evaluated in the literature* —
useful for justifying your metric choices and for the threats-to-validity discussion. A
peer-reviewed IEEE venue is a good anchor citation for a student report.

---

## Tier 5 — Filed but out of scope for the review

### L-14 — Constitutional AI (Bai et al., 2022)

Training a harmless assistant through AI feedback against a set of written principles, using
supervised self-critique and revision followed by RL from AI preferences.

**This is a training-time alignment method, not a runtime security control**, so it does not
belong in the action-layer related work. It does earn **one sentence** in your
defence-in-depth argument: alignment shapes what a model is disposed to do, and remains
probabilistic; Praetor constrains what a model is *able* to do, deterministically, and
holds even when alignment fails. That is a clean, correct use of it. Do not stretch it further.

### L-15 — Claude's Constitution (Anthropic, 2026)

Anthropic's specification of intended values and behaviour for its Claude models, written
with the model as primary audience.

**Not a research source and not citable as prior art for this project.** It has no
methodology, no evaluation, and no relationship to tool-call enforcement. If it entered the
folder because it was open in another tab, remove it from `references.bib` — an irrelevant
citation in a literature review reads as padding, and a panel that spots one starts checking
the others. The only legitimate use would be a passing footnote in the ethics chapter about
published behavioural specifications, and even that is optional.

---

## Positioning summary — the defence-layer table

Reproduce this in `COMPARISON.md`. It is the single clearest artefact for the viva.

| Layer | What it inspects | Representative work | Determinism | Praetor's relation |
|-------|------------------|--------------------|-------------|--------------------|
| Training / alignment | Model dispositions | L-14 | Probabilistic | Complementary; assumed to fail |
| Input text | Prompts before the model | L-08, L-09 | Probabilistic | Complementary; upstream |
| Retrieval grounding | Retrieved context | L-10 | Probabilistic | Complementary; different failure mode |
| Output text | Generated responses | L-08, L-09 | Probabilistic | Complementary; downstream |
| Data / information flow | Value provenance to sinks | L-02 | Provable, by design | Stronger guarantee, heavier integration |
| **Action / tool call** | **Structured call + arguments + state** | **L-01, Praetor** | **Deterministic** | **Our layer** |
| Governance / framework | Control selection, risk | L-04, L-05, L-06, L-07 | N/A | Describes the control we implement |

---

## Novelty statement — grounded, bounded, defensible

Write it in this shape, and never broader than this:

> The action-layer enforcement concept is established prior art (Progent, L-01), and
> flow-level defences offer stronger formal guarantees at higher integration cost (CaMeL,
> L-02). Praetor's contribution is not the layer but the **trust and operational model at
> that layer**: (i) *zero-LLM-trust* — no model participates in the decision path, so policy
> cannot be hallucinated or influenced by injection, in deliberate contrast to LLM-generated
> policy (L-01) and LLM-agent-based mitigation (L-11); (ii) *session-level sequence and state
> constraints* as a first-class rule type, complementing argument-level narrowing;
> (iii) *canonicalization-before-matching* as an explicit, separately-evaluated layer,
> addressing parser-differential bypass, which the surveyed literature does not treat as a
> distinct enforcement concern; and (iv) *tamper-evident auditability* via a hash-chained
> decision record, addressing OWASP T8 Repudiation (L-04). We claim these for a
> single-agent, ~5-tool, LangChain deployment evaluated on a self-authored corpus; we do not
> claim benchmark parity with L-01 or the formal guarantees of L-02.

Three sentences of what you did, one of what you did not. That last clause is what makes
the rest believable.

---

## Coverage gaps — what this folder is missing

Honest assessment, so week 11 holds no surprises.

1. **No benchmark paper.** AgentDojo is the benchmark both L-01 and L-02 report against, and
   you have neither its paper nor its dataset. Either obtain it and discuss why you did not
   run against it (time, scope — a legitimate answer), or expect the question cold.
2. **No InjecAgent.** Your week-3 plan schedules reading it for the attack taxonomy, and it
   is not here. Get it — it is the standard source for indirect-injection attack structure.
3. **No Greshake et al.** on indirect prompt injection — the origin citation for your core
   threat, referenced by L-02. Your introduction should cite the primary source.
4. **No Rebuff or LLM Guard primary sources**, though your `COMPARISON.md` promises to
   compare against them. Either obtain them or drop them and compare only against L-08 and
   L-09, which you do have.
5. **Willison's "lethal trifecta"** is in your week-2 plan and absent here — short, widely
   cited, and the crispest one-paragraph framing of the risk for your introduction.
6. **Nothing on path canonicalization or parser-differential bypass**, which is your
   distinctive technical contribution. Look to the traditional appsec literature (OWASP path
   traversal guidance, unicode normalization and IDN homograph work) rather than the LLM
   literature. Grounding INV-06 in established appsec is a strength: it shows you are
   applying known security engineering to a new layer, not improvising.

Gaps 1–3 are the ones that would actually cost marks. Gap 6 is the one that would most
improve the report.

---

## Per-source note template — `docs/literature/notes/L-XX.md`

```markdown
---
tags: [literature]
id: L-XX
status: read | skimmed | queued
---
# L-XX — <Short title>
**Full citation:** <authors, title, venue, year>  ·  **BibTeX key:** <key>

## Claim
<one or two sentences, in your own words>

## Method
<how they evaluated it, and on what>

## Relevant to
- [[praetor]] — <which invariant, ADR, or chapter this informs>

## What it does NOT cover
<the gap — this is the sentence you will reuse in the report>

## Quotable facts (paraphrase, with page/section)
- <fact> (§X)

## Where cited
Report §<n>; `COMPARISON.md`; ADR <number>
```

**Write the note while reading, not later.** A note written from memory in week 11 is worth
less than three written in week 3, and only these notes — not the PDFs — go into the repo.
