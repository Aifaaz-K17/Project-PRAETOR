---
tags: [index, knowledge-base, map-of-content]
---

# Knowledge Vault — AI Agent Action Firewall

Welcome to the living architecture and knowledge vault for the **Deterministic Action Firewall for AI Agents**.

---

## Core Concepts

- [[action-firewall]] — Conceptual foundation of action-layer deterministic interception vs input/output text filtering.
- [[interception-layer]] — Technical mechanics of intercepting LangChain tool calls before execution.
- [[canonicalization]] — Normalizing paths/hosts/emails/text before policy evaluation (INV-06).
- [[policy-engine]] — Policy schema specification, evaluator, parameter bounds, RBAC, and state sequence enforcement.

---

## Architectural Decision Records (ADRs)

- [[0003-policy-engine-deployment-mode]] — Choice of in-process library vs OPA sidecar.
- [[0004-tool-scale-scope]] — Scope decision for 5 mocked tools in demo agent.
- [[0005-hitl-approval-mechanism]] — Terminal CLI prompt vs Slack/webhook approval mechanism.
- [[0006-agent-framework-choice]] — LangChain primary target vs AutoGen extension.
- [[0007-interceptor-enforcement-point]] — Wrap-at-registration as the enforcement point; call-normalization contract; fail-closed/TOCTOU-safe chokepoint.
- [[0008-canonicalization-before-matching]] — Real filesystem/IDNA resolution over string matching; single percent-decode; label-boundary domain matching; strip vs. reject policy.
- [[0009-policy-conflict-resolution]] — DENY > NEEDS_APPROVAL > ALLOW > default; why gate-shaped rules must be action: deny.
- [[0010-policy-integrity-and-loading]] — Load-once SHA-256 hashing, frozen structures, ReDoS static linting + runtime timeout (verified against a real hanging pattern).
- [[0011-unknown-parameter-enforcement]] — parameter_schema rule type closing the "unknown parameter → DENY" gap in INV-08; opt-in per tool, and why.

---

## Project Audit Log

- [[CHANGELOG]] — Sequential log of project milestones, architectural commits, and code changes.
