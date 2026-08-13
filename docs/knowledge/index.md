---
tags: [index, knowledge-base, map-of-content]
---

# Knowledge Vault — AI Agent Action Firewall

Welcome to the living architecture and knowledge vault for the **Deterministic Action Firewall for AI Agents**.

---

## Core Concepts

- [[action-firewall]] — Conceptual foundation of action-layer deterministic interception vs input/output text filtering.
- [[interception-layer]] — Technical mechanics of intercepting LangChain tool calls before execution.
- [[policy-engine]] — Policy schema specification, evaluator, parameter bounds, RBAC, and state sequence enforcement.

---

## Architectural Decision Records (ADRs)

- [[0003-policy-engine-deployment-mode]] — Choice of in-process library vs OPA sidecar.
- [[0004-tool-scale-scope]] — Scope decision for 5 mocked tools in demo agent.
- [[0005-hitl-approval-mechanism]] — Terminal CLI prompt vs Slack/webhook approval mechanism.
- [[0006-agent-framework-choice]] — LangChain primary target vs AutoGen extension.

---

## Project Audit Log

- [[CHANGELOG]] — Sequential log of project milestones, architectural commits, and code changes.
