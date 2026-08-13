---
tags: [architecture, interception, langchain]
status: active
---

# Interception Layer

The proxy/decorator layer (`@firewall_guard`) wrapping LangChain tool functions (`Tool.func` or `@tool`). Intercepts call parameters, captures call metadata (agent ID, session ID, timestamp), passes evaluation requests to the policy engine, and enforces ALLOW/DENY decisions.

## Depends on
- [[action-firewall]] — Conceptual blueprint.

## Used by
- [[policy-engine]] — Passes parameters to policy engine for evaluation.

## Key decisions
- [[0006-agent-framework-choice]]
