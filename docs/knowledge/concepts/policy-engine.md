---
tags: [architecture, policy, rule-engine]
status: active
---

# Policy Engine

In-process YAML-driven policy evaluator that parses policy rules and evaluates tool parameters, RBAC scopes, domain allowlists, and call sequences.

## Depends on
- [[interception-layer]] — Receives tool calls from the wrapper.

## Used by
- [[action-firewall]] — Primary decision engine.

## Key decisions
- [[0003-policy-engine-deployment-mode]]
- [[0004-tool-scale-scope]]
- [[0005-hitl-approval-mechanism]]
