---
tags: [architecture, security, concept]
status: active
---

# Action Firewall

A deterministic proxy/middleware security layer that sits between an LLM agent's decision to call a tool and the actual execution of that tool call.

## Depends on
- [[interception-layer]] — Invokes policy evaluation prior to tool execution.
- [[policy-engine]] — Evaluates tool parameters against explicit rules.

## Used by
- [[demo-agent]] — Standard defensive wrapper around LLM tools.

## Key decisions
- [[0003-policy-engine-deployment-mode]]
- [[0006-agent-framework-choice]]
