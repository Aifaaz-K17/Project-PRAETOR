---
tags: [decision, architecture, policy-engine]
status: accepted
date: 2026-08-09
---

# 0003 — Policy Engine Deployment Mode

## Status
Accepted (primary path). OPA sidecar noted as stretch goal, not committed.

## Context
The policy engine that evaluates intercepted tool calls could run in one of three modes:
1. **In-process library** — policy evaluation happens as a plain function call inside the same Python process as the agent/interceptor
2. **Sidecar / local REST service** — a separate process (e.g. Open Policy Agent, OPA) running alongside the agent, queried over localhost HTTP
3. **Centralized policy server** — a shared remote service evaluating policies for multiple agents/services across a network

## Decision
Build a lightweight, custom in-process Python policy evaluator that reads YAML policy files (see [[policy-engine]]). This runs in the same process as the [[interception-layer]], with no network hop.

## Consequences
**Positive:**
- No new infrastructure to learn or run
- Zero added network latency or failure surface for the evaluation call
- Easier to debug for a beginner team — one process, one stack trace
- Simple to demo reliably in a live viva

**Negative / tradeoffs:**
- Doesn't demonstrate familiarity with production policy tooling (OPA/Rego) unless stretch goal added
- Less realistic for multi-agent microservices deployment

## Related
- [[policy-engine]]
- [[interception-layer]]
