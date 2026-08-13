---
tags: [decision, scope, demo-agent]
status: accepted
date: 2026-08-09
---

# 0004 — Action/Tool Scale Scope

## Status
Accepted.

## Context
The demo agent could be built against anywhere from a handful of simple tools to 50+ dynamic tool schemas resembling a production enterprise agent. Tool count affects mocking work, policy set size, and demo clarity.

## Decision
Keep the demo agent at approximately 5 mocked tools (`read_file`, `send_email`, `search_web`, `transfer_funds`). Design the [[policy-engine]]'s YAML schema so tool identity is a lookup key (not hardcoded branching logic).

## Consequences
**Positive:**
- Matches time budget and project scope
- Keeps attack scenarios and evaluation harness easy to reason about and demo live
- Generic key-based schema generalizes defensibly

## Related
- [[demo-agent]]
- [[policy-engine]]
