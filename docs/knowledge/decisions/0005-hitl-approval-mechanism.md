---
tags: [decision, hitl, dashboard, policy-engine]
status: accepted
date: 2026-08-09
---

# 0005 — Human-in-the-Loop (HITL) Approval Mechanism

## Status
Accepted (primary path). Dashboard-button approval noted as stretch goal.

## Context
The [[policy-engine]] returns ALLOW / DENY / NEEDS_APPROVAL per call. For NEEDS_APPROVAL, the system needs a mechanism for a human to approve or deny before the tool executes. Options range from Slack/webhook integration to a simple terminal prompt.

## Decision
Primary mechanism: when a call is flagged NEEDS_APPROVAL, the system queues it and blocks execution until a terminal/CLI prompt (`y/n`) is answered. No external service required.

Stretch goal: add an "Approve/Deny" button inside the [[dashboard]] (Streamlit).

## Consequences
**Positive:**
- Zero external dependencies — nothing that can fail during a live demo
- Fast to implement, easy to reason about and test
- Still demonstrates the core HITL concept

**Negative / tradeoffs:**
- Terminal-based approval isn't representative of production UX
- Doesn't demonstrate integration with real notification tooling (Slack, PagerDuty)

## Related
- [[policy-engine]]
- [[dashboard]]
- [[interception-layer]]
