---
tags: [decision, framework, langchain]
status: accepted
date: 2026-08-09
---

# 0006 — Agent Orchestration Framework Choice

## Status
Accepted.

## Context
Several frameworks orchestrate LLM agent tool-calling: LangChain, LlamaIndex, AutoGen, or a custom Python loop. The choice affects how the [[interception-layer]] hooks into tool execution, documentation availability, and literature review framing.

## Decision
Build primarily against **LangChain**. Optionally add one small **AutoGen** demo late in the timeline to show the interception design generalizes across frameworks.

## Consequences
**Positive:**
- Largest community and tutorial base — critical for a beginner team
- LangChain's `Tool` object has a simple, single function-call wrapping point that maps directly onto a `@firewall_guard` decorator
- Most existing academic writing on LLM agent security uses LangChain examples
- A later small AutoGen demo earns a genuine "generalizes across frameworks" claim cheaply

**Negative / tradeoffs:**
- LlamaIndex and custom-loop approaches aren't demonstrated
- LangChain version pinning needed to avoid breaking internal API changes

## Related
- [[interception-layer]]
- [[demo-agent]]
