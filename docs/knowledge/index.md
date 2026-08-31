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
- [[session-state-and-audit-trail]] — Per-session call history (`SessionStore`) and the hash-chained, redacted audit log (`AuditLogger`).
- [[anomaly-detection]] — Second deterministic layer catching multi-call attack shapes a single-call policy rule can't see.
- [[hitl-approval]] — Blocking, out-of-band terminal approval for NEEDS_APPROVAL decisions (INV-12).

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
- [[0012-rbac-composition-with-allowlist-rules]] — real RBAC-bypass bug found via testing: unconditional path_scope/domain_allowlist ALLOW votes were outvoting rbac restrictions on the same tool; fixed with an opt-in `roles` field.
- [[0013-rule-based-anomaly-detection]] — four pure-function detectors (call volume, tool-outside-declared-set, high-risk sequence, argument entropy) folded into a policy Decision; opt-in, requires a `session_store`.
- [[0014-phase4-security-review-findings]] — pre-Phase-5 review pass: a numeric-string type-confusion bypass in parameter_bounds min/max, two more instances of ADR 0012's RBAC-composition bug, and the structural guard test ADR 0012 named as a follow-up, now built.
- [[0015-hitl-resolution-mechanics]] — HitlResolver as a Protocol on interceptor.py (avoids a circular import), reader-thread+queue timeout for cross-platform blocking approval, and why the HITL outcome is a second audit row rather than an edit to the first.

---

## Project Audit Log

- [[CHANGELOG]] — Sequential log of project milestones, architectural commits, and code changes.
