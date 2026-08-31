# Praetor

**A deterministic action firewall for LLM agents.**

[![CI](https://github.com/<org>/praetor/actions/workflows/ci.yml/badge.svg)](...)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](...)

LLM agents with tool access are vulnerable to indirect prompt injection: instructions
hidden in fetched content can steer an agent into calling tools in harmful ways. Text
filters try to catch the malicious *input*; Praetor checks the resulting *action*.

Every tool call is intercepted, its arguments canonicalized, and the call evaluated
against static human-authored policy before execution — fail-closed, with no language
model anywhere in the decision path.

> ⚠️ Research project, not production software. All tools are mocked and all attack
> scenarios run against a local sandbox. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
> for what Praetor does **not** protect against.
