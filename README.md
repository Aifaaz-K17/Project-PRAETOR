# Praetor

**A deterministic action firewall for LLM agents.**

[![CI](https://github.com/Aifaaz-K17/Project-PRAETOR/actions/workflows/ci.yml/badge.svg)](https://github.com/Aifaaz-K17/Project-PRAETOR/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.14](https://img.shields.io/badge/python-3.14-blue.svg)](https://www.python.org/)

LLM agents with tool access are vulnerable to indirect prompt injection: instructions
hidden in fetched content can steer an agent into calling tools in harmful ways. Text
filters try to catch the malicious *input*; Praetor checks the resulting *action*.

Every tool call is intercepted, its arguments canonicalized, and the call evaluated
against static human-authored policy before execution — fail-closed, with no language
model anywhere in the decision path.

> ⚠️ **Research project, not production software.** This is a final-year university
> project. All tools are mocked and all attack scenarios run against a local sandbox
> (`sandbox/`) — no real-world targets or unauthorized external systems are ever
> accessed. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for what Praetor does
> **not** protect against.

---

## Architecture Overview

```mermaid
graph TD
    User([User / External System]) --> Agent[LLM Agent - LangChain]
    Agent -->|Tool Call Request| Interceptor[Firewall Guard / Interception Layer]
    Interceptor -->|Evaluate Call| PolicyEngine[Policy Engine YAML Rules]
    PolicyEngine -->|Decision: ALLOW / DENY / NEEDS_APPROVAL| Interceptor
    Interceptor -->|Audit Log| Logger[(SQLite Audit Trail)]
    Interceptor -->|If ALLOWED| MockTools[Mock Tool Execution]
    Interceptor -->|If DENIED / NEEDS_APPROVAL| BlockHandler[Block / HITL Escalation]
```

---

## Directory Structure

```
/
├── firewall/             # Core firewall interception & policy engine library
├── policies/              # YAML policy definition files
├── demo_agent/            # Sample LangChain agent & mock tool definitions
├── dashboard/             # Streamlit audit & monitoring dashboard
├── tests/                 # Test suite (pytest) & evaluation harness
├── docs/                  # Project documentation & Knowledge Base Vault
├── scripts/               # Operational scripts (safe_push, verify_chain, ...)
├── sandbox/               # Fixture filesystem for file-tool tests
├── PROGRESS.md            # Phase status and execution notes
├── LIMITATIONS.md         # Honest register of known gaps and shortcuts
├── requirements.txt       # Project dependencies (exact-pinned)
└── README.md              # Project overview
```

---

## Quickstart Setup

1. **Clone the repository and enter the directory**:
   ```bash
   git clone https://github.com/Aifaaz-K17/Project-PRAETOR.git
   cd Project-PRAETOR
   ```

2. **Set up a virtual environment**:
   ```bash
   python -m venv venv
   # On Windows PowerShell:
   .\venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies** (runtime + dev tooling):
   ```bash
   pip install -r requirements.txt -r requirements-dev.txt
   ```

4. **Install the gitleaks binary** (needed once, for the local pre-commit
   secret-scan hook — CI runs its own copy separately and needs nothing
   installed locally):
   - Download the `v8.30.1` release for your OS from
     https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1
   - Extract `gitleaks` (or `gitleaks.exe` on Windows) and put it on your `PATH`.
   - Verify: `gitleaks version` should print `8.30.1`.

5. **Install the git hooks** (run once per clone):
   ```bash
   pre-commit install
   ```

6. **Run the test suite**:
   ```bash
   pytest -v
   ```

7. **Run the full local CI gate** (what `.github/workflows/ci.yml` runs):
   ```bash
   ruff check .
   black --check .
   mypy firewall/
   pytest -v
   pip-audit -r requirements.txt
   bandit -r firewall/
   ```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
