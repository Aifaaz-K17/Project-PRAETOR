"""
Phase 0 Verification & Scaffold Test Suite.
Validates environment installation, package imports, and LangChain tool instantiation.
"""

import firewall
from demo_agent.hello_world import (
    echo_tool,
    run_hello_world,
    run_hello_world_via_mock_llm,
)


def test_firewall_package_import():
    """Verify core firewall package imports cleanly."""
    assert firewall.__version__ == "0.1.0"


def test_langchain_tool_instantiation():
    """Verify LangChain tool definitions and invocations work."""
    result = echo_tool.invoke({"message": "scaffold_test"})
    assert result == "Echo: scaffold_test"


def test_hello_world_execution():
    """Verify demo agent hello world function (direct tool invocation)."""
    res = run_hello_world()
    assert "Hello from LangChain Agent!" in res


def test_hello_world_via_mock_llm_requires_no_api_key():
    """Verify the full mock-LLM -> tool-call -> execution round trip works
    with zero API keys and zero network access (INV-14, Phase 0 step 0f)."""
    res = run_hello_world_via_mock_llm()
    assert res == "Echo: Hello from a mocked LLM!"
