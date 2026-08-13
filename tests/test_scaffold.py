"""
Phase 0 Verification & Scaffold Test Suite.
Validates environment installation, package imports, and LangChain tool instantiation.
"""

import firewall
from demo_agent.hello_world import echo_tool, run_hello_world


def test_firewall_package_import():
    """Verify core firewall package imports cleanly."""
    assert firewall.__version__ == "0.1.0"


def test_langchain_tool_instantiation():
    """Verify LangChain tool definitions and invocations work."""
    result = echo_tool.invoke({"message": "scaffold_test"})
    assert result == "Echo: scaffold_test"


def test_hello_world_execution():
    """Verify demo agent hello world function."""
    res = run_hello_world()
    assert "Hello from LangChain Agent!" in res
