"""
Demo Agent Hello World Smoke Test.
Demonstrates defining and invoking a mocked LangChain tool.
"""

from langchain_core.tools import tool


@tool
def echo_tool(message: str) -> str:
    """Echoes back the input message (Mocked Tool)."""
    return f"Echo: {message}"


def run_hello_world():
    print("Executing hello world tool smoke test...")
    result = echo_tool.invoke({"message": "Hello from LangChain Agent!"})
    print(f"Tool Result: {result}")
    return result


if __name__ == "__main__":
    run_hello_world()
