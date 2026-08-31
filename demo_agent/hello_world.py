"""Demo Agent Hello World Smoke Test.

Proves two things about the environment, both required before any firewall
code can be trusted (Phase 0 step 0f):

1. A LangChain `@tool`-decorated callable can be defined and invoked
   directly.
2. A full "LLM decides to call a tool -> tool executes" round trip works
   end-to-end using `GenericFakeChatModel` — a LangChain chat model that
   returns pre-scripted messages instead of calling a real provider. No API
   key is read, set, or required anywhere in this module, and no network
   call is made (INV-14). A real key stays optional and is only ever used
   in interactive demos outside the test suite.
"""

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.tools import tool


@tool
def echo_tool(message: str) -> str:
    """Echoes back the input message (mocked tool)."""
    return f"Echo: {message}"


def run_hello_world() -> str:
    """Invoke echo_tool directly, with no LLM involved at all."""
    print("Executing hello world tool smoke test (direct invocation)...")
    result = echo_tool.invoke({"message": "Hello from LangChain Agent!"})
    print(f"Tool Result: {result}")
    return result


def run_hello_world_via_mock_llm() -> str:
    """Invoke echo_tool via a scripted fake LLM that decides to call it.

    This is the shape every later phase depends on: the interceptor sits
    between "the model produced a tool call" and "the tool executes". This
    function proves that shape works before any firewall code exists.
    """
    print("Executing hello world tool smoke test (via mock LLM)...")

    # The fake model ignores its actual input and just returns the next
    # message from this pre-scripted list, in order. Here that's a single
    # AIMessage carrying a tool call, exactly like a real model would
    # return when it decides to invoke a tool.
    scripted_reply = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "echo_tool",
                "args": {"message": "Hello from a mocked LLM!"},
                "id": "call_hello_world_1",
                "type": "tool_call",
            }
        ],
    )
    fake_llm = GenericFakeChatModel(messages=iter([scripted_reply]))

    conversation: list[BaseMessage] = [
        HumanMessage(content="Please echo a greeting using the echo tool.")
    ]
    ai_response = fake_llm.invoke(conversation)

    if not ai_response.tool_calls:
        raise RuntimeError(
            "Mock LLM did not produce a tool call — smoke test setup is broken."
        )

    tool_call = ai_response.tool_calls[0]
    print(f"Mock LLM requested tool call: {tool_call['name']}({tool_call['args']})")

    # This is the exact point Phase 1's interceptor will sit at: between the
    # model's decision (tool_call) and the tool actually executing.
    result = echo_tool.invoke(tool_call["args"])
    print(f"Tool Result: {result}")
    return result


if __name__ == "__main__":
    run_hello_world()
    run_hello_world_via_mock_llm()
