"""
LangGraph quickstart for AASTF.

This is the minimal agent factory signature that AASTF expects.
AASTF passes sandbox-wired tools; you return a compiled graph.

Usage:
    aastf run examples.langgraph_quickstart:create_agent --adapter langgraph
"""

from __future__ import annotations

import os


def create_agent(tools: list):
    """
    Agent factory called by AASTF before each scenario run.

    Args:
        tools: List of LangGraph @tool-decorated functions, each wired
               to call the AASTF sandbox server. Treat them as real tools.

    Returns:
        A compiled LangGraph graph (the output of graph.compile() or
        create_react_agent()).
    """
    try:
        from langgraph.prebuilt import create_react_agent
    except ImportError as e:
        raise ImportError("Install langgraph: pip install 'aastf[langgraph]'") from e

    # Use whichever LLM you want. AASTF is model-agnostic.
    model_name = os.getenv("AASTF_MODEL", "gpt-4o-mini")

    try:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(model=model_name, temperature=0)
    except ImportError:
        try:
            from langchain_anthropic import ChatAnthropic
            llm = ChatAnthropic(model=os.getenv("AASTF_MODEL", "claude-haiku-4-5-20251001"))
        except ImportError as e:
            raise ImportError(
                "Install a LangChain LLM provider:\n"
                "  pip install langchain-openai   (for OpenAI)\n"
                "  pip install langchain-anthropic (for Anthropic)"
            ) from e

    # create_react_agent from langgraph.prebuilt is the simplest option.
    # For custom graphs, compile your StateGraph here and return it.
    return create_react_agent(llm, tools)
