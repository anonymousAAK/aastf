"""
Claude + LangGraph agent factories for AASTF benchmark.
Uses ChatAnthropic inside create_react_agent.
"""

from __future__ import annotations


def create_claude_opus(tools: list):
    """Claude Opus 4.6 via LangGraph ReAct agent."""
    from langchain_anthropic import ChatAnthropic
    from langgraph.prebuilt import create_react_agent
    llm = ChatAnthropic(model="claude-opus-4-6", temperature=0, max_tokens=2048)
    return create_react_agent(llm, tools)


def create_claude_sonnet(tools: list):
    """Claude Sonnet 4.6 via LangGraph ReAct agent."""
    from langchain_anthropic import ChatAnthropic
    from langgraph.prebuilt import create_react_agent
    llm = ChatAnthropic(model="claude-sonnet-4-6", temperature=0, max_tokens=2048)
    return create_react_agent(llm, tools)


def create_claude_haiku(tools: list):
    """Claude Haiku 4.5 via LangGraph ReAct agent — fastest and cheapest."""
    from langchain_anthropic import ChatAnthropic
    from langgraph.prebuilt import create_react_agent
    llm = ChatAnthropic(model="claude-haiku-4-5-20251001", temperature=0, max_tokens=2048)
    return create_react_agent(llm, tools)
