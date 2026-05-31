# -*- coding: utf-8 -*-
"""
VSOS Guard Integrations v0.5.3

Framework adapters for seamless integration with popular AI frameworks.
One-line setup, zero code changes required.

Supported:
- LangChain (CallbackHandler)
- OpenAI Python SDK (decorator wrapper)
"""

from vsos_guard.integrations.langchain import LangChainGuard
from vsos_guard.integrations.openai_sdk import OpenAIGuard

__all__ = ["LangChainGuard", "OpenAIGuard"]
