# -*- coding: utf-8 -*-
"""
VSOS Guard LangChain Integration v0.5.3

One-line security guard for LangChain agents.

Usage:
    from vsos_guard.integrations import LangChainGuard

    guard = LangChainGuard(mode="standard")
    agent = AgentExecutor(
        agent=agent,
        tools=tools,
        callbacks=[guard.callback()],
    )

Or with automatic blocking:
    guard = LangChainGuard(mode="standard", auto_block=True)
    # When attack detected, agent execution is stopped automatically

Supports:
- Agent input interception (on_agent_action)
- Tool call interception (on_tool_start)
- LLM input interception (on_llm_start)
- Automatic execution blocking on detection
"""

from typing import Optional, Any, Dict, List
from vsos_guard.guard import VSOSGuard, CheckResult


class _LangChainCallbackHandler:
    """
    LangChain BaseCallbackHandler adapter for VSOS Guard.

    Intercepts agent inputs and tool calls, runs security checks,
    and optionally blocks execution on attack detection.
    """

    def __init__(self, guard: VSOSGuard, auto_block: bool = True):
        self._guard = guard
        self._auto_block = auto_block
        self._last_result: Optional[CheckResult] = None
        self._block_count: int = 0
        self._warn_count: int = 0

    @property
    def last_result(self) -> Optional[CheckResult]:
        """Return the last check result."""
        return self._last_result

    @property
    def block_count(self) -> int:
        """Return the number of blocked inputs."""
        return self._block_count

    @property
    def warn_count(self) -> int:
        """Return the number of warnings."""
        return self._warn_count

    def _check_and_handle(self, text: str) -> CheckResult:
        """Run security check and handle the result."""
        result = self._guard.check(text)
        self._last_result = result

        if result.is_blocked():
            self._block_count += 1
        elif result.is_warning():
            self._warn_count += 1

        return result

    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs) -> Optional[bool]:
        """Intercept LLM input before sending to the model."""
        if not prompts:
            return None

        for prompt in prompts:
            result = self._check_and_handle(prompt)
            if result.is_blocked() and self._auto_block:
                return False  # Signal to abort

        return None

    def on_agent_action(self, action: Any, **kwargs) -> Optional[bool]:
        """Intercept agent action input before execution."""
        input_text = ""
        if hasattr(action, "log"):
            input_text = action.log or ""
        if hasattr(action, "tool_input"):
            tool_input = action.tool_input
            if isinstance(tool_input, str):
                input_text = tool_input
            elif isinstance(tool_input, dict):
                input_text = str(tool_input)

        if not input_text:
            return None

        result = self._check_and_handle(input_text)
        if result.is_blocked() and self._auto_block:
            return False  # Signal to abort

        return None

    def on_tool_start(self, serialized: Dict[str, Any], input_str: Any, **kwargs) -> Optional[bool]:
        """Intercept tool call input before execution."""
        text = input_str if isinstance(input_str, str) else str(input_str)

        if not text:
            return None

        result = self._check_and_handle(text)
        if result.is_blocked() and self._auto_block:
            return False  # Signal to abort

        return None

    def on_chain_start(self, serialized: Dict[str, Any], inputs: Dict[str, Any], **kwargs) -> Optional[bool]:
        """Intercept chain input before execution."""
        if not inputs:
            return None

        # Check the most common input fields
        text_to_check = []
        for key in ("input", "question", "query", "human_input", "user_input"):
            if key in inputs and isinstance(inputs[key], str):
                text_to_check.append(inputs[key])

        if "messages" in inputs:
            messages = inputs["messages"]
            if isinstance(messages, list):
                for msg in messages:
                    if hasattr(msg, "content"):
                        text_to_check.append(msg.content)
                    elif isinstance(msg, dict) and "content" in msg:
                        text_to_check.append(msg["content"])

        for text in text_to_check:
            result = self._check_and_handle(text)
            if result.is_blocked() and self._auto_block:
                return False

        return None

    def get_stats(self) -> Dict[str, Any]:
        """Return security check statistics."""
        return {
            "blocks": self._block_count,
            "warnings": self._warn_count,
            "last_result": self._last_result.to_dict() if self._last_result else None,
        }


class LangChainGuard:
    """
    VSOS Guard wrapper for LangChain integration.

    Usage:
        guard = LangChainGuard(mode="standard")
        callbacks = [guard.callback()]
        agent = AgentExecutor(agent=agent, tools=tools, callbacks=callbacks)

    Args:
        mode: Guard mode - "relaxed", "standard", or "strict"
        auto_block: If True, block agent execution on attack detection
        policy_file: Optional YAML policy file path
        log_file: Optional log file path
        on_block: Optional callback when input is blocked
        on_warn: Optional callback when warning is raised
    """

    def __init__(
        self,
        mode: str = "standard",
        auto_block: bool = True,
        policy_file: Optional[str] = None,
        log_file: Optional[str] = None,
        on_block: Optional[Any] = None,
        on_warn: Optional[Any] = None,
    ):
        self._guard = VSOSGuard(
            mode=mode,
            policy_file=policy_file,
            log_file=log_file,
            on_block=on_block,
            on_warn=on_warn,
        )
        self._auto_block = auto_block
        self._handler = _LangChainCallbackHandler(self._guard, auto_block)

    def callback(self) -> _LangChainCallbackHandler:
        """Return the LangChain callback handler."""
        return self._handler

    def check(self, text: str) -> CheckResult:
        """Direct security check (bypass LangChain, use guard directly)."""
        return self._guard.check(text)

    def get_stats(self) -> Dict[str, Any]:
        """Return security check statistics."""
        return self._handler.get_stats()

    @property
    def guard(self) -> VSOSGuard:
        """Access the underlying VSOSGuard instance."""
        return self._guard
