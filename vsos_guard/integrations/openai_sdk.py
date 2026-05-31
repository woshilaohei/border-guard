# -*- coding: utf-8 -*-
"""
VSOS Guard OpenAI SDK Integration v0.5.3

Security wrapper for OpenAI Python SDK.

Usage (Decorator mode):
    from vsos_guard.integrations import OpenAIGuard

    guard = OpenAIGuard(mode="standard")
    response = guard.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}],
    )

Usage (Guard mode - check before send):
    guard = OpenAIGuard(mode="standard")
    messages = [{"role": "user", "content": user_input}]
    result = guard.check_messages(messages)
    if result.is_blocked():
        print(f"Blocked: {result.reason}")
    else:
        response = openai.ChatCompletion.create(...)

Supports:
- Message-level input interception
- Streaming mode detection
- Output safety check (ASI02)
"""

from typing import Optional, Any, Dict, List, Union
from vsos_guard.guard import VSOSGuard, CheckResult


class _ChatCompletionsProxy:
    """Proxy for openai.resources.chat.completions with security checks."""

    def __init__(self, guard_instance: "OpenAIGuard", client: Any = None):
        self._guard_instance = guard_instance
        self._client = client

    def create(self, **kwargs) -> Any:
        """
        Intercept ChatCompletion.create() call with security checks.

        Checks all user messages before forwarding to OpenAI.
        If attack detected and auto_block=True, raises ValueError.
        """
        messages = kwargs.get("messages", [])

        # Check each user message
        for msg in messages:
            if isinstance(msg, dict) and msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, list):
                    # Multi-modal content
                    for part in content:
                        if isinstance(part, dict) and part.get("type") == "text":
                            result = self._guard_instance._guard.check(part["text"])
                            if result.is_blocked() and self._guard_instance._auto_block:
                                raise ValueError(
                                    f"VSOS Guard: Input blocked - {result.reason}"
                                )
                elif isinstance(content, str):
                    result = self._guard_instance._guard.check(content)
                    if result.is_blocked() and self._guard_instance._auto_block:
                        raise ValueError(
                            f"VSOS Guard: Input blocked - {result.reason}"
                        )

        # If we have a real client, forward the call
        if self._client is not None:
            response = self._client.chat.completions.create(**kwargs)

            # Check output if enabled
            if self._guard_instance._check_output and response:
                self._guard_instance._check_response_output(response)

            return response

        # No client - return the check result for manual handling
        return CheckResult(safe=True, confidence="safe")


class _ChatProxy:
    """Proxy for openai.resources.chat with security checks."""

    def __init__(self, guard_instance: "OpenAIGuard", client: Any = None):
        self._guard_instance = guard_instance
        self._client = client
        self.completions = _ChatCompletionsProxy(guard_instance, client)


class OpenAIGuard:
    """
    VSOS Guard wrapper for OpenAI Python SDK.

    Usage (Standalone - check messages before sending):
        guard = OpenAIGuard(mode="standard")
        result = guard.check_messages(messages)
        if not result.is_blocked():
            response = openai.ChatCompletion.create(...)

    Usage (With OpenAI client - auto-intercept):
        import openai
        client = openai.OpenAI(api_key="...")
        guard = OpenAIGuard(mode="standard", client=client)
        # guard.chat.completions.create() auto-checks before forwarding
        response = guard.chat.completions.create(
            model="gpt-4",
            messages=messages,
        )

    Args:
        mode: Guard mode - "relaxed", "standard", or "strict"
        client: Optional openai.OpenAI client instance
        auto_block: If True, raise ValueError on attack detection
        check_output: If True, also check AI outputs for sensitive data
        policy_file: Optional YAML policy file path
        log_file: Optional log file path
    """

    def __init__(
        self,
        mode: str = "standard",
        client: Any = None,
        auto_block: bool = True,
        check_output: bool = True,
        policy_file: Optional[str] = None,
        log_file: Optional[str] = None,
    ):
        self._guard = VSOSGuard(
            mode=mode,
            policy_file=policy_file,
            log_file=log_file,
        )
        self._auto_block = auto_block
        self._check_output = check_output
        self._client = client
        self.chat = _ChatProxy(self, client)
        self._input_block_count: int = 0
        self._output_block_count: int = 0

    def check_messages(self, messages: List[Dict[str, Any]]) -> CheckResult:
        """
        Check a list of chat messages for security threats.

        Scans all user-role messages and returns the most severe result.

        Args:
            messages: List of message dicts with 'role' and 'content'

        Returns:
            CheckResult with the most severe finding
        """
        worst_result: Optional[CheckResult] = None

        for msg in messages:
            if not isinstance(msg, dict):
                continue
            if msg.get("role") != "user":
                continue

            content = msg.get("content", "")
            if isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        result = self._guard.check(part["text"])
                        if result.is_blocked():
                            self._input_block_count += 1
                            return result  # Return immediately on block
                        if worst_result is None or (result.is_warning() and not worst_result.is_warning()):
                            worst_result = result
            elif isinstance(content, str):
                result = self._guard.check(content)
                if result.is_blocked():
                    self._input_block_count += 1
                    return result
                if worst_result is None or (result.is_warning() and not worst_result.is_warning()):
                    worst_result = result

        return worst_result or CheckResult(safe=True, confidence="safe")

    def check_output(self, response_text: str) -> CheckResult:
        """
        Check AI output for sensitive data leakage and injection propagation.

        Args:
            response_text: The AI's response text to check

        Returns:
            CheckResult with any findings
        """
        return self._guard.check_output(response_text)

    def _check_response_output(self, response: Any) -> None:
        """Check an OpenAI response object for output safety."""
        try:
            if hasattr(response, "choices") and response.choices:
                for choice in response.choices:
                    if hasattr(choice, "message") and hasattr(choice.message, "content"):
                        content = choice.message.content
                        if content:
                            result = self._guard.check_output(content)
                            if result.is_blocked():
                                self._output_block_count += 1
        except Exception:
            pass  # Never break the user's flow

    def get_stats(self) -> Dict[str, Any]:
        """Return security check statistics."""
        guard_stats = self._guard.logger.get_stats()
        return {
            "input_blocks": self._input_block_count,
            "output_blocks": self._output_block_count,
            "guard_stats": guard_stats,
        }

    @property
    def guard(self) -> VSOSGuard:
        """Access the underlying VSOSGuard instance."""
        return self._guard
