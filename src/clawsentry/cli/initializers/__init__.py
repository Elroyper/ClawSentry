"""Framework initializers for `clawsentry init`."""

from __future__ import annotations

from .a3s_code import A3SCodeInitializer
from .base import FrameworkInitializer, InitResult, SetupResult
from .claude_code import ClaudeCodeInitializer
from .codex import CodexInitializer
from .gemini_cli import GeminiCLIInitializer
from .kimi_cli import KimiCLIInitializer
from .openclaw import OpenClawInitializer

FRAMEWORK_INITIALIZERS: dict[str, type] = {
    "a3s-code": A3SCodeInitializer,
    "claude-code": ClaudeCodeInitializer,
    "codex": CodexInitializer,
    "gemini-cli": GeminiCLIInitializer,
    "kimi-cli": KimiCLIInitializer,
    "openclaw": OpenClawInitializer,
}


def get_initializer(framework: str) -> FrameworkInitializer:
    """Get an initializer instance by framework name.

    Raises KeyError if framework is not registered.
    """
    if framework not in FRAMEWORK_INITIALIZERS:
        available = ", ".join(sorted(FRAMEWORK_INITIALIZERS.keys()))
        raise KeyError(
            f"Unknown framework: {framework!r}. Available: {available}"
        )
    return FRAMEWORK_INITIALIZERS[framework]()
