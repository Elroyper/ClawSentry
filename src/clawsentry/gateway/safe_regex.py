"""Lightweight ReDoS-safe regex compilation.

Detects nested repetition patterns that could cause exponential
backtracking. Inspired by ClawKeeper's safe-regex.ts.

Known limitation: does not detect adjacent quantified atoms like
``\\d+\\d+`` or ``(ab)+(cd)+`` which can also cause catastrophic
backtracking. These require character-set overlap analysis not
implemented here.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

__all__ = ["has_nested_repetition", "compile_safe_regex"]

logger = logging.getLogger(__name__)

_QUANTIFIER_RE = re.compile(r"[*+?]|\{\d+,?\d*\}")


def has_nested_repetition(pattern: str) -> bool:
    """Conservative check for nested quantifiers that indicate ReDoS risk.

    Detects: (a+)+, (a*)+, (a|b)+ (alternation inside quantified group).
    """
    depth = 0
    # Stack tracks whether each nesting level has inner "complexity"
    # (quantifiers or alternation that could cause backtracking)
    has_inner_complexity: list[bool] = [False]
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            i += 2  # skip escaped char
            continue
        if ch == "[":
            # Skip character class entirely.
            # Handle []] and [^]] where ] is the first char in the class.
            i += 1
            if i < len(pattern) and pattern[i] == "^":
                i += 1  # skip negation
            if i < len(pattern) and pattern[i] == "]":
                i += 1  # literal ] as first char in class
            while i < len(pattern) and pattern[i] != "]":
                if pattern[i] == "\\" and i + 1 < len(pattern):
                    i += 1
                i += 1
            i += 1
            continue
        if ch == "(":
            depth += 1
            has_inner_complexity.append(False)
        elif ch == ")":
            inner = has_inner_complexity.pop() if len(has_inner_complexity) > 1 else False
            depth = max(depth - 1, 0)
            # Check if this group is followed by a quantifier
            rest = pattern[i + 1:]
            if _QUANTIFIER_RE.match(rest) and inner:
                return True
        elif ch == "|":
            # Alternation inside a group counts as complexity
            if depth > 0 and has_inner_complexity:
                has_inner_complexity[-1] = True
        elif ch in "*+":
            if has_inner_complexity:
                has_inner_complexity[-1] = True
        elif ch == "{" and _QUANTIFIER_RE.match(pattern[i:]):
            if has_inner_complexity:
                has_inner_complexity[-1] = True
        i += 1
    return False


def compile_safe_regex(
    pattern: str, flags: int = re.IGNORECASE | re.DOTALL
) -> Optional[re.Pattern]:
    """Compile a regex only if it passes safety checks.

    Returns None and logs a warning if the pattern is unsafe or invalid.
    """
    if not pattern:
        logger.warning("Skipped empty regex pattern")
        return None
    if has_nested_repetition(pattern):
        logger.warning("Skipped potential ReDoS pattern: %r", pattern)
        return None
    try:
        return re.compile(pattern, flags)
    except re.error as e:
        logger.warning("Skipped invalid regex pattern %r: %s", pattern, e)
        return None
