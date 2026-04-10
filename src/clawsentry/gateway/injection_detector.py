"""
D6 Injection Detection — Layer 1 (heuristic regex) + Layer 2 (canary token) + Layer 3 (vector similarity).

Design basis: docs/plans/archive/2026-03/2026-03-23-e4-phase1-design-v1.2.md section 2.2
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Protocol, runtime_checkable

from .models import CanaryToken
from .text_utils import count_invisible_chars, normalize_text

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Layer 1: Heuristic regex patterns
# ---------------------------------------------------------------------------

WEAK_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"ignore\s+(?:\w+\s+)*(?:previous|above|prior)\s+(?:instructions?|prompts?)",
        r"disregard\s+(?:\w+\s+)*(?:previous|above)",
        r"new (instructions?|task|goal)",
        r"system:\s*you are now",
        r"forget (everything|all|previous)",
        r"start (over|fresh|new)",
        r"from now on",
        r"<\|endoftext\|>",
        r"###\s*Instruction:",
        r"\b(must|should)\b[^\n]*\b(now|immediately)\b",
        # --- Chinese: ignore/discard ---
        r"忽略[^。]{0,20}(?:之前|所有|一切|上面).*?(?:指令|提示|规则|约束|要求)",
        r"忘记[^。]{0,20}(?:之前|所有|一切).*?(?:指令|提示|规则|约束|内容)",
        r"抛弃[^。]{0,20}(?:之前|所有|一切).*?(?:指令|提示|规则|约束)",
        r"遗忘[^。]{0,20}(?:之前|所有|一切|上面).*?(?:指令|提示|规则|约束)",
        r"无视[^。]{0,20}(?:之前|所有|一切|上面).*?(?:指令|提示|规则|约束|要求)",
        r"不要[^。]{0,20}(?:遵守|执行|按照).*?(?:之前|原本).*?(?:指令|提示|规则)",
        # --- Chinese: override/modify ---
        r"覆盖[^。]{0,20}(?:系统|原本|之前).*?(?:指令|提示|规则|约束)",
        r"替换[^。]{0,20}(?:你的|原本).*?(?:指令|提示|规则|系统提示)",
        r"修改[^。]{0,20}(?:你的|系统).*?(?:指令|提示|规则)",
        r"改变[^。]{0,20}(?:你的|系统).*?(?:指令|提示|功能)",
        # --- Chinese: new instructions ---
        r"(?:新的|全新的|最新)(?:指令|规则|提示|要求).*?(?:是|为|如下)[：:]",
        r"(?:从现在开始|今后|从此刻起|接下来)[^。]{0,20}(?:你的|你应该).*?(?:指令|行为|目标)",
    ]
]

STRONG_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE | re.DOTALL) for p in [
        r"<script\b",
        r"data:text/html;base64,",
        r"eval\s*\(|exec\s*\(|__import__\s*\(",
        r"<!--[^>]*(?:ignore|disregard)",
        r"data:[^,]*base64,[^)]{0,2048}(?:curl|wget)",
        r"\$\{[A-Z_]+\}.*?(curl|wget)",
        r"git\s+push.*?http.*?@",
        # --- Chinese: bypass safety ---
        r"(?:关闭|禁用|停用|取消|移除)[^。]{0,20}(?:安全|审核|检测|限制|过滤|防护)",
        r"(?:突破|绕过|跳过|无视)[^。]{0,20}(?:安全|限制|过滤|防护|审核|道德|伦理)",
        # --- Chinese: role play (FIXED: 是 properly placed) ---
        r"你\s*(?:现在|已经)?\s*是\s*(?:一个|一名)[^。]*?(?:邪恶|不受限|无约束|黑客|恶意)",
        r"(?:进入|切换|启动|激活)[^。]{0,20}(?:开发者|管理员|不受限|无约束|邪恶|神)\s*(?:模式|状态)",
        r"(?:模拟|扮演|假设|假如).*?你\s*(?:是|为)\s*(?:开发者|管理员|黑客|神)",
        # --- Chinese: system markers ---
        r"【\s*(?:系统|管理|开发|操作者)\s*】",
        r"《\s*系统提示\s*》",
        r"\[系统\s*(?:提示|指令|命令|消息)[^]]{0,15}?\]",
        # --- Mixed Chinese-English ---
        r"(?:ignore|disregard).*?(?:指令|规则|提示)",
        r"(?:忽略|遗忘|忘记|抛弃).*?(?:instructions?|rules?|prompts?)",
    ]
]

TOOL_SPECIFIC_PATTERNS: dict[str, list[re.Pattern]] = {
    "read_file": [
        re.compile(r"<!--\s*IMPORTANT.*?-->", re.IGNORECASE | re.DOTALL),
        re.compile(r"!\[.*?\]\(https?://[^)]+\?[^)]+\)"),
    ],
    "http_request": [
        re.compile(r"<script>.*?fetch\(", re.IGNORECASE | re.DOTALL),
        re.compile(r"font-size:\s*0", re.IGNORECASE),
    ],
}

_MAX_SCORE_INPUT_LEN = 65_536  # 64KB cap — matches event_text() limit


def score_layer1(
    text: str,
    tool_name: Optional[str] = None,
    content_origin: Optional[str] = None,
    d6_boost: float = 0.0,
) -> float:
    """Score text for injection patterns (Layer 1 heuristic). Returns 0.0-3.0.

    Args:
        content_origin: ``"external"`` / ``"user"`` / ``"unknown"`` / ``None``.
        d6_boost: Additional score to add when *content_origin* is ``"external"``
                  (configured via ``DetectionConfig.external_content_d6_boost``).
    """
    if len(text) > _MAX_SCORE_INPUT_LEN:
        text = text[:_MAX_SCORE_INPUT_LEN]
    score = 0.0

    # Invisible char detection on RAW text (before normalization)
    invisible_count = count_invisible_chars(text)
    if invisible_count > 0:
        score += min(invisible_count * 0.8, 2.4)

    # Normalize for pattern matching (NFKC + strip invisible)
    normalized = normalize_text(text)

    # Weak patterns: +0.3 each, max 1.5
    weak_count = sum(1 for p in WEAK_INJECTION_PATTERNS if p.search(normalized))
    score += min(weak_count * 0.3, 1.5)

    # Strong patterns: +0.8 each, max 2.4
    strong_count = sum(1 for p in STRONG_INJECTION_PATTERNS if p.search(normalized))
    score += min(strong_count * 0.8, 2.4)

    # Tool-specific: +0.5 each
    if tool_name:
        tool_pats = TOOL_SPECIFIC_PATTERNS.get(tool_name, [])
        tool_count = sum(1 for p in tool_pats if p.search(normalized))
        score += min(tool_count * 0.5, 1.0)

    # E-8: External content D6 boost
    if content_origin == "external" and d6_boost > 0:
        score += d6_boost

    return min(score, 3.0)


# ---------------------------------------------------------------------------
# Layer 3: Vector similarity interface
# ---------------------------------------------------------------------------

@runtime_checkable
class EmbeddingBackend(Protocol):
    """Protocol for pluggable embedding backends.

    Users implement this with their preferred model (e.g. sentence-transformers,
    OpenAI embeddings). The ``max_similarity`` method returns the highest cosine
    similarity between the input text and a corpus of known injection attacks.
    """

    def max_similarity(self, text: str) -> float: ...


_VECTOR_SIMILARITY_THRESHOLD = 0.75


class VectorLayer:
    """Layer 3 vector similarity scoring with pluggable backend.

    When *enabled* is ``False`` or *backend* is ``None``, ``score()`` returns 0.0.
    When enabled, maps similarity above *threshold* to a 0.0-2.0 score range.
    """

    def __init__(
        self,
        backend: Optional[EmbeddingBackend] = None,
        *,
        enabled: bool = True,
        threshold: float = _VECTOR_SIMILARITY_THRESHOLD,
    ) -> None:
        self._backend = backend
        self._enabled = enabled and (backend is not None)
        self._threshold = threshold

    def score(self, text: str) -> float:
        """Score text via vector similarity. Returns 0.0-2.0."""
        if not self._enabled or self._backend is None:
            return 0.0
        try:
            similarity = self._backend.max_similarity(text)
            if similarity <= self._threshold:
                return 0.0
            return min(2.0 * (similarity - self._threshold) / (1.0 - self._threshold), 2.0)
        except Exception as exc:
            logger.warning("VectorLayer scoring failed (%s)", type(exc).__name__, exc_info=True)
            return 0.0


class InjectionDetector:
    """D6 injection detection combining heuristic regex, canary token, and optional vector similarity."""

    def __init__(self, vector_layer: Optional[VectorLayer] = None) -> None:
        self._vector_layer = vector_layer

    def create_canary(self) -> CanaryToken:
        return CanaryToken.generate()

    def score(
        self,
        text: str,
        tool_name: str,
        canary: Optional[CanaryToken] = None,
    ) -> float:
        """Compute D6 injection score (0.0-3.0). Combines Layer 1 + Layer 2 + Layer 3."""
        l1_score = score_layer1(text, tool_name)
        canary_score = 0.0
        if canary is not None:
            canary_score = canary.check_leak(text)
        vector_score = 0.0
        if self._vector_layer is not None:
            vector_score = self._vector_layer.score(text)
        return min(l1_score + canary_score + vector_score, 3.0)
