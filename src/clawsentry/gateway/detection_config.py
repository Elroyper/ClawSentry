"""
Unified detection configuration — single source of truth for all tunable parameters.

All defaults match the pre-existing hardcoded values for 100% backward compatibility.
Parameters can be overridden via constructor or ``CS_`` environment variables.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DetectionConfig:
    """Immutable configuration for ClawSentry detection pipeline.

    Every field has a default that matches the original hardcoded constant,
    ensuring zero behavioural change when no overrides are provided.
    """

    # --- Composite scoring weights (risk_snapshot._composite_score_v2) ---
    composite_weight_max_d123: float = 0.4
    composite_weight_d4: float = 0.25
    composite_weight_d5: float = 0.15
    d6_injection_multiplier: float = 0.5  # formula: 1.0 + X * (d6/3.0)

    # --- Risk level thresholds ---
    threshold_critical: float = 2.2
    threshold_high: float = 1.5
    threshold_medium: float = 0.8

    # --- D4 session accumulation thresholds ---
    d4_high_threshold: int = 5   # count >= X → d4=2
    d4_mid_threshold: int = 2    # count >= X → d4=1

    # --- L2 semantic analysis ---
    l2_budget_ms: float = 5000.0
    l3_budget_ms: Optional[float] = None  # Separate L3 budget; None = use l2_budget_ms
    attack_patterns_path: Optional[str] = None  # None = built-in default

    # --- Post-action tier thresholds ---
    post_action_emergency: float = 0.9
    post_action_escalate: float = 0.6
    post_action_monitor: float = 0.3
    post_action_whitelist: Optional[tuple[str, ...]] = field(default=None)

    # --- Trajectory analyzer ---
    trajectory_max_events: int = 50
    trajectory_max_sessions: int = 10_000

    # --- E-8: External content safety ---
    external_content_d6_boost: float = 0.3
    external_content_post_action_multiplier: float = 1.3

    # --- E-8: D4 frequency anomaly detection ---
    d4_freq_enabled: bool = True
    d4_freq_burst_count: int = 10
    d4_freq_burst_window_s: float = 5.0
    d4_freq_repetitive_count: int = 20
    d4_freq_repetitive_window_s: float = 60.0
    d4_freq_rate_limit_per_min: int = 60

    # --- E-9: DEFER timeout ---
    defer_timeout_action: str = "block"   # "block" or "allow"
    defer_timeout_s: float = 300.0        # 5 minutes default
    defer_bridge_enabled: bool = True     # Enable DEFER→operator bridge
    defer_max_pending: int = 100          # Max concurrent pending DEFERs (0 = unlimited)

    # --- P3: LLM daily budget ---
    llm_daily_budget_usd: float = 0.0    # 0 = unlimited

    # --- E-5: Self-evolving pattern repository ---
    evolving_enabled: bool = False
    evolved_patterns_path: Optional[str] = None

    def __post_init__(self) -> None:
        # Convert list to tuple if passed (convenience for callers)
        if isinstance(self.post_action_whitelist, list):
            object.__setattr__(self, "post_action_whitelist", tuple(self.post_action_whitelist))
        # Validate threshold ordering
        if not (self.threshold_medium <= self.threshold_high <= self.threshold_critical):
            raise ValueError(
                f"threshold ordering violated: medium={self.threshold_medium} "
                f"<= high={self.threshold_high} <= critical={self.threshold_critical}"
            )
        if self.d4_mid_threshold > self.d4_high_threshold:
            raise ValueError(
                f"d4 threshold ordering violated: mid={self.d4_mid_threshold} "
                f"> high={self.d4_high_threshold}"
            )
        for wname in ("composite_weight_max_d123", "composite_weight_d4", "composite_weight_d5", "d6_injection_multiplier"):
            if getattr(self, wname) < 0:
                raise ValueError(f"weight {wname} must be >= 0, got {getattr(self, wname)}")
        if self.l2_budget_ms <= 0:
            raise ValueError(f"l2_budget_ms must be > 0, got {self.l2_budget_ms}")
        if self.l3_budget_ms is not None and self.l3_budget_ms <= 0:
            raise ValueError(f"l3_budget_ms must be > 0, got {self.l3_budget_ms}")
        if not (self.post_action_monitor <= self.post_action_escalate <= self.post_action_emergency):
            raise ValueError(
                f"post_action tier ordering violated: monitor={self.post_action_monitor} "
                f"<= escalate={self.post_action_escalate} <= emergency={self.post_action_emergency}"
            )
        if self.defer_timeout_action not in ("block", "allow"):
            logger.warning(
                "Invalid defer_timeout_action=%r, falling back to 'block'",
                self.defer_timeout_action,
            )
            object.__setattr__(self, "defer_timeout_action", "block")
        if self.defer_timeout_s <= 0:
            raise ValueError(f"defer_timeout_s must be > 0, got {self.defer_timeout_s}")
        if self.llm_daily_budget_usd < 0:
            raise ValueError(f"llm_daily_budget_usd must be >= 0, got {self.llm_daily_budget_usd}")
        if self.threshold_critical > 3.0:
            logger.warning(
                "threshold_critical=%.2f exceeds max achievable score (3.0) with default weights; "
                "CRITICAL level may be unreachable",
                self.threshold_critical,
            )


# ---------------------------------------------------------------------------
# Environment-variable mapping: CS_<FIELD_NAME> → field
# ---------------------------------------------------------------------------

_ENV_MAP: list[tuple[str, str, type]] = [
    ("CS_COMPOSITE_WEIGHT_MAX_D123", "composite_weight_max_d123", float),
    ("CS_COMPOSITE_WEIGHT_D4", "composite_weight_d4", float),
    ("CS_COMPOSITE_WEIGHT_D5", "composite_weight_d5", float),
    ("CS_D6_INJECTION_MULTIPLIER", "d6_injection_multiplier", float),
    ("CS_THRESHOLD_CRITICAL", "threshold_critical", float),
    ("CS_THRESHOLD_HIGH", "threshold_high", float),
    ("CS_THRESHOLD_MEDIUM", "threshold_medium", float),
    ("CS_D4_HIGH_THRESHOLD", "d4_high_threshold", int),
    ("CS_D4_MID_THRESHOLD", "d4_mid_threshold", int),
    ("CS_L2_BUDGET_MS", "l2_budget_ms", float),
    ("CS_L3_BUDGET_MS", "l3_budget_ms", float),
    ("CS_ATTACK_PATTERNS_PATH", "attack_patterns_path", str),
    ("CS_POST_ACTION_EMERGENCY", "post_action_emergency", float),
    ("CS_POST_ACTION_ESCALATE", "post_action_escalate", float),
    ("CS_POST_ACTION_MONITOR", "post_action_monitor", float),
    ("CS_TRAJECTORY_MAX_EVENTS", "trajectory_max_events", int),
    ("CS_TRAJECTORY_MAX_SESSIONS", "trajectory_max_sessions", int),
    ("CS_EVOLVED_PATTERNS_PATH", "evolved_patterns_path", str),
    ("CS_EXTERNAL_CONTENT_D6_BOOST", "external_content_d6_boost", float),
    ("CS_EXTERNAL_CONTENT_POST_ACTION_MULTIPLIER", "external_content_post_action_multiplier", float),
    ("CS_D4_FREQ_BURST_COUNT", "d4_freq_burst_count", int),
    ("CS_D4_FREQ_BURST_WINDOW_S", "d4_freq_burst_window_s", float),
    ("CS_D4_FREQ_REPETITIVE_COUNT", "d4_freq_repetitive_count", int),
    ("CS_D4_FREQ_REPETITIVE_WINDOW_S", "d4_freq_repetitive_window_s", float),
    ("CS_D4_FREQ_RATE_LIMIT_PER_MIN", "d4_freq_rate_limit_per_min", int),
    ("CS_DEFER_TIMEOUT_ACTION", "defer_timeout_action", str),
    ("CS_DEFER_TIMEOUT_S", "defer_timeout_s", float),
    ("CS_DEFER_MAX_PENDING", "defer_max_pending", int),
    ("CS_LLM_DAILY_BUDGET_USD", "llm_daily_budget_usd", float),
]

# Comma-separated list vars handled separately
_ENV_LIST_MAP: list[tuple[str, str]] = [
    ("CS_POST_ACTION_WHITELIST", "post_action_whitelist"),
]


def build_detection_config_from_env() -> DetectionConfig:
    """Build a :class:`DetectionConfig` from ``CS_`` environment variables.

    Missing or unparseable variables silently fall back to defaults.
    If the combination of overrides violates validation constraints,
    the entire config falls back to defaults with an error log.
    """
    overrides: dict = {}

    for env_key, field_name, typ in _ENV_MAP:
        raw = os.getenv(env_key)
        if raw is None:
            continue
        try:
            overrides[field_name] = typ(raw)
        except (ValueError, TypeError):
            logger.warning("Invalid value for %s=%r, using default", env_key, raw)

    for env_key, field_name in _ENV_LIST_MAP:
        raw = os.getenv(env_key)
        if raw is None:
            continue
        items = [s.strip() for s in raw.split(",") if s.strip()]
        if items:
            overrides[field_name] = tuple(items)

    # Bool env vars (special handling: "1"/"true"/"yes" → True)
    def _parse_bool_env(env_key: str, field_name: str) -> None:
        raw = os.getenv(env_key, "").strip().lower()
        if raw in ("1", "true", "yes"):
            overrides[field_name] = True
        elif raw in ("0", "false", "no"):
            overrides[field_name] = False
        elif raw:
            logger.warning("Invalid value for %s=%r, using default", env_key, raw)

    _parse_bool_env("CS_EVOLVING_ENABLED", "evolving_enabled")
    _parse_bool_env("CS_D4_FREQ_ENABLED", "d4_freq_enabled")
    _parse_bool_env("CS_DEFER_BRIDGE_ENABLED", "defer_bridge_enabled")

    try:
        return DetectionConfig(**overrides)
    except (ValueError, TypeError) as exc:
        logger.error(
            "CS_ env vars produce invalid DetectionConfig (%s); falling back to defaults",
            exc,
        )
        return DetectionConfig()


# --- Preset security levels ---

PRESETS: dict[str, dict[str, object]] = {
    "low": {
        "threshold_critical": 2.8,
        "threshold_high": 2.0,
        "threshold_medium": 1.2,
        "d6_injection_multiplier": 0.3,
        "post_action_emergency": 0.95,
        "post_action_escalate": 0.7,
        "post_action_monitor": 0.4,
        "defer_timeout_action": "allow",
        "defer_bridge_enabled": False,
    },
    "medium": {},  # all defaults
    "high": {
        "threshold_critical": 1.8,
        "threshold_high": 1.2,
        "threshold_medium": 0.5,
        "d6_injection_multiplier": 0.7,
        "post_action_emergency": 0.8,
        "post_action_escalate": 0.5,
        "post_action_monitor": 0.2,
    },
    "strict": {
        "threshold_critical": 1.3,
        "threshold_high": 0.9,
        "threshold_medium": 0.3,
        "d6_injection_multiplier": 1.0,
        "post_action_emergency": 0.7,
        "post_action_escalate": 0.4,
        "post_action_monitor": 0.15,
    },
}


def from_preset(name: str, **overrides: object) -> DetectionConfig:
    """Create a DetectionConfig from a named preset with optional overrides.

    Raises KeyError if preset name is unknown.
    """
    if name not in PRESETS:
        raise KeyError(f"Unknown preset: {name!r}. Available: {sorted(PRESETS.keys())}")
    params = dict(PRESETS[name])
    params.update(overrides)
    return DetectionConfig(**params)


def build_detection_config_with_preset(
    preset_name: str,
    project_overrides: dict[str, object],
) -> DetectionConfig:
    """Build a :class:`DetectionConfig` from a preset, project overrides, and env vars.

    Priority chain (highest wins):
      1. ``CS_`` environment variables
      2. ``project_overrides`` (from ``.clawsentry.toml [overrides]``)
      3. Preset values
      4. :class:`DetectionConfig` defaults

    If the preset name is unknown, logs a warning and falls back to defaults.
    If the final combination violates validation, falls back to defaults.
    """
    # 1. Start from preset
    try:
        preset_params = dict(PRESETS[preset_name])
    except KeyError:
        logger.warning(
            "Unknown preset %r in project config; using defaults", preset_name
        )
        preset_params = {}

    # 2. Apply project overrides on top
    params: dict[str, object] = {**preset_params, **project_overrides}

    # 3. Apply env var overrides on top (highest priority)
    for env_key, field_name, typ in _ENV_MAP:
        raw = os.getenv(env_key)
        if raw is None:
            continue
        try:
            params[field_name] = typ(raw)
        except (ValueError, TypeError):
            logger.warning("Invalid value for %s=%r, using default", env_key, raw)

    for env_key, field_name in _ENV_LIST_MAP:
        raw = os.getenv(env_key)
        if raw is None:
            continue
        items = [s.strip() for s in raw.split(",") if s.strip()]
        if items:
            params[field_name] = tuple(items)

    def _parse_bool_env(env_key: str, field_name: str) -> None:
        raw = os.getenv(env_key, "").strip().lower()
        if raw in ("1", "true", "yes"):
            params[field_name] = True
        elif raw in ("0", "false", "no"):
            params[field_name] = False
        elif raw:
            logger.warning("Invalid value for %s=%r, using default", env_key, raw)

    _parse_bool_env("CS_EVOLVING_ENABLED", "evolving_enabled")
    _parse_bool_env("CS_D4_FREQ_ENABLED", "d4_freq_enabled")
    _parse_bool_env("CS_DEFER_BRIDGE_ENABLED", "defer_bridge_enabled")

    try:
        return DetectionConfig(**params)
    except (ValueError, TypeError) as exc:
        logger.error(
            "Preset %r + overrides produce invalid DetectionConfig (%s); "
            "falling back to defaults",
            preset_name,
            exc,
        )
        return DetectionConfig()
