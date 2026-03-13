"""
botwall/config.py — centralised configuration loader.

Load order (highest priority wins):
  1. Environment variables (BOTWALL_*)
  2. TOML file at BOTWALL_CONFIG env var path
  3. botwall.toml in the current working directory
  4. ~/.config/botwall/botwall.toml
  5. Built-in defaults
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── TOML loading ──────────────────────────────────────────────────────────────

def _find_toml() -> Path | None:
    """Return the first botwall.toml found in the standard search path."""
    candidates = [
        os.environ.get("BOTWALL_CONFIG"),
        "botwall.toml",
        Path.home() / ".config" / "botwall" / "botwall.toml",
    ]
    for c in candidates:
        if c and Path(c).is_file():
            return Path(c)
    return None


def _load_toml() -> dict[str, Any]:
    path = _find_toml()
    if path is None:
        return {}
    with open(path, "rb") as fh:
        return tomllib.load(fh)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get(toml: dict, *keys: str, default: Any = None) -> Any:
    """Drill into a nested TOML dict with dot-separated key path."""
    node: Any = toml
    for k in keys:
        if not isinstance(node, dict):
            return default
        node = node.get(k, default)
    return node


def _env(var: str, toml_val: Any, cast=str) -> Any:
    """Return env var (cast to type) if set, otherwise toml_val."""
    raw = os.environ.get(var)
    if raw is not None:
        return cast(raw)
    return toml_val


# ── Settings dataclass ────────────────────────────────────────────────────────

@dataclass(slots=True)
class ScoringWeights:
    # request-level
    ua_bot_marker: float = -45
    ua_browser: float = 4
    missing_accept_lang: float = -10
    ip_bad: float = -25
    ip_good: float = 6
    missing_ja3: float = -5
    session_continuity: float = 3
    burst_extreme: float = -35
    burst_high: float = -15
    # traversal
    traversal_valid: float = 10
    traversal_invalid: float = -10
    # beacon
    trap_hit_per_event: float = -25
    scroll_dwell_human: float = 12
    low_dwell: float = -8
    entropy_ok: float = 8
    entropy_outlier: float = -6
    focus_visibility: float = 4
    screenshot_combo: float = -5
    render_flat: float = -10
    render_variance: float = 6
    ua_mismatch_tls_js: float = -25
    platform_mismatch: float = -15
    ua_data_empty: float = -10
    # sequence
    seq_dwell_good: float = 8
    seq_scroll_good: float = 7
    seq_entropy_good: float = 6
    seq_trap_penalty: float = -20
    seq_backtrack_bonus: float = 5
    seq_linearity_penalty: float = -12


@dataclass(slots=True)
class Settings:
    # Server
    app_host: str = "127.0.0.1"
    app_port: int = 4000
    session_cookie: str = "bw_sid"
    gate_cookie: str = "bw_gate"

    # Secrets
    secret_key: str = "dev-change-me"
    telemetry_secret: str = "telemetry-dev-secret"

    # Redis
    redis_enabled: bool = False
    redis_url: str = "redis://127.0.0.1:6379/0"

    # Scoring thresholds
    allow_threshold: float = 30.0
    decoy_threshold: float = -80.0
    observe_threshold: float = -35.0
    sequence_window: int = 16

    # Token TTLs
    proof_ttl_seconds: int = 60
    traversal_ttl_seconds: int = 300
    recovery_ttl_seconds: int = 180
    recovery_allow_seconds: int = 300
    gate_ttl_seconds: int = 86400

    # PoW (Stage 1)
    pow_default_difficulty: int = 5
    pow_elevated_difficulty: int = 6
    pow_max_solve_seconds: int = 30

    # Decoy
    decoy_max_nodes: int = 80
    decoy_min_links: int = 4
    decoy_max_links: int = 6

    # Telemetry
    telemetry_enabled: bool = False
    telemetry_peer_threshold_mild: int = 3
    telemetry_peer_threshold_strong: int = 5
    telemetry_peer_threshold_hard: int = 10
    peer_secrets_raw: str = ""

    # Scoring weights (nested object)
    weights: ScoringWeights = field(default_factory=ScoringWeights)

    def botwall_api_url(self) -> str:
        """Canonical base URL for this server (used in deployment configs)."""
        return f"http://{self.app_host}:{self.app_port}"


# ── Factory ───────────────────────────────────────────────────────────────────

def load_settings() -> Settings:
    """Load settings from TOML file + environment variables."""
    toml = _load_toml()

    def t(*keys: str, default: Any = None) -> Any:
        return _get(toml, *keys, default=default)

    w_toml = t("scoring", "weights") or {}

    weights = ScoringWeights(
        ua_bot_marker=float(w_toml.get("ua_bot_marker", -45)),
        ua_browser=float(w_toml.get("ua_browser", 4)),
        missing_accept_lang=float(w_toml.get("missing_accept_lang", -10)),
        ip_bad=float(w_toml.get("ip_bad", -25)),
        ip_good=float(w_toml.get("ip_good", 6)),
        missing_ja3=float(w_toml.get("missing_ja3", -5)),
        session_continuity=float(w_toml.get("session_continuity", 3)),
        burst_extreme=float(w_toml.get("burst_extreme", -35)),
        burst_high=float(w_toml.get("burst_high", -15)),
        traversal_valid=float(w_toml.get("traversal_valid", 10)),
        traversal_invalid=float(w_toml.get("traversal_invalid", -10)),
        trap_hit_per_event=float(w_toml.get("trap_hit_per_event", -25)),
        scroll_dwell_human=float(w_toml.get("scroll_dwell_human", 12)),
        low_dwell=float(w_toml.get("low_dwell", -8)),
        entropy_ok=float(w_toml.get("entropy_ok", 8)),
        entropy_outlier=float(w_toml.get("entropy_outlier", -6)),
        focus_visibility=float(w_toml.get("focus_visibility", 4)),
        screenshot_combo=float(w_toml.get("screenshot_combo", -5)),
        render_flat=float(w_toml.get("render_flat", -10)),
        render_variance=float(w_toml.get("render_variance", 6)),
        ua_mismatch_tls_js=float(w_toml.get("ua_mismatch_tls_js", -25)),
        platform_mismatch=float(w_toml.get("platform_mismatch", -15)),
        ua_data_empty=float(w_toml.get("ua_data_empty", -10)),
        seq_dwell_good=float(w_toml.get("seq_dwell_good", 8)),
        seq_scroll_good=float(w_toml.get("seq_scroll_good", 7)),
        seq_entropy_good=float(w_toml.get("seq_entropy_good", 6)),
        seq_trap_penalty=float(w_toml.get("seq_trap_penalty", -20)),
        seq_backtrack_bonus=float(w_toml.get("seq_backtrack_bonus", 5)),
        seq_linearity_penalty=float(w_toml.get("seq_linearity_penalty", -12)),
    )

    return Settings(
        # Server
        app_host=_env("BOTWALL_HOST", t("server", "host", default="127.0.0.1")),
        app_port=int(_env("BOTWALL_PORT", t("server", "port", default=4000), cast=int)),
        session_cookie=_env("BOTWALL_SESSION_COOKIE", t("server", "session_cookie", default="bw_sid")),
        gate_cookie=_env("BOTWALL_GATE_COOKIE", t("server", "gate_cookie", default="bw_gate")),
        # Secrets
        secret_key=_env("BOTWALL_SECRET_KEY", t("secrets", "secret_key", default="dev-change-me")),
        telemetry_secret=_env("BOTWALL_TELEMETRY_SECRET", t("secrets", "telemetry_secret", default="telemetry-dev-secret")),
        # Redis
        redis_enabled=_env("BOTWALL_REDIS_ENABLED", t("redis", "enabled", default=False), cast=lambda v: v == "1"),
        redis_url=_env("BOTWALL_REDIS_URL", t("redis", "url", default="redis://127.0.0.1:6379/0")),
        # Scoring
        allow_threshold=float(_env("BOTWALL_ALLOW_THRESHOLD", t("scoring", "allow_threshold", default=30.0), cast=float)),
        decoy_threshold=float(_env("BOTWALL_DECOY_THRESHOLD", t("scoring", "decoy_threshold", default=-80.0), cast=float)),
        observe_threshold=float(_env("BOTWALL_OBSERVE_THRESHOLD", t("scoring", "observe_threshold", default=-35.0), cast=float)),
        sequence_window=int(_env("BOTWALL_SEQUENCE_WINDOW", t("scoring", "sequence_window", default=16), cast=int)),
        # Tokens
        proof_ttl_seconds=int(_env("BOTWALL_PROOF_TTL", t("tokens", "proof_ttl_seconds", default=60), cast=int)),
        traversal_ttl_seconds=int(_env("BOTWALL_TRAVERSAL_TTL", t("tokens", "traversal_ttl_seconds", default=300), cast=int)),
        recovery_ttl_seconds=int(_env("BOTWALL_RECOVERY_TTL", t("tokens", "recovery_ttl_seconds", default=180), cast=int)),
        recovery_allow_seconds=int(_env("BOTWALL_RECOVERY_ALLOW", t("tokens", "recovery_allow_seconds", default=300), cast=int)),
        gate_ttl_seconds=int(_env("BOTWALL_GATE_TTL", t("tokens", "gate_ttl_seconds", default=86400), cast=int)),
        # PoW
        pow_default_difficulty=int(_env("BOTWALL_POW_DIFFICULTY", t("pow", "default_difficulty", default=5), cast=int)),
        pow_elevated_difficulty=int(_env("BOTWALL_POW_ELEVATED_DIFFICULTY", t("pow", "elevated_difficulty", default=6), cast=int)),
        pow_max_solve_seconds=int(_env("BOTWALL_POW_MAX_SOLVE", t("pow", "max_solve_seconds", default=30), cast=int)),
        # Decoy
        decoy_max_nodes=int(_env("BOTWALL_DECOY_MAX_NODES", t("decoy", "max_nodes", default=80), cast=int)),
        decoy_min_links=int(_env("BOTWALL_DECOY_MIN_LINKS", t("decoy", "min_links", default=4), cast=int)),
        decoy_max_links=int(_env("BOTWALL_DECOY_MAX_LINKS", t("decoy", "max_links", default=6), cast=int)),
        # Telemetry
        telemetry_enabled=_env("BOTWALL_TELEMETRY_ENABLED", t("telemetry", "enabled", default=False), cast=lambda v: v == "1"),
        telemetry_peer_threshold_mild=int(_env("BOTWALL_TELEMETRY_MILD", t("telemetry", "peer_threshold_mild", default=3), cast=int)),
        telemetry_peer_threshold_strong=int(_env("BOTWALL_TELEMETRY_STRONG", t("telemetry", "peer_threshold_strong", default=5), cast=int)),
        telemetry_peer_threshold_hard=int(_env("BOTWALL_TELEMETRY_HARD", t("telemetry", "peer_threshold_hard", default=10), cast=int)),
        peer_secrets_raw=_env("BOTWALL_PEER_SECRETS", t("telemetry", "peer_secrets", default="")),
        weights=weights,
    )
