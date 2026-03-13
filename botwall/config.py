from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(slots=True)
class Settings:
    app_host: str = field(default_factory=lambda: os.getenv("BOTWALL_HOST", "127.0.0.1"))
    app_port: int = field(default_factory=lambda: int(os.getenv("BOTWALL_PORT", "4000")))
    session_cookie: str = field(default_factory=lambda: os.getenv("BOTWALL_SESSION_COOKIE", "bw_sid"))
    secret_key: str = field(default_factory=lambda: os.getenv("BOTWALL_SECRET_KEY", "dev-change-me"))
    telemetry_secret: str = field(default_factory=lambda: os.getenv("BOTWALL_TELEMETRY_SECRET", "telemetry-dev-secret"))
    redis_url: str = field(default_factory=lambda: os.getenv("BOTWALL_REDIS_URL", "redis://127.0.0.1:6379/0"))
    redis_enabled: bool = field(default_factory=lambda: os.getenv("BOTWALL_REDIS_ENABLED", "0") == "1")
    proof_ttl_seconds: int = field(default_factory=lambda: int(os.getenv("BOTWALL_PROOF_TTL", "60")))
    traversal_ttl_seconds: int = field(default_factory=lambda: int(os.getenv("BOTWALL_TRAVERSAL_TTL", "300")))
    sequence_window: int = field(default_factory=lambda: int(os.getenv("BOTWALL_SEQUENCE_WINDOW", "16")))
    telemetry_enabled: bool = field(default_factory=lambda: os.getenv("BOTWALL_TELEMETRY_ENABLED", "0") == "1")


def load_settings() -> Settings:
    return Settings()
