from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


SCHEMA_VERSION = "1.0"


class BeaconEvent(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    session_id: str
    nonce: str | None = None
    page_path: str | None = None
    pointer_moves: int = 0
    scroll_events: int = 0
    max_scroll_depth: int = 0
    visibility_changes: int = 0
    focus_events: int = 0
    blur_events: int = 0
    trap_hits: int = 0
    trap_ids: list[str] = Field(default_factory=list)
    copy_events: int = 0
    key_events: int = 0
    screenshot_combo_hits: int = 0
    dwell_ms: int = 0
    event_loop_jitter: float = 0.0
    pointer_entropy: float = 0.0
    canvas_frame_ms: list[float] = Field(default_factory=list)
    webgl_frame_ms: list[float] = Field(default_factory=list)
    user_agent: str | None = None
    platform: str | None = None
    ua_data: dict[str, Any] = Field(default_factory=dict)


class GateEnvReport(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    webdriver: bool = False
    chrome_obj: bool = True
    plugins_count: int = 0
    languages: list[str] = Field(default_factory=list)
    viewport: list[int] = Field(default_factory=lambda: [0, 0])
    notification_api: bool = True
    perf_memory: bool = True
    touch_support: bool = False
    device_pixel_ratio: float = 1.0
    timezone: str = ""
    renderer: str = "unknown"


class GateVerifyRequest(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    session_id: str
    challenge_token: str
    challenge: str
    nonce: str
    hash: str
    solve_ms: int
    return_to: str = "/"
    env: GateEnvReport


class GateVerifyResponse(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    session_id: str
    decision: Literal["allow", "challenge"]
    env_score: int
    next_path: str
    gate_expires_at: int | None = None
    reasons: list[str] = Field(default_factory=list)


class ProofSubmission(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    session_id: str
    token: str
    page_path: str
    nonce: str
    beacon: BeaconEvent


class DecisionState(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    session_id: str
    decision: Literal["allow", "observe", "challenge", "decoy"]
    score: float
    reasons: list[str]
    needs_challenge: bool = False


class TraversalToken(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    session_id: str
    page_path: str
    token: str


class TelemetryFingerprint(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    fingerprint: str
    suspicion: float = Field(ge=-100.0, le=100.0)
    source: str
    observed_at: int


class TelemetryExport(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    source: str
    exported_at: int
    fingerprints: list[TelemetryFingerprint]
    signature: str


class TelemetryImport(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    source: str
    exported_at: int
    fingerprints: list[TelemetryFingerprint]
    signature: str


class RecoveryStartRequest(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    session_id: str
    reason: str = "false_positive"


class RecoveryStartResponse(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    recovery_token: str
    instruction: str


class RecoveryCompleteRequest(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    session_id: str
    recovery_token: str
    acknowledgement: str


class RecoveryCompleteResponse(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    decision: Literal["allow"]
    allow_until: int


class CheckResponse(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    session_id: str
    decision: Literal["gate", "allow", "observe", "challenge", "decoy"]
    score: float
    reasons: list[str]
