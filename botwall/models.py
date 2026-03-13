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
    decision: Literal["allow", "observe", "challenge", "decoy"]
    score: float
    reasons: list[str]


class EnvReport(BaseModel):
    webdriver: bool
    chrome_obj: bool
    plugins_count: int
    languages: list[str]
    viewport: list[int]
    notification_api: bool
    perf_memory: bool
    touch_support: bool
    device_pixel_ratio: float
    timezone: str
    renderer: str


class GateVerifyRequest(BaseModel):
    challenge: str
    nonce: str
    env_report: EnvReport


class GateVerifyResponse(BaseModel):
    ok: bool
    reason: str | None = None

