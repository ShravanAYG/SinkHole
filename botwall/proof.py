from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

from .crypto import TokenError, now_ts, sign_json, verify_json


@dataclass(slots=True)
class PowChallenge:
    challenge_token: str
    challenge: str
    difficulty: int
    issued_at: int
    expires_at: int


@dataclass(slots=True)
class PowSolutionResult:
    challenge_id: str
    difficulty: int
    issued_at: int
    solved_at: int


def compute_pow_hash(challenge: str, nonce: str) -> str:
    input_bytes = (challenge + nonce).encode("utf-8")
    return hashlib.sha256(input_bytes).hexdigest()


def issue_pow_challenge(
    *,
    secret: str,
    session_id: str,
    ip_hash: str,
    difficulty: int,
    ttl_seconds: int,
) -> PowChallenge:
    now = now_ts()
    challenge = secrets.token_hex(16)
    payload = {
        "t": "gate_challenge",
        "sid": session_id,
        "iph": ip_hash,
        "c": challenge,
        "d": int(difficulty),
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    token = sign_json(payload, secret)
    return PowChallenge(
        challenge_token=token,
        challenge=challenge,
        difficulty=int(difficulty),
        issued_at=now,
        expires_at=now + ttl_seconds,
    )


def verify_pow_solution(
    *,
    challenge_token: str,
    secret: str,
    session_id: str,
    ip_hash: str,
    challenge: str,
    nonce: str,
    submitted_hash: str,
    solve_ms: int,
    max_solve_seconds: int,
    now: int | None = None,
) -> PowSolutionResult:
    if now is None:
        now = now_ts()

    payload = verify_json(challenge_token, secret)

    if payload.get("t") != "gate_challenge":
        raise TokenError("wrong challenge token type")
    if payload.get("sid") != session_id:
        raise TokenError("challenge token session mismatch")
    if payload.get("iph") != ip_hash:
        raise TokenError("challenge token ip mismatch")
    if int(payload.get("exp", 0)) < now:
        raise TokenError("challenge token expired")

    expected_challenge = str(payload.get("c", ""))
    if challenge != expected_challenge:
        raise TokenError("challenge mismatch")

    difficulty = int(payload.get("d", 0))
    if difficulty <= 0:
        raise TokenError("invalid challenge difficulty")

    # solve_ms is client-reported and therefore untrusted; never fail only because
    # a modern CPU solved quickly. Keep an upper-bound timeout guard.
    if solve_ms > max_solve_seconds * 1000:
        raise TokenError("solve time exceeded maximum")

    expected_hash = compute_pow_hash(expected_challenge, nonce)
    if submitted_hash.lower() != expected_hash:
        raise TokenError("pow hash mismatch")

    required_prefix = "0" * difficulty
    if not expected_hash.startswith(required_prefix):
        raise TokenError("pow difficulty target not met")

    return PowSolutionResult(
        challenge_id=str(payload.get("jti", "")),
        difficulty=difficulty,
        issued_at=int(payload.get("iat", 0)),
        solved_at=now,
    )


def score_gate_environment(report: Mapping[str, Any], request_user_agent: str | None = None) -> tuple[int, list[str], bool]:
    score = 0
    reasons: list[str] = []
    hard_fail = False

    ua = (request_user_agent or "").lower()

    webdriver = bool(report.get("webdriver", False))
    if webdriver:
        hard_fail = True
        reasons.append("env:webdriver_true")

    chrome_obj = bool(report.get("chrome_obj", False))
    if "chrome" in ua and not chrome_obj:
        score -= 30
        reasons.append("env:missing_window_chrome")

    plugins_count = int(report.get("plugins_count", 0) or 0)
    if plugins_count < 1:
        score -= 15
        reasons.append("env:no_plugins")

    languages = report.get("languages", [])
    if not isinstance(languages, list):
        languages = []
    if len(languages) < 2:
        score -= 10
        reasons.append("env:low_language_count")

    notification_api = bool(report.get("notification_api", False))
    if not notification_api:
        score -= 10
        reasons.append("env:notification_api_missing")

    perf_memory = bool(report.get("perf_memory", False))
    if "chrome" in ua and not perf_memory:
        score -= 10
        reasons.append("env:performance_memory_missing")

    viewport = report.get("viewport", [0, 0])
    width, height = 0, 0
    if isinstance(viewport, list) and len(viewport) >= 2:
        try:
            width, height = int(viewport[0]), int(viewport[1])
        except (TypeError, ValueError):
            width, height = 0, 0

    if width <= 0 or height <= 0 or (width == 800 and height == 600):
        score -= 15
        reasons.append("env:viewport_suspicious")

    renderer = str(report.get("renderer", "")).lower()
    bad_renderer_markers = ("none", "swiftshader", "llvmpipe", "error")
    if not renderer or any(marker in renderer for marker in bad_renderer_markers):
        score -= 20
        reasons.append("env:webgl_renderer_suspicious")

    return score, reasons, hard_fail


def issue_gate_token(
    *,
    secret: str,
    session_id: str,
    ip_hash: str,
    solved_difficulty: int,
    env_score: int,
    ttl_seconds: int,
) -> str:
    now = now_ts()
    payload = {
        "t": "gate",
        "sid": session_id,
        "iph": ip_hash,
        "diff": int(solved_difficulty),
        "env": int(env_score),
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return sign_json(payload, secret)


def verify_gate_token(
    *,
    token: str,
    secret: str,
    current_ip_hash: str,
    now: int | None = None,
) -> dict[str, Any]:
    if now is None:
        now = now_ts()

    payload = verify_json(token, secret)
    if payload.get("t") != "gate":
        raise TokenError("wrong token type")
    if payload.get("iph") != current_ip_hash:
        raise TokenError("IP changed since gate was passed")
    if int(payload.get("exp", 0)) < now:
        raise TokenError("gate token expired")

    return payload


def issue_proof_token(
    *,
    secret: str,
    session_id: str,
    ip_hash: str,
    page_path: str,
    ttl_seconds: int,
) -> tuple[str, str]:
    now = now_ts()
    nonce = uuid.uuid4().hex
    payload = {
        "t": "proof",
        "sid": session_id,
        "iph": ip_hash,
        "path": page_path,
        "nonce": nonce,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return sign_json(payload, secret), nonce


def verify_proof_token(
    *,
    token: str,
    secret: str,
    session_id: str,
    ip_hash: str,
    page_path: str,
    nonce: str,
    now: int | None = None,
) -> dict[str, str | int]:
    if now is None:
        now = now_ts()

    payload = verify_json(token, secret)
    if payload.get("t") != "proof":
        raise TokenError("wrong token type")
    if payload.get("sid") != session_id:
        raise TokenError("session mismatch")
    if payload.get("iph") != ip_hash:
        raise TokenError("ip hash mismatch")
    if payload.get("path") != page_path:
        raise TokenError("path mismatch")
    if payload.get("nonce") != nonce:
        raise TokenError("nonce mismatch")
    if int(payload.get("exp", 0)) < now:
        raise TokenError("proof token expired")

    return payload
