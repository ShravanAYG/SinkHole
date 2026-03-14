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
    """
    Score environment report from gate challenge.
    Returns: (score_delta, reasons, hard_fail)
    
    Hardened against stealth browsers (Firecrawl, Puppeteer-stealth, etc.)
    """
    score = 0
    reasons: list[str] = []
    hard_fail = False

    # === ABSOLUTE HARD FAILS (cannot be bypassed by stealth) ===
    
    # CDP detection - Chrome DevTools Protocol leaves traces
    if report.get("cdp_detected"):
        hard_fail = True
        reasons.append("env:cdp_detected_hard_fail")
        return score, reasons, hard_fail
        
    # Webdriver detection
    if report.get("webdriver"):
        hard_fail = True
        reasons.append("env:webdriver_true")
        return score, reasons, hard_fail
    
    # Automation globals that stealth plugins sometimes miss
    js_globals = report.get("js_globals", [])
    high_confidence_automation = [
        "cdc_adoQpoasnfa76pfcZLmcfl_", "__webdriver_script_fn", "domAutomation",
        "__playwright", "__pw_manual", "__PW_EVALUATE",  # Playwright/Firecrawl
    ]
    for g in js_globals:
        if any(h in g for h in high_confidence_automation):
            hard_fail = True
            reasons.append(f"env:automation_global_hard_fail:{g}")
            return score, reasons, hard_fail
    
    # Container/cloud runtime detection
    container_indicators = report.get("container_indicators", [])
    if len(container_indicators) >= 3:
        hard_fail = True
        reasons.append("env:container_runtime_detected")
        return score, reasons, hard_fail
    
    # Unnatural solve speed (impossible for humans)
    solve_time_ms = report.get("solve_time_ms", 0)
    if solve_time_ms > 0 and solve_time_ms < 400:  # Sub-400ms is definitely automated
        score -= 50
        reasons.append("env:impossible_solve_speed")
        hard_fail = True
        return score, reasons, hard_fail
    elif solve_time_ms > 0 and solve_time_ms < 800:
        score -= 35
        reasons.append("env:suspicious_solve_speed")

    # === HIGH CONFIDENCE SIGNALS (heavy penalties) ===
    
    # Automation score from client-side analysis
    automation_score = report.get("automation_score", 0)
    if automation_score >= 60:
        score -= 50
        reasons.append(f"env:high_automation_score:{automation_score}")
        hard_fail = True
    elif automation_score >= 40:
        score -= 35
        reasons.append(f"env:elevated_automation_score:{automation_score}")
    elif automation_score >= 20:
        score -= 20
        reasons.append(f"env:moderate_automation_score:{automation_score}")
    
    # Hardware concurrency checks (servers often have high core counts)
    hw_concurrency = report.get("hardware_concurrency", 0)
    if hw_concurrency == 0:
        score -= 15
        reasons.append("env:no_hardware_concurrency")
    elif hw_concurrency >= 32:  # Unlikely for consumer devices
        score -= 20
        reasons.append(f"env:suspicious_core_count:{hw_concurrency}")
    
    # Device memory (servers often have high RAM)
    device_memory = report.get("device_memory", 0)
    if device_memory == 0:
        score -= 10
        reasons.append("env:no_device_memory")
    elif device_memory >= 32:  # 32GB+ is uncommon for browsing
        score -= 15
        reasons.append(f"env:suspicious_memory:{device_memory}gb")
    
    # Screen dimensions consistency
    viewport = report.get("viewport", [0, 0])
    screen_avail = [report.get("screen_avail_width", 0), report.get("screen_avail_height", 0)]
    if viewport[0] > 0 and screen_avail[0] > 0:
        # Viewport should never exceed screen available
        if viewport[0] > screen_avail[0] or viewport[1] > screen_avail[1]:
            score -= 25
            reasons.append("env:viewport_exceeds_screen")
        score -= 15
        reasons.append("env:viewport_suspicious")

    renderer = str(report.get("renderer", "")).lower()
    bad_renderer_markers = ("none", "swiftshader", "llvmpipe", "error")
    if not renderer or any(marker in renderer for marker in bad_renderer_markers):
        score -= 20
        reasons.append("env:webgl_renderer_suspicious")

    # 8. Timing analysis - advanced crawlers often solve challenges too quickly/consistent
    solve_time_ms = int(report.get("solve_time_ms", 0))
    if solve_time_ms > 0 and solve_time_ms < 500:  # Unnaturally fast solve
        score -= 25
        reasons.append("env:unnatural_solve_speed")
    
    # 9. Screen/monitor detection - cloud browsers often have odd display configs
    screen_avail_width = int(report.get("screen_avail_width", 0))
    screen_avail_height = int(report.get("screen_avail_height", 0))
    if screen_avail_width > 0 and screen_avail_height > 0:
        # Check for headless common sizes
        if (screen_avail_width, screen_avail_height) in [(800, 600), (1024, 768), (1280, 720), (1920, 1080)]:
            if report.get("device_pixel_ratio", 1) == 1:  # Often exactly 1 in headless
                score -= 10
                reasons.append("env:common_headless_resolution")
    
    # 10. Plugin detail analysis - headless often has generic plugin names
    plugins_detail = report.get("plugins_detail", [])
    if isinstance(plugins_detail, list) and len(plugins_detail) > 0:
        generic_names = ["Chrome PDF Plugin", "Native Client", "Widevine Content Decryption Module"]
        if all(p.get("name", "") in generic_names for p in plugins_detail[:3]):
            score -= 15
            reasons.append("env:generic_plugin_fingerprint")

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
