from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from typing import Any

from .models import BeaconEvent


@dataclass(slots=True)
class ScoreOutcome:
    delta: float
    reasons: list[str]


def _trim_reasons(session: dict[str, Any], max_reasons: int = 30) -> None:
    session["reasons"] = session.get("reasons", [])[-max_reasons:]


def _trim_request_times(session: dict[str, Any], now: int) -> None:
    times = session.get("request_times", [])
    session["request_times"] = [ts for ts in times if now - ts <= 20][-40:]


def score_request(meta: dict[str, Any], session: dict[str, Any], now: int | None = None) -> ScoreOutcome:
    if now is None:
        now = int(time.time())

    ua = (meta.get("user_agent") or "").lower()
    accept_lang = (meta.get("accept_language") or "").strip()
    ip_reputation = (meta.get("ip_reputation") or "unknown").lower()
    ja3 = (meta.get("ja3") or "").strip()

    reasons: list[str] = []
    delta = 0.0

    bot_markers = ["headless", "puppeteer", "playwright", "selenium", "phantomjs", "curl", "wget"]
    if any(marker in ua for marker in bot_markers):
        delta -= 45
        reasons.append("request:automation_ua_marker")
    elif "mozilla" in ua:
        delta += 4
        reasons.append("request:browser_like_ua")

    if not accept_lang:
        delta -= 10
        reasons.append("request:missing_accept_language")
    else:
        delta += 2

    if ip_reputation == "bad":
        delta -= 25
        reasons.append("request:ip_reputation_bad")
    elif ip_reputation == "good":
        delta += 6

    if "chrome" in ua and not ja3:
        delta -= 5
        reasons.append("request:missing_ja3_for_chrome")

    if session.get("session_id"):
        delta += 3

    session.setdefault("request_times", []).append(now)
    _trim_request_times(session, now)
    burst_10s = sum(1 for ts in session["request_times"] if now - ts <= 10)
    if burst_10s >= 10:
        delta -= 35
        reasons.append("request:extreme_burst")
    elif burst_10s >= 6:
        delta -= 15
        reasons.append("request:high_burst")

    return ScoreOutcome(delta=delta, reasons=reasons)


def _variance(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    return statistics.pvariance(values)


def score_beacon(beacon: BeaconEvent, request_ua: str | None = None) -> ScoreOutcome:
    reasons: list[str] = []
    delta = 0.0

    if beacon.trap_hits > 0:
        penalty = min(50, beacon.trap_hits * 25)
        delta -= penalty
        reasons.append("beacon:trap_hit")

    if beacon.max_scroll_depth >= 200 and beacon.dwell_ms >= 1500:
        delta += 12
        reasons.append("beacon:human_scroll_dwell")
    elif beacon.dwell_ms < 400:
        delta -= 8
        reasons.append("beacon:very_low_dwell")

    if 0.4 <= beacon.pointer_entropy <= 4.5:
        delta += 8
        reasons.append("beacon:pointer_entropy_ok")
    elif beacon.pointer_moves > 0:
        delta -= 6
        reasons.append("beacon:pointer_entropy_outlier")

    if beacon.visibility_changes > 0 and beacon.focus_events > 0:
        delta += 4
        reasons.append("beacon:focus_visibility_pattern")

    if beacon.screenshot_combo_hits > 0:
        delta -= 5
        reasons.append("beacon:screenshot_combo_hits")

    canvas_var = _variance(beacon.canvas_frame_ms)
    webgl_var = _variance(beacon.webgl_frame_ms)
    if beacon.canvas_frame_ms or beacon.webgl_frame_ms:
        if canvas_var + webgl_var < 0.01:
            delta -= 10
            reasons.append("beacon:render_variance_too_flat")
        else:
            delta += 6
            reasons.append("beacon:render_variance_present")

    if request_ua and beacon.user_agent:
        req = request_ua.lower()
        b_ua = beacon.user_agent.lower()
        if ("chrome" in req and "chrome" not in b_ua) or ("safari" in req and "safari" not in b_ua):
            delta -= 20
            reasons.append("beacon:ua_mismatch")

    return ScoreOutcome(delta=delta, reasons=reasons)


def apply_score(session: dict[str, Any], outcome: ScoreOutcome, now: int | None = None) -> None:
    if now is None:
        now = int(time.time())

    session["score"] = float(session.get("score", 0.0) + outcome.delta)
    reasons = session.setdefault("reasons", [])
    reasons.extend(outcome.reasons)
    _trim_reasons(session)
    session["updated_at"] = now


def score_traversal(session: dict[str, Any], valid: bool) -> ScoreOutcome:
    if valid:
        session["traversal_valid"] = int(session.get("traversal_valid", 0)) + 1
        return ScoreOutcome(delta=10.0, reasons=["traversal:valid"])

    session["traversal_invalid"] = int(session.get("traversal_invalid", 0)) + 1
    return ScoreOutcome(delta=-10.0, reasons=["traversal:invalid"])


def score_telemetry_match(session: dict[str, Any], suspicion: float) -> ScoreOutcome:
    session["telemetry_hits"] = int(session.get("telemetry_hits", 0)) + 1
    return ScoreOutcome(delta=-abs(suspicion), reasons=["telemetry:mesh_match"])


def sequence_quality(session: dict[str, Any], window: int) -> float:
    events = session.get("events", [])[-window:]
    if not events:
        return -10.0

    dwell_values = [int(e.get("dwell_ms", 0)) for e in events]
    scroll_depths = [int(e.get("max_scroll_depth", 0)) for e in events]
    trap_hits = sum(int(e.get("trap_hits", 0)) for e in events)
    pointer_entropy = [float(e.get("pointer_entropy", 0.0)) for e in events if e.get("pointer_moves", 0) > 0]

    quality = 0.0
    if statistics.mean(dwell_values) >= 900:
        quality += 8.0
    if max(scroll_depths, default=0) >= 200:
        quality += 7.0
    if pointer_entropy and 0.4 <= statistics.mean(pointer_entropy) <= 4.5:
        quality += 6.0
    if trap_hits > 0:
        quality -= 20.0

    return quality


def decide(session: dict[str, Any], sequence_window: int, now: int | None = None) -> tuple[str, list[str]]:
    if now is None:
        now = int(time.time())

    if int(session.get("allow_until", 0)) > now:
        return "allow", ["recovery:temporary_allow"]

    score = float(session.get("score", 0.0))
    request_count = len(session.get("request_times", []))
    proof_valid = int(session.get("proof_valid", 0))
    challenges = int(session.get("challenge_issued", 0))
    seq_q = sequence_quality(session, sequence_window)

    reasons: list[str] = [f"sequence_quality:{seq_q:.1f}"]

    if score <= -80:
        reasons.append("decision:hard_decoy_threshold")
        return "decoy", reasons

    if proof_valid == 0:
        if request_count <= 1 and score > -35:
            reasons.append("decision:observe_first_touch")
            return "observe", reasons
        if score <= -50 or challenges >= 2:
            reasons.append("decision:decoy_after_failed_proof")
            return "decoy", reasons
        reasons.append("decision:require_challenge")
        return "challenge", reasons

    # proof exists; require sequence, not a single request
    if score + seq_q >= 30 and len(session.get("events", [])) >= 1 and request_count >= 2:
        reasons.append("decision:allow_confident_sequence")
        return "allow", reasons

    if score <= -50:
        reasons.append("decision:decoy_low_post_proof")
        return "decoy", reasons

    reasons.append("decision:observe_more_sequence")
    return "observe", reasons
