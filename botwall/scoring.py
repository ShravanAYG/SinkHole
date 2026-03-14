from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from typing import Any

from .config import ScoringWeights
from .models import BeaconEvent

# Default weights used when no config is passed (matches botwall.toml defaults).
_DEFAULT_WEIGHTS = ScoringWeights()


@dataclass(slots=True)
class ScoreOutcome:
    delta: float
    reasons: list[str]


def _trim_reasons(session: dict[str, Any], max_reasons: int = 30) -> None:
    session["reasons"] = session.get("reasons", [])[-max_reasons:]


def _trim_request_times(session: dict[str, Any], now: int) -> None:
    times = session.get("request_times", [])
    session["request_times"] = [ts for ts in times if now - ts <= 20][-40:]


def score_request(
    meta: dict[str, Any],
    session: dict[str, Any],
    now: int | None = None,
    weights: ScoringWeights = _DEFAULT_WEIGHTS,
) -> ScoreOutcome:
    if now is None:
        now = int(time.time())

    ua = (meta.get("user_agent") or "").lower()
    accept_lang = (meta.get("accept_language") or "").strip()
    ip_reputation = (meta.get("ip_reputation") or "unknown").lower()
    ja3 = (meta.get("ja3") or "").strip()

    reasons: list[str] = []
    delta = 0.0

    hard_bot_markers = ["curl", "wget", "python-requests", "python-urllib", "httpx", "aiohttp", "go-http-client", "libwww-perl", "scrapy", "headless"]
    bot_markers = ["puppeteer", "playwright", "selenium", "phantomjs"]
    if any(marker in ua for marker in hard_bot_markers):
        delta += weights.ua_bot_marker * 2
        reasons.append("request:hard_bot_ua_marker")
    elif any(marker in ua for marker in bot_markers):
        delta += weights.ua_bot_marker
        reasons.append("request:automation_ua_marker")
    elif "mozilla" in ua:
        delta += weights.ua_browser
        reasons.append("request:browser_like_ua")

    if not accept_lang:
        delta += weights.missing_accept_lang
        reasons.append("request:missing_accept_language")
    else:
        delta += 2

    if ip_reputation == "bad":
        delta += weights.ip_bad
        reasons.append("request:ip_reputation_bad")
    elif ip_reputation == "good":
        delta += weights.ip_good

    if "chrome" in ua and not ja3:
        delta += weights.missing_ja3
        reasons.append("request:missing_ja3_for_chrome")

    if session.get("session_id"):
        delta += weights.session_continuity

    session.setdefault("request_times", []).append(now)
    _trim_request_times(session, now)
    burst_10s = sum(1 for ts in session["request_times"] if now - ts <= 10)
    last_burst_penalty = int(session.get("burst_penalty_at", 0))
    if now - last_burst_penalty >= 10:
        if burst_10s >= 10:
            delta += weights.burst_extreme
            reasons.append("request:extreme_burst")
            session["burst_penalty_at"] = now
        elif burst_10s >= 6:
            delta += weights.burst_high
            reasons.append("request:high_burst")
            session["burst_penalty_at"] = now

    return ScoreOutcome(delta=delta, reasons=reasons)


def _variance(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    return statistics.pvariance(values)


def _platform_family(value: str) -> str:
    v = value.lower()
    if "windows" in v or "win" in v:
        return "windows"
    if "mac" in v or "darwin" in v:
        return "mac"
    if "linux" in v or "x11" in v:
        return "linux"
    if "android" in v:
        return "android"
    if "iphone" in v or "ipad" in v or "ios" in v:
        return "ios"
    return "unknown"


def score_beacon(
    beacon: BeaconEvent,
    request_ua: str | None = None,
    weights: ScoringWeights = _DEFAULT_WEIGHTS,
) -> ScoreOutcome:
    reasons: list[str] = []
    delta = 0.0

    if beacon.trap_hits > 0:
        # Cap trap penalty at -50 by default to avoid unbounded single-signal dominance.
        penalty = max(-50.0, beacon.trap_hits * weights.trap_hit_per_event)
        delta += penalty
        reasons.append("beacon:trap_hit")

    if beacon.max_scroll_depth >= 200 and beacon.dwell_ms >= 1500:
        delta += weights.scroll_dwell_human
        reasons.append("beacon:human_scroll_dwell")
    elif beacon.dwell_ms < 400:
        delta += weights.low_dwell
        reasons.append("beacon:very_low_dwell")

    if 0.4 <= beacon.pointer_entropy <= 4.5:
        delta += weights.entropy_ok
        reasons.append("beacon:pointer_entropy_ok")
    elif beacon.pointer_moves > 0:
        delta += weights.entropy_outlier
        reasons.append("beacon:pointer_entropy_outlier")

    if beacon.visibility_changes > 0 and beacon.focus_events > 0:
        delta += weights.focus_visibility
        reasons.append("beacon:focus_visibility_pattern")

    if beacon.screenshot_combo_hits > 0:
        delta += weights.screenshot_combo
        reasons.append("beacon:screenshot_combo_hits")

    canvas_var = _variance(beacon.canvas_frame_ms)
    webgl_var = _variance(beacon.webgl_frame_ms)
    if beacon.canvas_frame_ms or beacon.webgl_frame_ms:
        if canvas_var + webgl_var < 0.01:
            delta += weights.render_flat
            reasons.append("beacon:render_variance_too_flat")
        else:
            delta += weights.render_variance
            reasons.append("beacon:render_variance_present")

    if request_ua and beacon.user_agent:
        req = request_ua.lower()
        b_ua = beacon.user_agent.lower()
        if ("chrome" in req and "chrome" not in b_ua) or ("safari" in req and "safari" not in b_ua):
            delta += weights.ua_mismatch_tls_js
            reasons.append("beacon:ua_mismatch")

    if request_ua and beacon.platform:
        req_family = _platform_family(request_ua)
        platform_family = _platform_family(beacon.platform)
        if req_family != "unknown" and platform_family != "unknown" and req_family != platform_family:
            delta += weights.platform_mismatch
            reasons.append("beacon:platform_mismatch")

    # ua_data empty in a Chrome request → headless signal
    if beacon.ua_data == {} and request_ua and "chrome" in (request_ua or "").lower():
        delta += weights.ua_data_empty
        reasons.append("beacon:ua_data_empty_chrome")

    return ScoreOutcome(delta=delta, reasons=reasons)


def apply_score(session: dict[str, Any], outcome: ScoreOutcome, now: int | None = None) -> None:
    if now is None:
        now = int(time.time())
    session["score"] = float(session.get("score", 0.0) + outcome.delta)
    reasons = session.setdefault("reasons", [])
    reasons.extend(outcome.reasons)
    _trim_reasons(session)
    session["updated_at"] = now


def score_traversal(
    session: dict[str, Any],
    valid: bool,
    weights: ScoringWeights = _DEFAULT_WEIGHTS,
) -> ScoreOutcome:
    if valid:
        session["traversal_valid"] = int(session.get("traversal_valid", 0)) + 1
        return ScoreOutcome(delta=weights.traversal_valid, reasons=["traversal:valid"])
    session["traversal_invalid"] = int(session.get("traversal_invalid", 0)) + 1
    return ScoreOutcome(delta=weights.traversal_invalid, reasons=["traversal:invalid"])


def score_telemetry_match(session: dict[str, Any], suspicion: float) -> ScoreOutcome:
    session["telemetry_hits"] = int(session.get("telemetry_hits", 0)) + 1
    return ScoreOutcome(delta=-abs(suspicion), reasons=["telemetry:mesh_match"])


def sequence_quality(
    session: dict[str, Any],
    window: int,
    weights: ScoringWeights = _DEFAULT_WEIGHTS,
) -> float:
    events = session.get("events", [])[-window:]
    if not events:
        return -10.0

    dwell_values = [int(e.get("dwell_ms", 0)) for e in events]
    scroll_depths = [int(e.get("max_scroll_depth", 0)) for e in events]
    trap_hits = sum(int(e.get("trap_hits", 0)) for e in events)
    pointer_entropy = [float(e.get("pointer_entropy", 0.0)) for e in events if e.get("pointer_moves", 0) > 0]

    quality = 0.0

    mean_dwell = statistics.mean(dwell_values)
    if mean_dwell >= 900:
        quality += weights.seq_dwell_good

    # Linearity penalty: if all dwell times within 5% of mean → bot-uniform
    if len(dwell_values) >= 3 and mean_dwell > 0:
        max_deviation = max(abs(d - mean_dwell) / mean_dwell for d in dwell_values)
        if max_deviation < 0.05:
            quality += weights.seq_linearity_penalty
            # label goes into session reasons on next apply_score call

    if max(scroll_depths, default=0) >= 200:
        quality += weights.seq_scroll_good

    if pointer_entropy and 0.4 <= statistics.mean(pointer_entropy) <= 4.5:
        quality += weights.seq_entropy_good

    if trap_hits > 0:
        quality += weights.seq_trap_penalty

    # Backtrack bonus: if page_history shows a revisited page
    page_histories = [e.get("page_history", []) for e in events]
    all_pages: list[str] = []
    for ph in page_histories:
        all_pages.extend(ph)
    if len(all_pages) != len(set(all_pages)):
        quality += weights.seq_backtrack_bonus

    return quality


def decide(
    session: dict[str, Any],
    sequence_window: int,
    now: int | None = None,
    allow_threshold: float = 30.0,
    decoy_threshold: float = -80.0,
    observe_threshold: float = -35.0,
) -> tuple[str, list[str]]:
    if now is None:
        now = int(time.time())

    if int(session.get("allow_until", 0)) > now:
        return "allow", ["recovery:temporary_allow"]

    score = float(session.get("score", 0.0))
    request_count = len(session.get("request_times", []))
    proof_valid = int(session.get("proof_valid", 0))
    challenges = int(session.get("challenge_issued", 0))
    gate_passed = bool(session.get("js_verification_passed") or session.get("gate_passed_at"))
    seq_q = sequence_quality(session, sequence_window)

    reasons: list[str] = [f"sequence_quality:{seq_q:.1f}"]

    if score <= decoy_threshold:
        reasons.append("decision:hard_decoy_threshold")
        return "decoy", reasons

    if proof_valid == 0:
        # Gate-verified users: they passed JS PoW + env checks, treat as semi-trusted.
        # Only send to decoy if score is truly bad; never re-challenge.
        if gate_passed:
            if score <= -50:
                reasons.append("decision:decoy_post_gate_low_score")
                return "decoy", reasons
            reasons.append("decision:observe_gate_passed")
            return "observe", reasons

        if request_count <= 1 and score > observe_threshold:
            reasons.append("decision:observe_first_touch")
            return "observe", reasons
        if score <= -50 or challenges >= 2:
            reasons.append("decision:decoy_after_failed_proof")
            return "decoy", reasons
        reasons.append("decision:require_challenge")
        return "challenge", reasons

    # Proof exists — require sequence, not a single request.
    if score + seq_q >= allow_threshold and len(session.get("events", [])) >= 1 and request_count >= 2:
        reasons.append("decision:allow_confident_sequence")
        return "allow", reasons

    if score <= -50:
        reasons.append("decision:decoy_low_post_proof")
        return "decoy", reasons

    reasons.append("decision:observe_more_sequence")
    return "observe", reasons
