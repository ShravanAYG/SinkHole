from __future__ import annotations

from botwall.models import BeaconEvent
from botwall.scoring import apply_score, decide, score_beacon, score_request


def _session() -> dict:
    return {
        "score": 0.0,
        "request_times": [],
        "reasons": [],
        "events": [],
        "proof_valid": 0,
        "challenge_issued": 0,
        "allow_until": 0,
    }


def test_request_scoring_headless_penalized() -> None:
    s = _session()
    outcome = score_request(
        {
            "user_agent": "HeadlessChrome/120.0",
            "accept_language": "",
            "ip_reputation": "bad",
            "ja3": "",
        },
        s,
        now=100,
    )
    assert outcome.delta < -50


def test_request_scoring_browser_positive() -> None:
    s = _session()
    outcome = score_request(
        {
            "user_agent": "Mozilla/5.0 Chrome/120.0",
            "accept_language": "en-US,en;q=0.9",
            "ip_reputation": "good",
            "ja3": "abc",
        },
        s,
        now=100,
    )
    assert outcome.delta > 0


def test_sequence_requires_proof_then_allow() -> None:
    s = _session()
    req = score_request(
        {
            "user_agent": "Mozilla/5.0 Chrome/120.0",
            "accept_language": "en-US",
            "ip_reputation": "good",
            "ja3": "abc",
        },
        s,
        now=100,
    )
    apply_score(s, req, now=100)
    req2 = score_request(
        {
            "user_agent": "Mozilla/5.0 Chrome/120.0",
            "accept_language": "en-US",
            "ip_reputation": "good",
            "ja3": "abc",
        },
        s,
        now=101,
    )
    apply_score(s, req2, now=101)

    # Without proof, should not allow.
    decision, _ = decide(s, sequence_window=16, now=100)
    assert decision in {"observe", "challenge"}

    beacon = BeaconEvent(
        session_id="sid",
        pointer_moves=30,
        scroll_events=10,
        max_scroll_depth=340,
        focus_events=2,
        visibility_changes=1,
        dwell_ms=2400,
        pointer_entropy=1.2,
        canvas_frame_ms=[1.0, 1.2, 1.4, 1.1],
        webgl_frame_ms=[0.9, 1.1, 1.0, 1.3],
        user_agent="Mozilla/5.0 Chrome/120.0",
    )
    b = score_beacon(beacon, request_ua="Mozilla/5.0 Chrome/120.0")
    apply_score(s, b, now=102)
    s["events"].append(beacon.model_dump(mode="json"))
    s["proof_valid"] = 1

    decision, _ = decide(s, sequence_window=16, now=102)
    assert decision == "allow"
