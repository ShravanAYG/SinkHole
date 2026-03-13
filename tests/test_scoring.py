from __future__ import annotations

from botwall.models import BeaconEvent
from botwall.scoring import apply_score, decide, score_beacon, score_request, score_traversal, sequence_quality


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


def test_traversal_penalty_and_bonus_are_applied() -> None:
    s = _session()
    bad = score_traversal(s, valid=False)
    good = score_traversal(s, valid=True)
    assert bad.delta < 0
    assert good.delta > 0


def test_sequence_quality_penalizes_uniform_dwell_pattern() -> None:
    s = _session()
    s["events"] = [
        {
            "dwell_ms": 1000,
            "max_scroll_depth": 50,
            "trap_hits": 0,
            "pointer_moves": 10,
            "pointer_entropy": 1.0,
            "page_history": ["/", "/a"],
        },
        {
            "dwell_ms": 1002,
            "max_scroll_depth": 60,
            "trap_hits": 0,
            "pointer_moves": 11,
            "pointer_entropy": 1.1,
            "page_history": ["/a", "/b"],
        },
        {
            "dwell_ms": 998,
            "max_scroll_depth": 65,
            "trap_hits": 0,
            "pointer_moves": 9,
            "pointer_entropy": 1.2,
            "page_history": ["/b", "/c"],
        },
    ]
    q = sequence_quality(s, window=16)
    assert q < 8
