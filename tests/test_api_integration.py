from __future__ import annotations

import re

from fastapi.testclient import TestClient

from botwall.app import create_app
from botwall.config import Settings


def build_client() -> TestClient:
    settings = Settings(
        app_host="127.0.0.1",
        app_port=4000,
        session_cookie="bw_sid",
        gate_cookie="bw_gate",
        secret_key="test-secret",
        telemetry_secret="telemetry-secret",
        redis_enabled=False,
        telemetry_enabled=True,
        proof_ttl_seconds=60,
        traversal_ttl_seconds=300,
        recovery_ttl_seconds=180,
        recovery_allow_seconds=300,
        gate_ttl_seconds=86400,
        sequence_window=16,
        allow_threshold=30.0,
        decoy_threshold=-80.0,
        observe_threshold=-35.0,
        pow_default_difficulty=5,
        pow_elevated_difficulty=7,
        pow_max_solve_seconds=30,
        decoy_max_nodes=80,
        decoy_min_links=4,
        decoy_max_links=6,
        peer_secrets_raw="",
    )
    return TestClient(create_app(settings))


def _extract_token_nonce(html: str) -> tuple[str, str]:
    token_match = re.search(r"const token = \"([^\"]+)\";", html)
    nonce_match = re.search(r"const nonce = \"([^\"]+)\";", html)
    assert token_match, "token not found"
    assert nonce_match, "nonce not found"
    return token_match.group(1), nonce_match.group(1)


def test_browser_flow_observe_challenge_proof_allow() -> None:
    client = build_client()
    headers = {
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "accept-language": "en-US,en;q=0.9",
        "x-ja3": "ja3-browser",
    }

    first = client.get("/", headers=headers)
    assert first.status_code == 200
    assert first.headers.get("x-botwall-decision") == "observe"

    second = client.get("/content/1", headers=headers, follow_redirects=False)
    assert second.status_code == 302
    assert second.headers["location"].startswith("/bw/challenge")

    challenge = client.get(second.headers["location"], headers=headers)
    token, nonce = _extract_token_nonce(challenge.text)

    proof_payload = {
        "schema_version": "1.0",
        "session_id": client.cookies.get("bw_sid"),
        "token": token,
        "page_path": "/content/1",
        "nonce": nonce,
        "beacon": {
            "schema_version": "1.0",
            "session_id": client.cookies.get("bw_sid"),
            "nonce": nonce,
            "page_path": "/content/1",
            "pointer_moves": 40,
            "scroll_events": 8,
            "max_scroll_depth": 320,
            "visibility_changes": 1,
            "focus_events": 2,
            "blur_events": 1,
            "trap_hits": 0,
            "trap_ids": [],
            "copy_events": 0,
            "key_events": 2,
            "screenshot_combo_hits": 0,
            "dwell_ms": 2400,
            "event_loop_jitter": 0.1,
            "pointer_entropy": 1.2,
            "canvas_frame_ms": [1.1, 1.4, 1.2, 1.3],
            "webgl_frame_ms": [0.9, 1.0, 1.1, 1.2],
            "user_agent": headers["user-agent"],
            "platform": "Linux x86_64",
            "ua_data": {"platform": "Linux"},
        },
    }

    proof = client.post("/bw/proof", json=proof_payload, headers=headers)
    assert proof.status_code == 202
    assert proof.json()["decision"] == "allow"

    replay = client.post("/bw/proof", json=proof_payload, headers=headers)
    assert replay.status_code == 409

    after = client.get("/", headers=headers)
    assert after.status_code == 200
    assert after.headers.get("x-botwall-decision") == "allow"


def test_headless_downgrades_to_decoy_and_recovery_works() -> None:
    client = build_client()
    headers = {
        "user-agent": "HeadlessChrome/120.0",
        "x-ip-reputation": "bad",
    }

    first = client.get("/", headers=headers, follow_redirects=False)
    assert first.status_code == 302
    assert first.headers["location"].startswith("/bw/decoy/")

    start = client.post("/bw/recovery/start", json={"reason": "false_positive"})
    assert start.status_code == 202
    token = start.json()["recovery_token"]

    complete = client.post(
        "/bw/recovery/complete",
        json={
            "session_id": client.cookies.get("bw_sid"),
            "recovery_token": token,
            "acknowledgement": "I am human and need real content",
        },
    )
    assert complete.status_code == 202
    assert complete.json()["decision"] == "allow"

    final = client.get("/", headers=headers)
    assert final.status_code == 200
    assert final.headers.get("x-botwall-decision") == "allow"


def test_invalid_proof_and_telemetry_signature_rejected() -> None:
    client = build_client()

    bad = client.post(
        "/bw/proof",
        json={
            "schema_version": "1.0",
            "session_id": "abc",
            "token": "invalid.token",
            "page_path": "/",
            "nonce": "n",
            "beacon": {"schema_version": "1.0", "session_id": "abc"},
        },
    )
    assert bad.status_code == 400

    beacon_payload = {
        "schema_version": "1.0",
        "session_id": "telemetry-sid",
        "pointer_moves": 1,
        "scroll_events": 1,
        "max_scroll_depth": 10,
        "visibility_changes": 0,
        "focus_events": 0,
        "blur_events": 0,
        "trap_hits": 1,
        "trap_ids": ["shadow-click"],
        "copy_events": 0,
        "key_events": 1,
        "screenshot_combo_hits": 0,
        "dwell_ms": 150,
        "event_loop_jitter": 0,
        "pointer_entropy": 0.0,
        "canvas_frame_ms": [0.0, 0.0],
        "webgl_frame_ms": [0.0, 0.0],
        "user_agent": "HeadlessChrome",
        "platform": "Linux",
        "ua_data": {},
    }
    ping = client.post("/api/v1/analytics-ping", json=beacon_payload)
    assert ping.status_code == 202

    exported = client.get("/telemetry/feed/export")
    assert exported.status_code == 200
    payload = exported.json()
    assert payload["fingerprints"]

    payload["signature"] = "bad-signature"
    imp_bad = client.post("/telemetry/feed/import", json=payload)
    assert imp_bad.status_code == 400

    payload = exported.json()
    imp_ok = client.post("/telemetry/feed/import", json=payload)
    assert imp_ok.status_code == 200
    assert imp_ok.json()["imported"] >= 1
