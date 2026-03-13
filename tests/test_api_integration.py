from __future__ import annotations

import hashlib
import os
import re
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from urllib.parse import quote

import httpx
import pytest


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_until_up(base_url: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(f"{base_url}/healthz", timeout=1.0)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"server not ready at {base_url}")


def _extract_const(page_html: str, name: str) -> str:
    match = re.search(rf"const\s+{re.escape(name)}\s*=\s*(.+?);", page_html)
    if not match:
        raise RuntimeError(f"missing JS const {name}")
    value = match.group(1).strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def _solve_pow(challenge: str, difficulty: int) -> tuple[str, str]:
    target = "0" * difficulty
    nonce = 0
    while True:
        hex_nonce = format(nonce, "x")
        digest = hashlib.sha256((challenge + hex_nonce).encode("utf-8")).hexdigest()
        if digest.startswith(target):
            return hex_nonce, digest
        nonce += 1


def _pass_gate(client: httpx.Client, return_to: str = "/") -> None:
    gate_page = client.get(f"/bw/gate/challenge?path={quote(return_to, safe='/?=&')}")
    assert gate_page.status_code == 200

    sid = client.cookies.get("bw_sid")
    assert sid

    # Simulate successful browser JS verification checks
    payload = {
        "session_id": sid,
        "return_path": return_to,
        "checks": {
            "passed": 10,
            "failed": 0,
            "details": [
                "window_ok", "navigator_ok", "no_webdriver", "screen_ok", 
                "document_ok", "window_dims_ok", "plugins_ok:3", "canvas_ok",
                "hardware_renderer_ok", "no_automation_vars", "no_stealth_plugin"
            ]
        },
        "timestamp": int(time.time() * 1000)
    }
    
    verify = client.post("/bw/js-verify", json=payload)
    assert verify.status_code == 200
    assert verify.json().get("decision") == "allow"
    assert client.cookies.get("bw_gate")


def _submit_stage2_proof(client: httpx.Client, challenge_location: str, ua: str) -> tuple[httpx.Response, dict]:
    challenge_page = client.get(challenge_location)
    assert challenge_page.status_code == 200
    token = _extract_const(challenge_page.text, "token")
    nonce = _extract_const(challenge_page.text, "nonce")
    target_path = _extract_const(challenge_page.text, "targetPath")
    sid = client.cookies.get("bw_sid")
    assert sid

    payload = {
        "schema_version": "1.0",
        "session_id": sid,
        "token": token,
        "page_path": target_path,
        "nonce": nonce,
        "beacon": {
            "schema_version": "1.0",
            "session_id": sid,
            "nonce": nonce,
            "page_path": target_path,
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
            "user_agent": ua,
            "platform": "Linux x86_64",
            "ua_data": {"platform": "Linux"},
        },
    }
    proof = client.post("/bw/proof", json=payload)
    assert proof.status_code == 202
    return proof, payload


@pytest.fixture(scope="module")
def live_base_url() -> Iterator[str]:
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    port = _free_port()
    host = "127.0.0.1"
    base_url = f"http://{host}:{port}"
    env = os.environ.copy()
    env["BOTWALL_HOST"] = host
    env["BOTWALL_PORT"] = str(port)
    env["BOTWALL_SECRET_KEY"] = "test-secret"
    env["BOTWALL_TELEMETRY_SECRET"] = "telemetry-secret"
    env["BOTWALL_POW_DIFFICULTY"] = "2"
    env["BOTWALL_POW_ELEVATED_DIFFICULTY"] = "3"
    env["BOTWALL_REDIS_ENABLED"] = "0"

    proc = subprocess.Popen(
        [sys.executable, "-m", "botwall"],
        cwd=repo,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_until_up(base_url)
        yield base_url
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def test_browser_flow_gate_challenge_proof_and_telemetry(live_base_url: str) -> None:
    headers = {
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "accept-language": "en-US,en;q=0.9",
        "x-ja3": "ja3-browser",
    }
    client = httpx.Client(base_url=live_base_url, headers=headers, follow_redirects=False, timeout=8.0)

    first = client.get("/")
    assert first.status_code == 302
    assert first.headers.get("location", "").startswith("/bw/gate/challenge")

    _pass_gate(client, "/")

    home = client.get("/")
    assert home.status_code == 200
    assert home.headers.get("x-botwall-decision") in {"observe", "allow"}

    gate_check = client.get("/bw/gate/check")
    assert gate_check.status_code == 200
    assert gate_check.json().get("ok") is True

    second = client.get("/content/1")
    assert second.status_code == 302
    assert second.headers["location"].startswith("/bw/challenge")

    proof, proof_payload = _submit_stage2_proof(client, second.headers["location"], headers["user-agent"])
    assert proof.json()["decision"] in {"allow", "observe"}

    replay = client.post("/bw/proof", json=proof_payload)
    assert replay.status_code == 409

    exported = client.get("/telemetry/feed/export")
    assert exported.status_code == 200
    payload = exported.json()
    assert "fingerprints" in payload

    payload["signature"] = "bad-signature"
    imp_bad = client.post("/telemetry/feed/import", json=payload)
    assert imp_bad.status_code == 400

    payload = exported.json()
    imp_ok = client.post("/telemetry/feed/import", json=payload)
    assert imp_ok.status_code == 200
    assert imp_ok.json()["imported"] >= 0


def test_gate_verify_replay_and_tamper_rejected(live_base_url: str) -> None:
    headers = {
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "accept-language": "en-US,en;q=0.9",
    }
    client = httpx.Client(base_url=live_base_url, headers=headers, follow_redirects=False, timeout=8.0)

    gate_page = client.get("/bw/gate/challenge?path=/")
    assert gate_page.status_code == 200
    sid = client.cookies.get("bw_sid")
    assert sid

    payload = {
        "session_id": sid,
        "return_path": "/",
        "checks": {
            "passed": 10,
            "failed": 0,
            "details": [
                "window_ok", "navigator_ok", "no_webdriver", "screen_ok", 
                "document_ok", "window_dims_ok", "plugins_ok:3", "canvas_ok",
                "hardware_renderer_ok", "no_automation_vars", "no_stealth_plugin"
            ]
        },
        "timestamp": int(time.time() * 1000)
    }

    ok = client.post("/bw/js-verify", json=payload)
    assert ok.status_code == 200

    # Test tampering a failed check
    tampered = dict(payload)
    tampered["checks"]["failed"] = 5
    tampered["checks"]["passed"] = 1
    bad = client.post("/bw/js-verify", json=tampered)
    assert bad.status_code == 403


def test_explicit_scrapers_are_sent_to_decoy_before_gate(live_base_url: str) -> None:
    for ua in ["firecrawl/1.0", "my-custom-scraper", "HeadlessChrome/120.0"]:
        client = httpx.Client(
            base_url=live_base_url,
            headers={"user-agent": ua},
            follow_redirects=False,
            timeout=8.0,
        )
        response = client.get("/")
        assert response.status_code == 302
        assert "/bw/decoy/" in response.headers.get("location", "")


def test_headless_decoy_and_recovery(live_base_url: str) -> None:
    client = httpx.Client(
        base_url=live_base_url,
        headers={"user-agent": "HeadlessChrome/120.0", "x-ip-reputation": "bad"},
        follow_redirects=False,
        timeout=8.0,
    )

    first = client.get("/")
    assert first.status_code == 302
    assert first.headers.get("location", "").startswith("/bw/decoy/")

    start = client.post("/bw/recovery/start", json={"reason": "false_positive"})
    assert start.status_code == 202
    token = start.json()["recovery_token"]
    sid = client.cookies.get("bw_sid")
    complete = client.post(
        "/bw/recovery/complete",
        json={
            "session_id": sid,
            "recovery_token": token,
            "game_score": 52,
            "hits": 11,
            "misses": 4,
            "duration_ms": 10300,
        },
    )
    assert complete.status_code == 202
    assert complete.json()["decision"] == "allow"

    final = client.get("/")
    assert final.status_code == 200
