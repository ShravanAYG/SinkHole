#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import re
import signal
import subprocess
import sys
import time
from urllib.parse import quote
from typing import Any

import httpx


def wait_until_up(base_url: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            resp = httpx.get(f"{base_url}/healthz", timeout=1.0)
            if resp.status_code == 200:
                return
        except Exception as exc:  # pragma: no cover
            last_err = exc
        time.sleep(0.2)
    raise RuntimeError(f"Server did not become ready at {base_url}: {last_err}")


def extract_token_nonce(html: str) -> tuple[str, str]:
    token = re.search(r'const token = "([^"]+)";', html)
    nonce = re.search(r'const nonce = "([^"]+)";', html)
    if not token or not nonce:
        raise RuntimeError("Could not extract token/nonce from challenge page")
    return token.group(1), nonce.group(1)


def _extract_const(page_html: str, name: str) -> str:
    pattern = rf"const\s+{re.escape(name)}\s*=\s*(.+?);"
    match = re.search(pattern, page_html)
    if not match:
        raise RuntimeError(f"Could not extract JS constant '{name}' from gate page")
    value = match.group(1).strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def extract_gate_payload(page_html: str) -> tuple[str, str, int]:
    challenge_token = _extract_const(page_html, "CHALLENGE_TOKEN")
    challenge = _extract_const(page_html, "CHALLENGE")
    difficulty_raw = _extract_const(page_html, "DIFFICULTY")
    try:
        difficulty = int(difficulty_raw)
    except ValueError as exc:
        raise RuntimeError(f"Invalid gate difficulty '{difficulty_raw}'") from exc
    return challenge_token, challenge, difficulty


def solve_pow(challenge: str, difficulty: int) -> tuple[str, str]:
    target = "0" * int(difficulty)
    nonce = 0
    while True:
        hex_nonce = format(nonce, "x")
        digest = hashlib.sha256((challenge + hex_nonce).encode("utf-8")).hexdigest()
        if digest.startswith(target):
            return hex_nonce, digest
        nonce += 1


def assert_true(cond: bool, msg: str) -> None:
    if not cond:
        raise RuntimeError(msg)


def browser_beacon(session_id: str, nonce: str, page_path: str, ua: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "session_id": session_id,
        "nonce": nonce,
        "page_path": page_path,
        "pointer_moves": 45,
        "scroll_events": 9,
        "max_scroll_depth": 340,
        "visibility_changes": 1,
        "focus_events": 2,
        "blur_events": 1,
        "trap_hits": 0,
        "trap_ids": [],
        "copy_events": 0,
        "key_events": 2,
        "screenshot_combo_hits": 0,
        "dwell_ms": 2400,
        "event_loop_jitter": 0.2,
        "pointer_entropy": 1.3,
        "canvas_frame_ms": [1.1, 1.3, 1.4, 1.2],
        "webgl_frame_ms": [0.9, 1.0, 1.1, 1.0],
        "user_agent": ua,
        "platform": "Linux x86_64",
        "ua_data": {"platform": "Linux"},
    }


def gate_env() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "webdriver": False,
        "chrome_obj": True,
        "plugins_count": 3,
        "languages": ["en-US", "en"],
        "viewport": [1366, 768],
        "notification_api": True,
        "perf_memory": True,
        "touch_support": False,
        "device_pixel_ratio": 1.0,
        "timezone": "America/New_York",
        "renderer": "ANGLE (NVIDIA)",
    }


def pass_gate(client: httpx.Client, return_to: str = "/") -> None:
    gate_page = client.get(f"/bw/gate/challenge?path={quote(return_to, safe='/')}")
    assert_true(gate_page.status_code == 200, f"Expected gate challenge 200, got {gate_page.status_code}")
    challenge_token, challenge, difficulty = extract_gate_payload(gate_page.text)
    sid = client.cookies.get("bw_sid")
    assert_true(bool(sid), "Expected bw_sid cookie on gate challenge")

    t0 = time.perf_counter()
    nonce, digest = solve_pow(challenge, difficulty)
    solve_ms = int((time.perf_counter() - t0) * 1000)
    if solve_ms < 60:
        # Server rejects unrealistically fast solves.
        time.sleep((60 - solve_ms) / 1000.0)
        solve_ms = 60

    verify_payload = {
        "schema_version": "1.0",
        "session_id": sid,
        "challenge_token": challenge_token,
        "challenge": challenge,
        "nonce": nonce,
        "hash": digest,
        "solve_ms": solve_ms,
        "return_to": return_to,
        "env": gate_env(),
    }
    verify = client.post("/bw/gate/verify", json=verify_payload)
    assert_true(verify.status_code == 200, f"Expected gate verify 200, got {verify.status_code}")
    assert_true(verify.json().get("decision") == "allow", "Expected gate decision=allow")
    assert_true(bool(client.cookies.get("bw_gate")), "Expected bw_gate cookie after verification")


def run_validation(base_url: str) -> None:
    browser_headers = {
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "accept-language": "en-US,en;q=0.9",
        "x-ja3": "ja3-browser",
    }

    browser = httpx.Client(base_url=base_url, headers=browser_headers, follow_redirects=False, timeout=5.0)

    pass_gate(browser, "/")

    r1 = browser.get("/")
    assert_true(r1.status_code == 200, f"Expected 200 on browser hit after gate, got {r1.status_code}")
    assert_true(r1.headers.get("x-botwall-decision") in {"observe", "allow"}, "Expected observe/allow after gate")

    r2 = browser.get("/content/1")
    assert_true(r2.status_code == 302, f"Expected challenge redirect, got {r2.status_code}")
    assert_true(r2.headers.get("location", "").startswith("/bw/challenge"), "Expected /bw/challenge redirect")

    challenge = browser.get(r2.headers["location"])
    token, nonce = extract_token_nonce(challenge.text)
    sid = browser.cookies.get("bw_sid")
    assert_true(bool(sid), "Session cookie bw_sid missing")

    proof_payload = {
        "schema_version": "1.0",
        "session_id": sid,
        "token": token,
        "page_path": "/content/1",
        "nonce": nonce,
        "beacon": browser_beacon(sid, nonce, "/content/1", browser_headers["user-agent"]),
    }
    proof = browser.post("/bw/proof", json=proof_payload)
    assert_true(proof.status_code == 202, f"Expected proof status 202, got {proof.status_code}")
    assert_true(proof.json().get("decision") in {"allow", "observe"}, "Expected allow/observe after valid proof")

    after = browser.get("/")
    assert_true(after.status_code == 200, "Expected 200 after proof")
    assert_true(after.headers.get("x-botwall-decision") in {"allow", "observe"}, "Expected allow/observe after proof")

    headless = httpx.Client(
        base_url=base_url,
        headers={"user-agent": "HeadlessChrome/120.0", "x-ip-reputation": "bad"},
        follow_redirects=False,
        timeout=5.0,
    )

    pass_gate(headless, "/")

    decoy_seen = False
    for _ in range(5):
        h = headless.get("/")
        assert_true(h.status_code == 302, f"Expected headless redirect, got {h.status_code}")
        loc = h.headers.get("location", "")
        if loc.startswith("/bw/decoy/"):
            decoy_seen = True
            break
        assert_true(loc.startswith("/bw/challenge"), f"Expected challenge/decoy redirect, got {loc}")
    assert_true(decoy_seen, "Expected decoy redirect for suspicious headless session")

    rec_start = headless.post("/bw/recovery/start", json={"reason": "false_positive"})
    assert_true(rec_start.status_code == 202, "Expected recovery start 202")
    rec_token = rec_start.json()["recovery_token"]
    rec_sid = headless.cookies.get("bw_sid")

    rec_complete = headless.post(
        "/bw/recovery/complete",
        json={
            "session_id": rec_sid,
            "recovery_token": rec_token,
            "acknowledgement": "I am human and need real content",
        },
    )
    assert_true(rec_complete.status_code == 202, "Expected recovery complete 202")

    export_resp = browser.get("/telemetry/feed/export")
    assert_true(export_resp.status_code == 200, "Expected telemetry export 200")
    payload = export_resp.json()
    assert_true("fingerprints" in payload, "Telemetry export missing fingerprints")

    import_resp = browser.post("/telemetry/feed/import", json=payload)
    assert_true(import_resp.status_code == 200, "Expected telemetry import 200")

    print("[OK] Stage-1 gate PoW + cookie issuance")
    print("[OK] Browser flow: challenge -> proof -> allow/observe")
    print("[OK] Headless flow: challenge/decoy escalation + recovery")
    print("[OK] Telemetry export/import")


def main() -> int:
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    host = "127.0.0.1"
    port = int(os.environ.get("BOTWALL_VALIDATION_PORT", "4010"))
    base_url = f"http://{host}:{port}"

    env = os.environ.copy()
    env["BOTWALL_HOST"] = host
    env["BOTWALL_PORT"] = str(port)

    proc = subprocess.Popen(
        [sys.executable, "-m", "botwall"],
        cwd=repo,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    err: Exception | None = None
    server_output = ""
    try:
        wait_until_up(base_url)
        run_validation(base_url)
    except Exception as exc:
        err = exc
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        if proc.stdout is not None:
            server_output = proc.stdout.read() or ""

    if err is not None:
        print(f"[FAIL] {err}")
        if server_output:
            print("--- server output ---")
            print(server_output[-4000:])
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
