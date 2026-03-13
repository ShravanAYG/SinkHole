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

import httpx


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def wait_until_up(base_url: str, path: str = "/healthz", timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            response = httpx.get(f"{base_url}{path}", timeout=1.5)
            if response.status_code == 200:
                return
        except Exception as exc:
            last_error = exc
        time.sleep(0.2)
    raise RuntimeError(f"{base_url}{path} not ready: {last_error}")


def _extract_const(page_html: str, name: str) -> str:
    match = re.search(rf"const\s+{re.escape(name)}\s*=\s*(.+?);", page_html)
    if not match:
        raise RuntimeError(f"Could not find JS constant {name}")
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


def _gate_env() -> dict[str, object]:
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


def submit_stage2_proof(client: httpx.Client, challenge_location: str, ua: str) -> None:
    challenge_page = client.get(challenge_location)
    assert_true(challenge_page.status_code == 200, f"Challenge page expected 200, got {challenge_page.status_code}")

    token = _extract_const(challenge_page.text, "token")
    nonce = _extract_const(challenge_page.text, "nonce")
    target_path = _extract_const(challenge_page.text, "targetPath")
    sid = client.cookies.get("bw_sid")
    assert_true(bool(sid), "Missing bw_sid while submitting Stage-2 proof")

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
            "pointer_moves": 36,
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
            "dwell_ms": 2200,
            "event_loop_jitter": 0.1,
            "pointer_entropy": 1.3,
            "canvas_frame_ms": [1.1, 1.4, 1.2, 1.3],
            "webgl_frame_ms": [0.9, 1.1, 1.0, 1.2],
            "user_agent": ua,
            "platform": "Linux x86_64",
            "ua_data": {"platform": "Linux"},
        },
    }
    proof = client.post("/bw/proof", json=payload)
    assert_true(proof.status_code == 202, f"Expected proof 202, got {proof.status_code}")


def pass_gate(client: httpx.Client, return_to: str = "/") -> None:
    gate_page = client.get(f"/bw/gate/challenge?path={quote(return_to, safe='/?=&')}")
    assert_true(gate_page.status_code == 200, f"Gate challenge expected 200, got {gate_page.status_code}")

    challenge_token = _extract_const(gate_page.text, "CHALLENGE_TOKEN")
    challenge = _extract_const(gate_page.text, "CHALLENGE")
    difficulty = int(_extract_const(gate_page.text, "DIFFICULTY"))
    sid = client.cookies.get("bw_sid")
    assert_true(bool(sid), "Missing bw_sid cookie on gate challenge")

    start = time.perf_counter()
    nonce, digest = _solve_pow(challenge, difficulty)
    solve_ms = int((time.perf_counter() - start) * 1000)
    if solve_ms < 60:
        time.sleep((60 - solve_ms) / 1000.0)
        solve_ms = 60

    payload = {
        "schema_version": "1.0",
        "session_id": sid,
        "challenge_token": challenge_token,
        "challenge": challenge,
        "nonce": nonce,
        "hash": digest,
        "solve_ms": solve_ms,
        "return_to": return_to,
        "env": _gate_env(),
    }
    verify = client.post("/bw/gate/verify", json=payload)
    assert_true(verify.status_code == 200, f"Gate verify expected 200, got {verify.status_code}")
    assert_true(verify.json().get("decision") == "allow", "Gate verify did not return decision=allow")
    assert_true(bool(client.cookies.get("bw_gate")), "Missing bw_gate cookie after gate verify")


def run_demo(gateway_url: str) -> None:
    browser = httpx.Client(
        base_url=gateway_url,
        headers={
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "accept-language": "en-US,en;q=0.9",
            "x-ja3": "demo-browser-ja3",
        },
        follow_redirects=False,
        timeout=8.0,
    )

    first = browser.get("/")
    assert_true(first.status_code == 302, f"Expected redirect to gate, got {first.status_code}")
    assert_true(first.headers.get("location", "").startswith("/bw/gate/challenge"), "Expected Stage-1 gate redirect")
    pass_gate(browser, "/")

    home = browser.get("/")
    assert_true(home.status_code == 200, f"Expected origin home via gateway, got {home.status_code}")
    assert_true("Local Origin Demo Site" in home.text, "Expected origin home content")
    assert_true(home.headers.get("x-botwall-decision") in {"observe", "allow"}, "Expected allow/observe decision")

    pricing = browser.get("/pricing")
    if pricing.status_code == 302 and pricing.headers.get("location", "").startswith("/bw/challenge"):
        submit_stage2_proof(browser, pricing.headers["location"], browser.headers.get("user-agent", ""))
        pricing = browser.get("/pricing")
    assert_true(pricing.status_code == 200, f"Expected /pricing from origin, got {pricing.status_code}")
    assert_true("Starter: $19/mo" in pricing.text, "Expected origin pricing content")

    headless = httpx.Client(
        base_url=gateway_url,
        headers={
            "user-agent": "HeadlessChrome/120.0",
            "x-ip-reputation": "bad",
        },
        follow_redirects=False,
        timeout=8.0,
    )
    gate_redirect = headless.get("/")
    assert_true(gate_redirect.status_code == 302, "Expected gate redirect for headless client")
    pass_gate(headless, "/")

    decoy_seen = False
    for _ in range(4):
        verdict = headless.get("/")
        assert_true(verdict.status_code == 302, f"Expected headless redirect after gate, got {verdict.status_code}")
        location = verdict.headers.get("location", "")
        if location.startswith("/bw/decoy/"):
            decoy_seen = True
            break
        assert_true(location.startswith("/bw/challenge"), f"Expected challenge/decoy redirect, got {location}")
        _ = headless.get(location)
    assert_true(decoy_seen, "Expected decoy redirect for suspicious session")

    rec_start = headless.post("/bw/recovery/start", json={"reason": "false_positive"})
    assert_true(rec_start.status_code == 202, f"Expected recovery start 202, got {rec_start.status_code}")
    rec_token = rec_start.json()["recovery_token"]
    rec_sid = headless.cookies.get("bw_sid")
    rec_done = headless.post(
        "/bw/recovery/complete",
        json={
            "session_id": rec_sid,
            "recovery_token": rec_token,
            "game_score": 58,
            "hits": 12,
            "misses": 5,
            "duration_ms": 10400,
        },
    )
    assert_true(rec_done.status_code == 202, f"Expected recovery complete 202, got {rec_done.status_code}")

    recovered = headless.get("/")
    assert_true(recovered.status_code == 200, f"Expected origin home after recovery, got {recovered.status_code}")
    assert_true("Local Origin Demo Site" in recovered.text, "Expected origin content after recovery")

    print("[OK] Gateway blocks ungated traffic with Stage-1 challenge")
    print("[OK] Browser client passed gate and reached origin pages through gateway")
    print("[OK] Headless profile was routed to decoy after gate")
    print("[OK] Recovery flow restored access to origin for false positive")


def _terminate(processes: list[subprocess.Popen[str]]) -> dict[int, str]:
    logs: dict[int, str] = {}
    for proc in processes:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
    for proc in processes:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        if proc.stdout is not None:
            logs[proc.pid] = proc.stdout.read() or ""
    return logs


def main() -> int:
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    python = sys.executable

    origin_url = "http://127.0.0.1:9100"
    botwall_url = "http://127.0.0.1:4100"
    gateway_url = "http://127.0.0.1:8088"

    processes: list[subprocess.Popen[str]] = []
    err: Exception | None = None

    try:
        origin_env = os.environ.copy()
        origin_env["ORIGIN_HOST"] = "127.0.0.1"
        origin_env["ORIGIN_PORT"] = "9100"
        origin = subprocess.Popen(
            [python, "scripts/demo_origin_site.py"],
            cwd=repo,
            env=origin_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        processes.append(origin)
        wait_until_up(origin_url)

        botwall_env = os.environ.copy()
        botwall_env["BOTWALL_HOST"] = "127.0.0.1"
        botwall_env["BOTWALL_PORT"] = "4100"
        botwall_env["BOTWALL_POW_DIFFICULTY"] = "2"
        botwall_env["BOTWALL_POW_ELEVATED_DIFFICULTY"] = "3"
        botwall = subprocess.Popen(
            [python, "-m", "botwall"],
            cwd=repo,
            env=botwall_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        processes.append(botwall)
        wait_until_up(botwall_url)

        gateway_env = os.environ.copy()
        gateway_env["GATEWAY_HOST"] = "127.0.0.1"
        gateway_env["GATEWAY_PORT"] = "8088"
        gateway_env["BOTWALL_URL"] = botwall_url
        gateway_env["ORIGIN_URL"] = origin_url
        gateway = subprocess.Popen(
            [python, "scripts/localhost_gateway.py"],
            cwd=repo,
            env=gateway_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        processes.append(gateway)
        wait_until_up(gateway_url)

        run_demo(gateway_url)
        return 0
    except Exception as exc:
        err = exc
    finally:
        logs = _terminate(processes)

    if err is not None:
        print(f"[FAIL] {err}")
        for proc in processes:
            log = logs.get(proc.pid, "").strip()
            if log:
                print(f"--- process {proc.pid} output (tail) ---")
                print(log[-3000:])
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
