#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import random
import re
import statistics
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx


import os


BASE = os.getenv("BW_BASE", "http://127.0.0.1:4101")


@dataclass
class ProbeResult:
    profile: str
    decision_counts: dict[str, int]
    status_counts: dict[int, int]


def extract_const(page_html: str, name: str) -> str:
    match = re.search(rf"const\s+{re.escape(name)}\s*=\s*(.+?);", page_html)
    if not match:
        raise RuntimeError(f"missing JS const {name}")
    value = match.group(1).strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def solve_pow(challenge: str, difficulty: int) -> tuple[str, str]:
    target = "0" * difficulty
    nonce = 0
    while True:
        hex_nonce = format(nonce, "x")
        digest = hashlib.sha256((challenge + hex_nonce).encode("utf-8")).hexdigest()
        if digest.startswith(target):
            return hex_nonce, digest
        nonce += 1


def pass_gate(client: httpx.Client, return_to: str = "/") -> None:
    gate = client.get(f"/bw/gate/challenge?path={quote(return_to, safe='/?=&')}")
    if gate.status_code != 200:
        raise RuntimeError(f"gate challenge failed: {gate.status_code}")

    challenge_token = extract_const(gate.text, "CHALLENGE_TOKEN")
    challenge = extract_const(gate.text, "CHALLENGE")
    difficulty = int(extract_const(gate.text, "DIFFICULTY"))
    sid = client.cookies.get("bw_sid")
    if not sid:
        raise RuntimeError("missing bw_sid from gate page")

    start = time.perf_counter()
    nonce, digest = solve_pow(challenge, difficulty)
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
        "env": {
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
            "timezone": "UTC",
            "renderer": "ANGLE (NVIDIA)",
        },
    }
    verify = client.post("/bw/gate/verify", json=payload)
    if verify.status_code != 200:
        raise RuntimeError(f"gate verify failed: {verify.status_code} {verify.text[:120]}")


def submit_stage2_proof(client: httpx.Client, challenge_location: str, ua: str, dwell_ms: int, entropy: float) -> None:
    challenge = client.get(challenge_location)
    if challenge.status_code != 200:
        raise RuntimeError(f"challenge page failed: {challenge.status_code}")

    token = extract_const(challenge.text, "token")
    nonce = extract_const(challenge.text, "nonce")
    path = extract_const(challenge.text, "targetPath")
    sid = client.cookies.get("bw_sid")
    if not sid:
        raise RuntimeError("missing bw_sid before proof")

    payload = {
        "schema_version": "1.0",
        "session_id": sid,
        "token": token,
        "page_path": path,
        "nonce": nonce,
        "beacon": {
            "schema_version": "1.0",
            "session_id": sid,
            "nonce": nonce,
            "page_path": path,
            "pointer_moves": 28,
            "scroll_events": 8,
            "max_scroll_depth": 280,
            "visibility_changes": 1,
            "focus_events": 2,
            "blur_events": 1,
            "trap_hits": 0,
            "trap_ids": [],
            "copy_events": 0,
            "key_events": 2,
            "screenshot_combo_hits": 0,
            "dwell_ms": dwell_ms,
            "event_loop_jitter": 0.1,
            "pointer_entropy": entropy,
            "canvas_frame_ms": [1.0, 1.2, 1.4, 1.1],
            "webgl_frame_ms": [0.9, 1.0, 1.1, 1.0],
            "user_agent": ua,
            "platform": "Linux x86_64",
            "ua_data": {"platform": "Linux"},
        },
    }
    res = client.post("/bw/proof", json=payload)
    if res.status_code != 202:
        raise RuntimeError(f"proof submit failed: {res.status_code} {res.text[:120]}")


def run_profile(name: str, headers: dict[str, str], iterations: int, random_delay: tuple[int, int], submit_proof: bool) -> ProbeResult:
    client = httpx.Client(base_url=BASE, headers=headers, follow_redirects=False, timeout=10.0)
    pass_gate(client, "/")

    decisions: dict[str, int] = {}
    statuses: dict[int, int] = {}

    paths = ["/", "/content/1", "/content/2", "/content/3", "/content/4"]

    for i in range(iterations):
        path = random.choice(paths)
        res = client.get(path)
        statuses[res.status_code] = statuses.get(res.status_code, 0) + 1

        if decision:
            decisions[decision] = decisions.get(decision, 0) + 1

        if res.status_code == 302:
            loc = res.headers.get("location", "")
            if loc.startswith("/bw/challenge") and submit_proof:
                submit_stage2_proof(
                    client,
                    loc,
                    headers.get("user-agent", "Mozilla/5.0"),
                    dwell_ms=random.randint(1500, 2600),
                    entropy=round(random.uniform(0.8, 1.8), 3),
                )
                follow = client.get(path)
                statuses[follow.status_code] = statuses.get(follow.status_code, 0) + 1
                if d2:
                    decisions[d2] = decisions.get(d2, 0) + 1
            elif loc.startswith("/bw/decoy"):
                decisions["decoy"] = decisions.get("decoy", 0) + 1

        sleep_ms = random.randint(random_delay[0], random_delay[1])
        time.sleep(sleep_ms / 1000.0)

    client.close()
    return ProbeResult(profile=name, decision_counts=decisions, status_counts=statuses)


def telemetry_snapshot() -> dict[str, Any]:
    res = httpx.get(f"{BASE}/bw/telemetry.json", timeout=10.0)
    res.raise_for_status()
    return res.json()


def main() -> int:
    random.seed(42)

    profiles = [
        {
            "name": "clean-browser",
            "headers": {
                "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                "accept-language": "en-US,en;q=0.9",
                "x-ja3": "ja3-browser-clean",
            },
            "iterations": 12,
            "random_delay": (160, 420),
            "submit_proof": True,
        },
        {
            "name": "aggressive-bot",
            "headers": {
                "user-agent": "HeadlessChrome/120.0",
                "accept-language": "en",
                "x-ip-reputation": "bad",
            },
            "iterations": 18,
            "random_delay": (20, 90),
            "submit_proof": False,
        },
    ]

    results: list[ProbeResult] = []
    for p in profiles:
        print(f"[RUN] {p['name']}")
        result = run_profile(
            name=p["name"],
            headers=p["headers"],
            iterations=p["iterations"],
            random_delay=p["random_delay"],
            submit_proof=p["submit_proof"],
        )
        results.append(result)

    snap = telemetry_snapshot()

    print("\n=== Stage 2 Scraper Metrics ===")
    for r in results:
        print(f"\nProfile: {r.profile}")
        print(f"  Decisions: {json.dumps(r.decision_counts, sort_keys=True)}")
        print(f"  HTTP: {json.dumps(r.status_counts, sort_keys=True)}")

    metrics = snap.get("metrics", {})
    sessions = snap.get("sessions", [])
    telemetry = snap.get("telemetry", [])

    scores = [float(s.get("score", 0.0)) for s in sessions]
    decision_tail = []
    for s in sessions:
        h = s.get("decision_history", [])
        if h:
            decision_tail.append(str(h[-1].get("decision", "")))

    print("\nTelemetry Snapshot:")
    print(f"  sessions_total: {metrics.get('sessions_total', 0)}")
    print(f"  gate_passed: {metrics.get('gate_passed', 0)}")
    print(f"  proof_sessions: {metrics.get('proof_sessions', 0)}")
    print(f"  decoy_sessions: {metrics.get('decoy_sessions', 0)}")
    print(f"  allow_sessions: {metrics.get('allow_sessions', 0)}")
    if scores:
        print(f"  score_min/avg/max: {min(scores):.2f} / {statistics.mean(scores):.2f} / {max(scores):.2f}")
    print(f"  telemetry_fingerprints: {len(telemetry)}")
    print(f"  latest_decisions: {decision_tail[-12:]}")

    print("\nLinks:")
    print(f"  Stage 1: {BASE}/bw/gate/challenge?path=/")
    print(f"  Telemetry UI: {BASE}/bw/telemetry")
    print(f"  Telemetry JSON: {BASE}/bw/telemetry.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
