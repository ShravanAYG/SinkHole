#!/usr/bin/env python3
"""
scripts/validate_live.py — IRL validation script for SinkHole Botwall.

Runs a battery of real HTTP probes against the live server at http://127.0.0.1:4000
and reports what happened for each scenario. No mocking, no stubs — pure HTTP.

Scenarios:
  1.  curl-style bot — bare GET, no headers
  2.  wget-style bot — wget UA
  3.  Python-requests bot — no Accept-Language
  4.  HeadlessChrome bot — automation UA + bad IP reputation
  5.  Good browser — full headers, passes gate
  6.  Gate challenge page render check
  7.  PoW: solve a real SHA-256 challenge in Python and submit it
  8.  Gate cookie: once issued, verify home is served
  9.  Burst attack — 15 rapid requests from "bot"
  10. Decoy page reachable and contains relational content
  11. Recovery flow end-to-end
  12. /bw/config endpoint
  13. Traversal token gating
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import urllib.parse

# stdlib-only http so it works in any venv
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:4000"

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
INFO = "\033[94m→\033[0m"

results: list[tuple[bool, str, str]] = []


def req(method: str, path: str, *, headers: dict = {}, data: bytes | None = None, allow_redirects: bool = False):
    url = BASE + path
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=15)
        return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="replace")
    except Exception as exc:
        return 0, {}, str(exc)


def check(ok: bool, name: str, detail: str = "") -> None:
    mark = PASS if ok else FAIL
    results.append((ok, name, detail))
    print(f"{mark}  {name}")
    if detail:
        for line in detail.splitlines():
            print(f"   {INFO} {line}")


def section(title: str) -> None:
    print(f"\n\033[1;37m{'─'*60}\033[0m")
    print(f"\033[1;37m  {title}\033[0m")
    print(f"\033[1;37m{'─'*60}\033[0m")


# ── Helpers ─────────────────────────────────────────────────────────────────

def solve_pow(challenge: str, difficulty: int) -> tuple[str, str]:
    """Pure-Python SHA-256 Hashcash. Slow but correct."""
    target = "0" * difficulty
    nonce = 0
    while True:
        hex_nonce = format(nonce, 'x')
        digest = hashlib.sha256((challenge + hex_nonce).encode()).hexdigest()
        if digest.startswith(target):
            return hex_nonce, digest
        nonce += 1


def post_json(path: str, payload: dict, cookies: str = "") -> tuple[int, dict, dict]:
    body = json.dumps(payload).encode()
    hdrs = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if cookies:
        hdrs["Cookie"] = cookies
    status, resp_hdrs, body_resp = req("POST", path, headers=hdrs, data=body)
    try:
        data = json.loads(body_resp)
    except Exception:
        data = {}
    return status, resp_hdrs, data


# ═══════════════════════════════════════════════════════════════════════════
# SCENARIO 1-4: Bots hit the gate
# ═══════════════════════════════════════════════════════════════════════════
section("SCENARIO 1-4: Bot / Scraper probes (no gate cookie)")

# 1. curl bare request
status, hdrs, body = req("GET", "/", headers={"User-Agent": "curl/7.81.0"})
loc = hdrs.get("location", hdrs.get("Location", ""))
check(
    status == 302 and "/bw/gate/challenge" in loc,
    "1. curl bot → redirected to gate challenge",
    f"HTTP {status}  Location: {loc}",
)

# 2. wget
status, hdrs, body = req("GET", "/", headers={"User-Agent": "Wget/1.21.1"})
loc = hdrs.get("location", hdrs.get("Location", ""))
check(
    status == 302 and "/bw/gate/challenge" in loc,
    "2. wget bot → redirected to gate challenge",
    f"HTTP {status}  Location: {loc}",
)

# 3. python-requests style (no accept-language)
status, hdrs, body = req("GET", "/", headers={"User-Agent": "python-requests/2.31.0"})
loc = hdrs.get("location", hdrs.get("Location", ""))
check(
    status == 302 and "/bw/gate/challenge" in loc,
    "3. python-requests bot → redirected to gate challenge",
    f"HTTP {status}  Location: {loc}",
)

# 4. HeadlessChrome with bad IP rep
status, hdrs, body = req("GET", "/", headers={
    "User-Agent": "HeadlessChrome/120.0",
    "X-IP-Reputation": "bad",
})
loc = hdrs.get("location", hdrs.get("Location", ""))
check(
    status == 302 and "/bw/gate/challenge" in loc,
    "4. HeadlessChrome + bad IP → redirected to gate (not served)",
    f"HTTP {status}  Location: {loc}",
)


# ═══════════════════════════════════════════════════════════════════════════
# SCENARIO 5: PoW Gate full flow — challenge → solve → verify → gate cookie
# ═══════════════════════════════════════════════════════════════════════════
section("SCENARIO 5-8: Stage 1 Entry Gate — PoW full flow")

# 5. Get challenge page
status, hdrs, body = req("GET", "/bw/gate/challenge?path=/", headers={
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
})
check(
    status == 200 and "Checking your browser" in body and "crypto.subtle" in body,
    "5. Gate challenge page renders correctly",
    f"HTTP {status} | Has PoW JS: {'crypto.subtle' in body} | Has progress bar: {'progress-bar' in body}",
)

# Extract session cookie from gate challenge response
set_cookie = hdrs.get("set-cookie", hdrs.get("Set-Cookie", ""))
session_id = ""
for part in set_cookie.split(";"):
    part = part.strip()
    if part.startswith("bw_sid="):
        session_id = part.split("=", 1)[1]
        break

if not session_id:
    import uuid
    session_id = uuid.uuid4().hex

# Extract challenge data from the page JS
import re
challenge_match = re.search(r'const CHALLENGE\s*=\s*"([a-f0-9]+)"', body)
token_match     = re.search(r'const CHALLENGE_TOKEN\s*=\s*"([^"]+)"', body)
difficulty_match = re.search(r'const DIFFICULTY\s*=\s*(\d+)', body)

has_challenge = bool(challenge_match and token_match and difficulty_match)
check(
    has_challenge,
    "6. Challenge page embeds CHALLENGE, TOKEN, DIFFICULTY in JS",
    f"challenge={'found' if challenge_match else 'MISSING'}  "
    f"token={'found' if token_match else 'MISSING'}  "
    f"difficulty={'found' if difficulty_match else 'MISSING'}",
)

gate_cookie = ""

if has_challenge:
    challenge   = challenge_match.group(1)
    token_str   = token_match.group(1)
    difficulty  = int(difficulty_match.group(1))

    print(f"\n   {INFO} Solving SHA-256 PoW: difficulty={difficulty} challenge={challenge[:16]}…")
    t0 = time.time()
    nonce, hash_hex = solve_pow(challenge, difficulty)
    elapsed = time.time() - t0
    print(f"   {INFO} Solved in {elapsed:.2f}s  nonce={nonce}  hash={hash_hex[:20]}…")

    # 7. Submit PoW solution
    env_report = {
        "webdriver": False,
        "chrome_obj": True,
        "plugins_count": 3,
        "languages": ["en-US", "en"],
        "viewport": [1280, 800],
        "notification_api": True,
        "perf_memory": True,
        "touch_support": False,
        "device_pixel_ratio": 1.0,
        "timezone": "Asia/Kolkata",
        "renderer": "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620, OpenGL 4.6)",
    }
    payload = {
        "schema_version": "1.0",
        "session_id": session_id,
        "challenge_token": token_str,
        "challenge": challenge,
        "nonce": nonce,
        "hash": hash_hex,
        "solve_ms": int(elapsed * 1000),
        "return_to": "/",
        "env": env_report,
    }
    status_v, hdrs_v, data_v = post_json("/bw/gate/verify", payload, cookies=f"bw_sid={session_id}")

    issued = status_v == 200 and data_v.get("decision") == "allow"
    check(
        issued,
        "7. PoW solution accepted → decision=allow",
        f"HTTP {status_v}  decision={data_v.get('decision')}  "
        f"env_score={data_v.get('env_score')}  "
        f"expires_at={data_v.get('gate_expires_at')}",
    )

    # Extract gate cookie from Set-Cookie
    sc = hdrs_v.get("set-cookie", hdrs_v.get("Set-Cookie", ""))
    for part in sc.split("\n"):
        if "bw_gate=" in part:
            gate_cookie = part.split("bw_gate=")[1].split(";")[0].strip()
            break

    check(
        bool(gate_cookie),
        "8. Gate cookie (bw_gate) issued in response",
        f"bw_gate={gate_cookie[:40]}…" if gate_cookie else "bw_gate=MISSING",
    )

    # 8. Access home page WITH gate cookie
    status_h, hdrs_h, body_h = req("GET", "/", headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "X-Forwarded-For": "10.0.0.1",
        "Cookie": f"bw_sid={session_id}; bw_gate={gate_cookie}",
    })
    decision_hdr = hdrs_h.get("x-botwall-decision", hdrs_h.get("X-Botwall-Decision", ""))
    check(
        status_h == 200 and decision_hdr in ("observe", "allow"),
        "9. Home page served to verified session (Stage 1 passed)",
        f"HTTP {status_h}  x-botwall-decision={decision_hdr}",
    )


# ═══════════════════════════════════════════════════════════════════════════
# SCENARIO 9: Replay attack — same PoW token twice
# ═══════════════════════════════════════════════════════════════════════════
section("SCENARIO 9: Anti-replay protection")

if has_challenge and gate_cookie:
    status_r, _, data_r = post_json("/bw/gate/verify", payload, cookies=f"bw_sid={session_id}")
    check(
        status_r == 409,
        "9. Replay of same PoW token rejected with 409 Conflict",
        f"HTTP {status_r}  detail={data_r.get('detail', '')}",
    )

    # Also test tampered hash
    bad_payload = {**payload, "hash": "0000000000000000000000000000000000000000000000000000000000000000"}
    status_bad, _, data_bad = post_json("/bw/gate/verify", bad_payload)
    check(
        status_bad == 400,
        "9b. Tampered PoW hash rejected with 400",
        f"HTTP {status_bad}  detail={data_bad.get('detail', '')}",
    )


# ═══════════════════════════════════════════════════════════════════════════
# SCENARIO 10: Burst bot attack → score tanks
# ═══════════════════════════════════════════════════════════════════════════
section("SCENARIO 10: Burst attack (15 rapid requests)")

if gate_cookie:
    burst_session = f"burst-bot-{int(time.time())}"
    bot_gate = ""
    # Solve PoW for this session to get past gate
    g_status, g_hdrs, g_body = req("GET", "/bw/gate/challenge?path=/", headers={
        "User-Agent": "Mozilla/5.0 Chrome/120",
        "Accept-Language": "en",
    })
    if g_status == 200:
        sc2 = g_hdrs.get("set-cookie", g_hdrs.get("Set-Cookie", ""))
        for part in sc2.split(";"):
            if "bw_sid=" in part:
                burst_session = part.split("bw_sid=")[1].strip()
        c_m = re.search(r'const CHALLENGE\s*=\s*"([a-f0-9]+)"', g_body)
        t_m = re.search(r'const CHALLENGE_TOKEN\s*=\s*"([^"]+)"', g_body)
        d_m = re.search(r'const DIFFICULTY\s*=\s*(\d+)', g_body)
        if c_m and t_m and d_m:
            n2, h2 = solve_pow(c_m.group(1), int(d_m.group(1)))
            s2, h2r, d2 = post_json("/bw/gate/verify", {
                "schema_version": "1.0", "session_id": burst_session,
                "challenge_token": t_m.group(1), "challenge": c_m.group(1),
                "nonce": n2, "hash": h2, "solve_ms": 500, "return_to": "/",
                "env": {"webdriver": False, "chrome_obj": True, "plugins_count": 3,
                        "languages": ["en-US", "en"], "viewport": [1280, 800],
                        "notification_api": True, "perf_memory": True,
                        "touch_support": False, "device_pixel_ratio": 1.0,
                        "timezone": "UTC", "renderer": "Intel HD"},
            }, cookies=f"bw_sid={burst_session}")
            sc3 = h2r.get("set-cookie", h2r.get("Set-Cookie", ""))
            for part in sc3.split("\n"):
                if "bw_gate=" in part:
                    bot_gate = part.split("bw_gate=")[1].split(";")[0].strip()

    if bot_gate:
        last_decision = ""
        last_location = ""
        for i in range(15):
            s_b, h_b, _ = req("GET", "/", headers={
                "User-Agent": "HeadlessChrome/120.0",
                "Accept-Language": "en",
                "Cookie": f"bw_sid={burst_session}; bw_gate={bot_gate}",
            })
            last_decision = h_b.get("x-botwall-decision", h_b.get("X-Botwall-Decision", ""))
            last_location = h_b.get("location", h_b.get("Location", ""))

        routed_to_decoy = "/bw/decoy" in last_location or last_decision == "decoy"
        check(
            routed_to_decoy,
            "10. Burst bot (15 rapid + HeadlessChrome UA) → decoy after Stage 2 scoring",
            f"Final decision={last_decision}  location={last_location}",
        )
    else:
        check(False, "10. SKIP — could not get burst session gate cookie", "")


# ═══════════════════════════════════════════════════════════════════════════
# SCENARIO 11: Decoy page — content and structure
# ═══════════════════════════════════════════════════════════════════════════
section("SCENARIO 11: Layer 2 Decoy graph")

status_d, hdrs_d, body_d = req("GET", "/bw/decoy/0", headers={
    "User-Agent": "Mozilla/5.0 Chrome/120",
})
has_relational = any(w in body_d for w in ["brother", "sibling", "lineage", "ledger", "VERIFY-AUTH"])
has_noindex   = "noindex" in body_d.lower()
has_bw_hdr   = hdrs_d.get("x-botwall-decision", hdrs_d.get("X-Botwall-Decision", "")) == "decoy"

check(status_d == 200, "11a. Decoy page accessible (HTTP 200)", f"HTTP {status_d}")
check(has_relational, "11b. Decoy page contains relational contradiction content",
      f"Sample: {body_d[body_d.find('brother')-20:body_d.find('brother')+50]}" if "brother" in body_d else "No relational text found")
check(has_noindex,   "11c. Decoy page has noindex meta tag", "")
check(has_bw_hdr,   "11d. Decoy page sets X-Botwall-Decision: decoy header", f"header={hdrs_d.get('x-botwall-decision', '')}")

# Multiple nodes
nodes_ok = 0
for n in [1, 7, 23, 47, 79]:
    s_n, _, b_n = req("GET", f"/bw/decoy/{n}", headers={"User-Agent": "Mozilla/5.0"})
    if s_n == 200 and "Archive Segment" in b_n:
        nodes_ok += 1
check(nodes_ok == 5, f"11e. All tested decoy nodes (1,7,23,47,79) return content", f"{nodes_ok}/5 nodes OK")


# ═══════════════════════════════════════════════════════════════════════════
# SCENARIO 12: /bw/config endpoint
# ═══════════════════════════════════════════════════════════════════════════
section("SCENARIO 12: Config + Health endpoints")

s_cfg, _, b_cfg = req("GET", "/bw/config", headers={"User-Agent": "Mozilla/5.0"})
try:
    cfg_data = json.loads(b_cfg)
except Exception:
    cfg_data = {}
check(
    s_cfg == 200 and "scoring" in cfg_data and "tokens" in cfg_data and "pow" in cfg_data,
    "12a. /bw/config returns active config (no secrets)",
    f"HTTP {s_cfg}  keys={list(cfg_data.keys())}",
)
check(
    "secret_key" not in b_cfg and "secret" not in json.dumps(cfg_data).lower(),
    "12b. /bw/config does NOT expose secret_key",
    "",
)

s_h, _, b_h = req("GET", "/healthz", headers={"User-Agent": "curl/7.81"})
check(s_h == 200, "12c. /healthz returns 200", f"body={b_h}")


# ═══════════════════════════════════════════════════════════════════════════
# SCENARIO 13: Recovery flow (false-positive human exit)
# ═══════════════════════════════════════════════════════════════════════════
section("SCENARIO 13: Recovery flow (false-positive human exit)")

recov_session = f"recov-test-{int(time.time())}"
s_rs, _, d_rs = post_json(
    "/bw/recovery/start",
    {"schema_version": "1.0", "session_id": recov_session, "reason": "false_positive"},
    cookies=f"bw_sid={recov_session}",
)
check(s_rs == 202, "13a. Recovery start returns 202", f"HTTP {s_rs}  keys={list(d_rs.keys())}")

recov_token = d_rs.get("recovery_token", "")
if recov_token:
    s_rc, _, d_rc = post_json(
        "/bw/recovery/complete",
        {
            "schema_version": "1.0",
            "session_id": recov_session,
            "recovery_token": recov_token,
            "game_score": 55,
            "hits": 11,
            "misses": 4,
            "duration_ms": 10200,
        },
        cookies=f"bw_sid={recov_session}",
    )
    check(
        s_rc == 202 and d_rc.get("decision") == "allow",
        "13b. Recovery complete grants allow decision",
        f"HTTP {s_rc}  decision={d_rc.get('decision')}  allow_until={d_rc.get('allow_until')}",
    )

    # Retry recovery with same token → should fail (replay)
    s_rr, _, d_rr = post_json(
        "/bw/recovery/complete",
        {
            "schema_version": "1.0",
            "session_id": recov_session,
            "recovery_token": recov_token,
            "game_score": 55,
            "hits": 11,
            "misses": 4,
            "duration_ms": 10200,
        },
        cookies=f"bw_sid={recov_session}",
    )
    check(s_rr == 409, "13c. Replay of recovery token rejected with 409", f"HTTP {s_rr}")

    # Invalid game payload
    s_rw, _, d_rw = post_json(
        "/bw/recovery/complete",
        {
            "schema_version": "1.0",
            "session_id": recov_session,
            "recovery_token": "fake.token",
            "game_score": 1,
            "hits": 1,
            "misses": 20,
            "duration_ms": 800,
        },
        cookies=f"bw_sid={recov_session}",
    )
    check(s_rw == 400, "13d. Invalid game payload rejected with 400", f"HTTP {s_rw}")


# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
section("SUMMARY")

passed = sum(1 for ok, _, _ in results if ok)
total  = len(results)
pct    = int(passed / total * 100) if total else 0

print(f"\n  Total checks: {total}")
print(f"  Passed:       {passed}  ({pct}%)")
print(f"  Failed:       {total - passed}")

if total - passed > 0:
    print("\n  Failed checks:")
    for ok, name, detail in results:
        if not ok:
            print(f"    {FAIL} {name}")
            if detail:
                print(f"         {detail}")

print()
sys.exit(0 if passed == total else 1)
