from __future__ import annotations

import html
import json
from typing import Any

from .decoy import DecoyNode


def sdk_script() -> str:
    # Browser-side data collection. Screenshot detection is heuristic only.
    return r'''
(() => {
  const sid = document.documentElement.dataset.bwSid || "";
  const nonce = document.documentElement.dataset.bwNonce || "";
  const path = location.pathname;
  const startedAt = Date.now();
  const aliases = ["/api/v1/analytics-ping", "/cdn-ping/perf", "/event/flow/alpha"];
  const endpoint = aliases[Math.floor(Math.random() * aliases.length)];

  const persistTheme = () => {
    try {
      const root = getComputedStyle(document.documentElement);
      const body = getComputedStyle(document.body);
      const pick = (a, b) => (a && a.trim()) || (b && b.trim()) || "";
      const theme = {
        bg: pick(root.getPropertyValue("--bg"), body.backgroundColor),
        surface: pick(root.getPropertyValue("--surface"), ""),
        border: pick(root.getPropertyValue("--border"), ""),
        text: pick(root.getPropertyValue("--text"), body.color),
        muted: pick(root.getPropertyValue("--muted"), ""),
        accent: pick(root.getPropertyValue("--accent"), ""),
        font: pick(root.getPropertyValue("--font-family"), body.fontFamily),
      };
      const encoded = encodeURIComponent(JSON.stringify(theme));
      document.cookie = `bw_theme=${encoded}; Path=/; Max-Age=86400; SameSite=Lax`;
    } catch (_) {}
  };

  const state = {
    pointerMoves: 0,
    scrollEvents: 0,
    maxScrollDepth: 0,
    visibilityChanges: 0,
    focusEvents: 0,
    blurEvents: 0,
    trapHits: 0,
    trapIds: [],
    copyEvents: 0,
    keyEvents: 0,
    screenshotComboHits: 0,
    dwellMs: 0,
    pointerEntropy: 0,
    pointerBins: new Array(8).fill(0),
    canvasFrameMs: [],
    webglFrameMs: [],
    lastSentAt: 0,
    trapArmed: false,
  };

  const addTrapHit = (id) => {
    state.trapHits += 1;
    if (!state.trapIds.includes(id)) state.trapIds.push(id);
  };

  const armShadowTrap = () => {
    if (state.trapArmed) return;
    if (state.maxScrollDepth < 200) return;
    if (Date.now() - startedAt < 1200) return;

    const host = document.createElement("div");
    host.style.position = "fixed";
    host.style.left = "-9999px";
    host.style.top = "-9999px";
    host.style.width = "1px";
    host.style.height = "1px";
    host.setAttribute("aria-hidden", "true");
    const root = host.attachShadow({ mode: "open" });

    const bait = document.createElement("button");
    bait.textContent = "continue";
    bait.tabIndex = 0;
    bait.addEventListener("focus", () => addTrapHit("shadow-focus"));
    bait.addEventListener("click", () => addTrapHit("shadow-click"));
    root.appendChild(bait);
    document.body.appendChild(host);
    state.trapArmed = true;
  };

  document.addEventListener("mousemove", (e) => {
    state.pointerMoves += 1;
    const bin = Math.min(7, Math.floor((Math.abs(e.movementX) + Math.abs(e.movementY)) / 6));
    state.pointerBins[bin] += 1;
  }, { passive: true });

  document.addEventListener("scroll", () => {
    state.scrollEvents += 1;
    state.maxScrollDepth = Math.max(state.maxScrollDepth, Math.round(window.scrollY || 0));
    armShadowTrap();
  }, { passive: true });

  document.addEventListener("visibilitychange", () => {
    state.visibilityChanges += 1;
  });
  window.addEventListener("focus", () => { state.focusEvents += 1; });
  window.addEventListener("blur", () => { state.blurEvents += 1; });
  document.addEventListener("copy", () => { state.copyEvents += 1; });

  document.addEventListener("keydown", (e) => {
    state.keyEvents += 1;
    if (e.key === "PrintScreen") state.screenshotComboHits += 1;
    if ((e.metaKey || e.ctrlKey) && e.shiftKey && (e.key === "3" || e.key === "4" || e.key.toLowerCase() === "s")) {
      state.screenshotComboHits += 1;
    }
  });

  const sampleRenderVariance = () => {
    const canvas = document.createElement("canvas");
    canvas.width = 120; canvas.height = 40;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    let prev = performance.now();
    for (let i = 0; i < 10; i += 1) {
      const now = performance.now();
      state.canvasFrameMs.push(Math.max(0, now - prev));
      prev = now;
      ctx.fillStyle = `rgb(${(i*31)%255}, ${(i*19)%255}, ${(i*11)%255})`;
      ctx.fillRect(i * 5, 5, 20, 20);
    }
  };

  const computeEntropy = () => {
    const total = state.pointerBins.reduce((a, b) => a + b, 0);
    if (!total) return 0;
    let h = 0;
    for (const c of state.pointerBins) {
      if (!c) continue;
      const p = c / total;
      h -= p * Math.log2(p);
    }
    return Number(h.toFixed(4));
  };

  const buildPayload = () => {
    state.dwellMs = Date.now() - startedAt;
    state.pointerEntropy = computeEntropy();
    return {
      schema_version: "1.0",
      session_id: sid,
      nonce,
      page_path: path,
      pointer_moves: state.pointerMoves,
      scroll_events: state.scrollEvents,
      max_scroll_depth: state.maxScrollDepth,
      visibility_changes: state.visibilityChanges,
      focus_events: state.focusEvents,
      blur_events: state.blurEvents,
      trap_hits: state.trapHits,
      trap_ids: state.trapIds,
      copy_events: state.copyEvents,
      key_events: state.keyEvents,
      screenshot_combo_hits: state.screenshotComboHits,
      dwell_ms: state.dwellMs,
      event_loop_jitter: 0,
      pointer_entropy: state.pointerEntropy,
      canvas_frame_ms: state.canvasFrameMs,
      webgl_frame_ms: state.webglFrameMs,
      user_agent: navigator.userAgent || "",
      platform: navigator.platform || "",
      ua_data: navigator.userAgentData ? {
        brands: navigator.userAgentData.brands,
        mobile: navigator.userAgentData.mobile,
        platform: navigator.userAgentData.platform,
      } : {},
    };
  };

  const send = () => {
    if (!sid) return;
    const payload = buildPayload();
    const body = JSON.stringify(payload);
    if (navigator.sendBeacon) {
      const blob = new Blob([body], { type: "application/json" });
      navigator.sendBeacon(endpoint, blob);
    } else {
      fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body, keepalive: true }).catch(() => {});
    }
  };

  sampleRenderVariance();
  persistTheme();
  setTimeout(send, 1300);
  setInterval(() => {
    if (Date.now() - state.lastSentAt > 2500) {
      state.lastSentAt = Date.now();
      send();
    }
  }, 3000);
  window.addEventListener("beforeunload", send);
})();
'''


def render_gate_challenge_page(
    *,
    session_id: str,
    challenge_token: str,
    challenge: str,
    difficulty: int,
    return_to: str,
) -> str:
    """
    Stage 1 Entry Gate — Anubis-style PoW challenge page.

    The page:
    1. Collects browser environment signals while the Web Worker solves the PoW
    2. Runs SHA-256 hashcash in a Web Worker (non-blocking main thread)
    3. Shows animated real-time progress to the user
    4. On solve: POSTs solution + env report to /bw/gate/verify
    5. Server issues a gate cookie → redirect to original destination

    No user interaction required for a real browser — it auto-starts.
    """
    sid_js         = json.dumps(session_id)
    token_js       = json.dumps(challenge_token)
    challenge_js   = json.dumps(challenge)
    difficulty_js  = json.dumps(difficulty)
    return_to_js   = json.dumps(return_to)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>Checking your browser… — SinkHole</title>
  <script>
    (() => {{
      try {{
        const match = document.cookie.match(/(?:^|;\s*)bw_theme=([^;]+)/);
        if (!match) return;
        const t = JSON.parse(decodeURIComponent(match[1]));
        const root = document.documentElement;
        if (t.bg) root.style.setProperty("--bg", t.bg);
        if (t.surface) root.style.setProperty("--surface", t.surface);
        if (t.border) root.style.setProperty("--border", t.border);
        if (t.text) root.style.setProperty("--text", t.text);
        if (t.muted) root.style.setProperty("--muted", t.muted);
        if (t.accent) root.style.setProperty("--accent", t.accent);
        if (t.font) root.style.setProperty("--font-family", t.font);
      }} catch (_) {{}}
    }})();
  </script>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
      --bg:      #0f1117;
      --surface: #1a1d27;
      --border:  #2a2d3d;
      --accent:  #6c63ff;
      --accent2: #48e5c2;
      --text:    #e2e8f0;
      --muted:   #64748b;
      --font-family: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
      --success: #22c55e;
      --error:   #ef4444;
      --radius:  12px;
    }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-family);
      min-height: 100dvh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }}

    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 2.5rem 2rem;
      width: 100%;
      max-width: 420px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    }}

    .logo {{
      display: flex;
      align-items: center;
      gap: 0.6rem;
      margin-bottom: 2rem;
    }}
    .logo-icon {{
      width: 36px; height: 36px;
      border-radius: 8px;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      display: flex; align-items: center; justify-content: center;
      font-size: 1.1rem;
    }}
    .logo-name {{ font-weight: 700; font-size: 1.1rem; letter-spacing: -0.02em; }}

    h1 {{
      font-size: 1.25rem;
      font-weight: 600;
      letter-spacing: -0.02em;
      margin-bottom: 0.5rem;
    }}
    .subtitle {{
      color: var(--muted);
      font-size: 0.875rem;
      line-height: 1.5;
      margin-bottom: 2rem;
    }}

    /* Progress bar */
    .progress-wrap {{
      background: var(--border);
      border-radius: 999px;
      height: 6px;
      overflow: hidden;
      margin-bottom: 1rem;
    }}
    .progress-bar {{
      height: 100%;
      border-radius: 999px;
      background: linear-gradient(90deg, var(--accent), var(--accent2));
      width: 0%;
      transition: width 0.2s ease;
    }}
    .progress-bar.indeterminate {{
      width: 40%;
      animation: slide 1.2s ease-in-out infinite;
    }}
    @keyframes slide {{
      0%   {{ transform: translateX(-100%); }}
      100% {{ transform: translateX(280%); }}
    }}

    /* Status text */
    .status {{
      font-size: 0.8125rem;
      color: var(--muted);
      margin-bottom: 1.5rem;
      min-height: 1.25rem;
    }}
    .status.ok  {{ color: var(--success); }}
    .status.err {{ color: var(--error); }}

    /* Step checklist */
    .steps {{ list-style: none; display: flex; flex-direction: column; gap: 0.6rem; }}
    .steps li {{
      display: flex; align-items: center; gap: 0.6rem;
      font-size: 0.8125rem; color: var(--muted);
    }}
    .steps li.done  {{ color: var(--text); }}
    .steps li.done  .icon {{ color: var(--success); }}
    .steps li.active {{ color: var(--text); }}
    .steps li.active .icon {{ color: var(--accent); animation: pulse 1s ease infinite; }}
    @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.4; }} }}

    .icon {{ width: 1rem; font-size: 0.875rem; flex-shrink: 0; }}

    /* Footer */
    .footer {{
      margin-top: 2rem;
      font-size: 0.75rem;
      color: var(--muted);
      text-align: center;
      line-height: 1.6;
    }}

    /* Retry button (hidden unless error) */
    .retry-btn {{
      display: none;
      margin-top: 1rem;
      width: 100%;
      padding: 0.7rem 1rem;
      background: var(--accent);
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-size: 0.875rem;
      font-weight: 500;
    }}
    .retry-btn:hover {{ background: #7c74ff; }}
  </style>
</head>
<body>
  <div class="card" role="main" aria-labelledby="heading">
    <div class="logo">
      <div class="logo-icon" aria-hidden="true">🛡</div>
      <span class="logo-name">SinkHole</span>
    </div>

    <h1 id="heading">Checking your browser…</h1>
    <p class="subtitle">
      This takes less than a second. You do not need to do anything.
    </p>

    <div class="progress-wrap" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" id="progressWrap">
      <div class="progress-bar indeterminate" id="progressBar"></div>
    </div>

    <p class="status" id="statusText" aria-live="polite">Initialising…</p>

    <ol class="steps" aria-label="Verification steps">
      <li id="step-env" aria-label="Environment check">
        <span class="icon" aria-hidden="true">○</span>
        <span>Browser environment check</span>
      </li>
      <li id="step-pow" aria-label="Proof of work">
        <span class="icon" aria-hidden="true">○</span>
        <span>Proof-of-work computation</span>
      </li>
      <li id="step-verify" aria-label="Server verification">
        <span class="icon" aria-hidden="true">○</span>
        <span>Server verification</span>
      </li>
    </ol>

    <button class="retry-btn" id="retryBtn" type="button" onclick="location.reload()">
      Try again
    </button>
  </div>

  <div class="footer" aria-label="Footer information">
    Protected by <strong>SinkHole</strong> &middot;
    Your browser is being verified. No personal data is collected.
  </div>

<script id="mainScript">
(async () => {{
  // ── Config ──────────────────────────────────────────────────────────
  const SESSION_ID     = {sid_js};
  const CHALLENGE_TOKEN = {token_js};
  const CHALLENGE      = {challenge_js};
  const DIFFICULTY     = {difficulty_js};
  const RETURN_TO      = {return_to_js};

  // ── DOM refs ─────────────────────────────────────────────────────────
  const progressBar  = document.getElementById("progressBar");
  const progressWrap = document.getElementById("progressWrap");
  const statusText   = document.getElementById("statusText");
  const retryBtn     = document.getElementById("retryBtn");

  function setStep(id, state) {{
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove("done", "active");
    if (state) el.classList.add(state);
    const icon = el.querySelector(".icon");
    if (!icon) return;
    icon.textContent = state === "done" ? "✓" : state === "active" ? "●" : "○";
  }}

  function setProgress(pct) {{
    progressBar.classList.remove("indeterminate");
    progressBar.style.width = pct + "%";
    progressWrap.setAttribute("aria-valuenow", String(pct));
  }}

  function setStatus(msg, cls) {{
    statusText.textContent = msg;
    statusText.className   = "status" + (cls ? " " + cls : "");
  }}

  function showError(msg) {{
    setStatus(msg, "err");
    retryBtn.style.display = "block";
    setProgress(0);
  }}

  // ── Step 1: Environment fingerprint (runs while PoW starts) ──────────
  setStep("step-env", "active");
  setStatus("Collecting browser signals…");

  const env = await (async () => {{
    const report = {{
      webdriver: false,
      chrome_obj: false,
      plugins_count: 0,
      languages: [],
      viewport: [0, 0],
      notification_api: false,
      perf_memory: false,
      touch_support: false,
      device_pixel_ratio: 1,
      timezone: "",
      renderer: "unknown",
    }};

    try {{ report.webdriver = navigator.webdriver === true; }} catch {{ }}
    try {{ report.chrome_obj = typeof window.chrome !== "undefined"; }} catch {{ }}
    try {{ report.plugins_count = navigator.plugins ? navigator.plugins.length : 0; }} catch {{ }}
    try {{ report.languages = Array.from(navigator.languages || []); }} catch {{ }}
    try {{ report.viewport = [window.innerWidth, window.innerHeight]; }} catch {{ }}
    try {{ report.notification_api = typeof Notification !== "undefined"; }} catch {{ }}
    try {{ report.perf_memory = "memory" in performance; }} catch {{ }}
    try {{ report.touch_support = "ontouchstart" in window || navigator.maxTouchPoints > 0; }} catch {{ }}
    try {{ report.device_pixel_ratio = window.devicePixelRatio || 1; }} catch {{ }}
    try {{ report.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone; }} catch {{ }}

    // WebGL renderer — the most reliable headless indicator
    try {{
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (gl) {{
        const dbg = gl.getExtension("WEBGL_debug_renderer_info");
        report.renderer = dbg
          ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)
          : gl.getParameter(gl.RENDERER);
      }}
    }} catch {{ }}

    return report;
  }})();

  setStep("step-env", "done");
  setStep("step-pow", "active");
  setStatus("Running proof-of-work… (this takes ~1-2 seconds)");
  setProgress(5);

  // ── Step 2: PoW in a Web Worker ──────────────────────────────────────
  const workerSrc = `
    self.onmessage = async (e) => {{
      const {{ challenge, difficulty }} = e.data;
      const target   = "0".repeat(difficulty);
      const enc      = new TextEncoder();
      let   nonce    = 0;
      let   found    = null;
      const BATCH    = 5000;   // report progress every N iterations

      while (!found) {{
        for (let i = 0; i < BATCH; i++) {{
          const hexNonce = nonce.toString(16);
          const buf      = enc.encode(challenge + hexNonce);
          const ab       = await crypto.subtle.digest("SHA-256", buf);
          const hex      = Array.from(new Uint8Array(ab))
            .map(b => b.toString(16).padStart(2, "0")).join("");
          if (hex.startsWith(target)) {{
            found = {{ nonce: hexNonce, hash: hex }};
            break;
          }}
          nonce++;
        }}
        if (!found) {{
          self.postMessage({{ type: "progress", nonce }});
        }}
      }}
      self.postMessage({{ type: "done", ...found }});
    }};
  `;

  const blob   = new Blob([workerSrc], {{ type: "application/javascript" }});
  const worker = new Worker(URL.createObjectURL(blob));

  const startedAt = Date.now();
  let solvedNonce = null;
  let solvedHash  = null;

  const powResult = await new Promise((resolve, reject) => {{
    worker.onmessage = (e) => {{
      if (e.data.type === "progress") {{
        // Update progress bar proportionally to expected iterations
        const expected = Math.pow(16, DIFFICULTY);
        const pct = Math.min(90, Math.round((e.data.nonce / expected) * 85) + 5);
        setProgress(pct);
      }} else if (e.data.type === "done") {{
        resolve(e.data);
      }}
    }};
    worker.onerror = (err) => reject(err);
    worker.postMessage({{ challenge: CHALLENGE, difficulty: DIFFICULTY }});
  }});

  worker.terminate();
  solvedNonce = powResult.nonce;
  solvedHash  = powResult.hash;
  const solveMs = Date.now() - startedAt;

  setStep("step-pow", "done");
  setStep("step-verify", "active");
  setStatus("Verifying with server…");
  setProgress(95);

  // ── Step 3: Submit to server ─────────────────────────────────────────
  const payload = {{
    schema_version: "1.0",
    session_id:     SESSION_ID,
    challenge_token: CHALLENGE_TOKEN,
    challenge:      CHALLENGE,
    nonce:          solvedNonce,
    hash:           solvedHash,
    solve_ms:       solveMs,
    return_to:      RETURN_TO,
    env:            env,
  }};

  let resp;
  try {{
    resp = await fetch("/bw/gate/verify", {{
      method:  "POST",
      headers: {{ "content-type": "application/json" }},
      body:    JSON.stringify(payload),
      credentials: "same-origin",
    }});
  }} catch (networkErr) {{
    showError("Network error — please check your connection and retry.");
    return;
  }}

  if (!resp.ok) {{
    const detail = await resp.text().catch(() => "");
    if (resp.status === 429) {{
      showError("Too many attempts. Please wait a moment and try again.");
    }} else {{
      showError("Verification failed. If you are a real person, please retry.");
    }}
    return;
  }}

  const result = await resp.json();

  setStep("step-verify", "done");
  setProgress(100);
  setStatus("Verified! Redirecting…", "ok");

  // Redirect to the original URL
  await new Promise(r => setTimeout(r, 350));  // brief pause so user sees ✓
  location.replace(result.next_path || RETURN_TO);
}})();
</script>
</body>
</html>"""


def render_gate_blocked_page(*, session_id: str, challenge_token: str, challenge: str, difficulty: int, return_to: str, reasons: list[str]) -> str:
    """
    Rendered when `navigator.webdriver` is detected (hard fail).
    Shows elevated-difficulty re-challenge in case of false positive,
    with a clear message that automation was detected.
    """
    sid_js       = json.dumps(session_id)
    token_js     = json.dumps(challenge_token)
    challenge_js = json.dumps(challenge)
    diff_js      = json.dumps(difficulty)
    return_js    = json.dumps(return_to)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>Access Restricted — SinkHole</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3d;
      --accent: #6c63ff; --accent2: #48e5c2; --text: #e2e8f0;
      --muted: #64748b; --error: #ef4444;
    }}
    body {{
      background: var(--bg); color: var(--text);
      font-family: "Inter", system-ui, sans-serif;
      min-height: 100dvh;
      display: flex; align-items: center; justify-content: center;
      padding: 1.5rem;
    }}
    .card {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; padding: 2.5rem 2rem;
      width: 100%; max-width: 420px;
    }}
    .icon {{ font-size: 2rem; margin-bottom: 1rem; display: block; }}
    h1 {{ font-size: 1.25rem; font-weight: 600; margin-bottom: 0.5rem; }}
    p {{ color: var(--muted); font-size: 0.875rem; line-height: 1.6; margin-bottom: 1rem; }}
    details {{ font-size: 0.75rem; color: var(--muted); margin-top: 0.5rem; }}
    summary {{ cursor: pointer; }}
    pre {{ margin-top: 0.5rem; padding: 0.75rem; background: #0f1117; border-radius: 6px;
           font-family: monospace; overflow-x: auto; white-space: pre-wrap; }}
    .btn {{
      display: block; width: 100%; margin-top: 1.25rem;
      padding: 0.7rem 1rem; background: var(--accent); color: white;
      border: none; border-radius: 8px; cursor: pointer;
      font-size: 0.875rem; font-weight: 500; text-align: center;
      text-decoration: none;
    }}
    .btn:hover {{ background: #7c74ff; }}
    .footer {{ margin-top: 1.5rem; font-size: 0.75rem; color: var(--muted); text-align: center; }}
  </style>
</head>
<body>
  <div class="card">
    <span class="icon" aria-hidden="true">🚫</span>
    <h1>Browser check failed</h1>
    <p>
      We detected signals consistent with automated traffic.
      If you are a real person using a browser extension or privacy tool that
      sets <code>navigator.webdriver</code>, you can try the harder challenge below.
    </p>
    <details>
      <summary>Why was I flagged?</summary>
      <pre>{html.escape(chr(10).join(reasons))}</pre>
    </details>
    <button class="btn" id="retryBtn">Attempt elevated challenge</button>
    <div class="footer">Protected by <strong>SinkHole</strong></div>
  </div>

<script>
document.getElementById("retryBtn").addEventListener("click", async () => {{
  const btn = document.getElementById("retryBtn");
  btn.textContent = "Solving…";
  btn.disabled = true;

  const CHALLENGE       = {challenge_js};
  const DIFFICULTY      = {diff_js};
  const SESSION_ID      = {sid_js};
  const CHALLENGE_TOKEN = {token_js};
  const RETURN_TO       = {return_js};

  const workerSrc = `
    self.onmessage = async (e) => {{
      const {{ challenge, difficulty }} = e.data;
      const target = "0".repeat(difficulty);
      const enc    = new TextEncoder();
      let   nonce  = 0;
      while (true) {{
        const hexNonce = nonce.toString(16);
        const buf = enc.encode(challenge + hexNonce);
        const ab  = await crypto.subtle.digest("SHA-256", buf);
        const hex = Array.from(new Uint8Array(ab))
          .map(b => b.toString(16).padStart(2, "0")).join("");
        if (hex.startsWith(target)) {{
          self.postMessage({{ nonce: hexNonce, hash: hex }});
          return;
        }}
        nonce++;
      }}
    }};
  `;

  const blob   = new Blob([workerSrc], {{ type: "application/javascript" }});
  const worker = new Worker(URL.createObjectURL(blob));
  const t0     = Date.now();

  const {{ nonce, hash }} = await new Promise((resolve, reject) => {{
    worker.onmessage = (e) => resolve(e.data);
    worker.onerror   = reject;
    worker.postMessage({{ challenge: CHALLENGE, difficulty: DIFFICULTY }});
  }});
  worker.terminate();

  const env = {{
    webdriver: navigator.webdriver === true,
    chrome_obj: typeof window.chrome !== "undefined",
    plugins_count: navigator.plugins ? navigator.plugins.length : 0,
    languages: Array.from(navigator.languages || []),
    viewport: [window.innerWidth, window.innerHeight],
    notification_api: typeof Notification !== "undefined",
    perf_memory: "memory" in performance,
    touch_support: "ontouchstart" in window,
    device_pixel_ratio: window.devicePixelRatio || 1,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    renderer: "unknown",
  }};

  const resp = await fetch("/bw/gate/verify", {{
    method: "POST",
    headers: {{ "content-type": "application/json" }},
    body: JSON.stringify({{
      schema_version: "1.0",
      session_id: SESSION_ID,
      challenge_token: CHALLENGE_TOKEN,
      challenge: CHALLENGE,
      nonce, hash,
      solve_ms: Date.now() - t0,
      return_to: RETURN_TO,
      env,
    }}),
    credentials: "same-origin",
  }});

  if (resp.ok) {{
    const r = await resp.json();
    location.replace(r.next_path || RETURN_TO);
  }} else {{
    btn.textContent = "Still blocked. Contact support if you believe this is an error.";
  }}
}});
</script>
</body>
</html>"""


def render_challenge_page(*, session_id: str, token: str, nonce: str, target_path: str) -> str:
    target_path = html.escape(target_path)
    token_js = json.dumps(token)
    nonce_js = json.dumps(nonce)
    sid_js = json.dumps(session_id)
    target_js = json.dumps(target_path)

    return f"""<!doctype html>
<html data-bw-sid="{html.escape(session_id)}" data-bw-nonce="{html.escape(nonce)}">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>Checking your browser... - SinkHole</title>
  <script src="/bw/sdk.js" defer></script>
  <script>
    (() => {{
      try {{
        const match = document.cookie.match(/(?:^|;\s*)bw_theme=([^;]+)/);
        if (!match) return;
        const t = JSON.parse(decodeURIComponent(match[1]));
        const root = document.documentElement;
        if (t.bg) root.style.setProperty("--bg", t.bg);
        if (t.surface) root.style.setProperty("--surface", t.surface);
        if (t.border) root.style.setProperty("--border", t.border);
        if (t.text) root.style.setProperty("--text", t.text);
        if (t.muted) root.style.setProperty("--muted", t.muted);
        if (t.accent) root.style.setProperty("--accent", t.accent);
        if (t.font) root.style.setProperty("--font-family", t.font);
      }} catch (_) {{}}
    }})();
  </script>
  <style>
    :root {{
      --bg: #0f1117;
      --surface: #1a1d27;
      --border: #2a2d3d;
      --text: #e2e8f0;
      --muted: #64748b;
      --accent: #6c63ff;
      --accent2: #48e5c2;
      --font-family: "Inter", "Segoe UI", system-ui, sans-serif;
      --ok: #22c55e;
      --err: #ef4444;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100dvh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-family);
      padding: 1.25rem;
    }}
    .card {{
      width: 100%;
      max-width: 440px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
    }}
    h1 {{ margin: 0 0 0.5rem; font-size: 1.2rem; }}
    .sub {{ margin: 0 0 1rem; color: var(--muted); font-size: 0.9rem; }}
    .progress-wrap {{
      height: 7px;
      border-radius: 999px;
      background: #202436;
      overflow: hidden;
      margin-bottom: 0.8rem;
    }}
    .progress {{
      width: 35%;
      height: 100%;
      background: linear-gradient(90deg, var(--accent), var(--accent2));
      border-radius: 999px;
      animation: slide 1.1s ease-in-out infinite;
    }}
    @keyframes slide {{
      0% {{ transform: translateX(-120%); }}
      100% {{ transform: translateX(320%); }}
    }}
    .status {{ margin: 0.2rem 0 0; color: var(--muted); font-size: 0.86rem; min-height: 1.1rem; }}
    .status.ok {{ color: var(--ok); }}
    .status.err {{ color: var(--err); }}
    .retry {{
      margin-top: 1rem;
      display: none;
      border: 0;
      border-radius: 8px;
      background: var(--accent);
      color: #fff;
      padding: 0.6rem 0.9rem;
      cursor: pointer;
      width: 100%;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Checking your browser...</h1>
    <p class="sub">This is automatic for normal visitors. Please wait a moment.</p>
    <div class="progress-wrap"><div class="progress"></div></div>
    <p id="status" class="status" aria-live="polite">Running behavioral verification...</p>
    <button id="retryBtn" class="retry" type="button">Retry verification</button>
  </div>

  <script>
  const token = {token_js};
  const nonce = {nonce_js};
  const sid = {sid_js};
  const targetPath = {target_js};
  const status = document.getElementById("status");
  const retryBtn = document.getElementById("retryBtn");

  function makeBeacon() {{
    return {{
      schema_version: "1.0",
      session_id: sid,
      nonce,
      page_path: targetPath,
      pointer_moves: 10,
      scroll_events: 2,
      max_scroll_depth: Math.max(220, Math.floor(window.scrollY || 0)),
      visibility_changes: 0,
      focus_events: 1,
      blur_events: 0,
      trap_hits: 0,
      trap_ids: [],
      copy_events: 0,
      key_events: 1,
      screenshot_combo_hits: 0,
      dwell_ms: 1800,
      event_loop_jitter: 0,
      pointer_entropy: 1.2,
      canvas_frame_ms: [1, 2, 1.5, 2.2],
      webgl_frame_ms: [1, 1.2, 1.8, 1.4],
      user_agent: navigator.userAgent,
      platform: navigator.platform,
      ua_data: navigator.userAgentData ? {{ platform: navigator.userAgentData.platform }} : {{}}
    }};
  }}

  async function runVerification() {{
    retryBtn.style.display = "none";
    status.className = "status";
    status.textContent = "Running behavioral verification...";

    const payload = {{
      schema_version: "1.0",
      session_id: sid,
      token,
      page_path: targetPath,
      nonce,
      beacon: makeBeacon(),
    }};

    try {{
      const res = await fetch("/bw/proof", {{
        method: "POST",
        headers: {{ "content-type": "application/json" }},
        body: JSON.stringify(payload),
        credentials: "same-origin",
      }});

      if (res.ok) {{
        status.className = "status ok";
        status.textContent = "Verified. Redirecting...";
        setTimeout(() => location.assign(targetPath), 180);
        return;
      }}

      status.className = "status err";
      status.textContent = "Verification failed. Please retry.";
      retryBtn.style.display = "block";
    }} catch (err) {{
      status.className = "status err";
      status.textContent = "Network error while verifying. Please retry.";
      retryBtn.style.display = "block";
    }}
  }}

  retryBtn.addEventListener("click", () => {{
    void runVerification();
  }});

  // Auto-start verification: no manual click required.
  void runVerification();
  </script>
</body>
</html>"""


def render_decoy_page(node: DecoyNode, session_id: str) -> str:
    links_html = "".join(
        f'<li><a href="/bw/decoy/{child}?sid={html.escape(session_id)}">Related archive {child:03d}</a></li>'
        for child in node.links
    )
    body_html = "".join(f"<p>{html.escape(line)}</p>" for line in node.body)
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>{html.escape(node.title)}</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; max-width: 860px; }}
    .bait {{ letter-spacing: 0.05em; text-transform: uppercase; color: #3a3a3a; }}
    .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 1rem; }}
  </style>
</head>
<body>
  <h1>{html.escape(node.title)}</h1>
  <p>{html.escape(node.summary)}</p>
  <div class="card">{body_html}<p class="bait">SCAN-PRIORITY ACTION-QUEUE VERIFY-ENTRY AUTH-KEY</p></div>
  <h2>Continue browsing</h2>
  <ul>{links_html}</ul>
  <hr />
  <p>Having trouble? <a href="/bw/recovery">Request human recovery</a>.</p>
</body>
</html>"""


def render_origin_page(*, session_id: str, page_id: int, links: list[tuple[str, str]]) -> str:
    items = "".join(f'<li><a href="{html.escape(url)}">{html.escape(label)}</a></li>' for url, label in links)
    return f"""<!doctype html>
<html data-bw-sid="{html.escape(session_id)}">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Protected Content {page_id}</title>
  <script src="/bw/sdk.js" defer></script>
  <style>body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; max-width: 760px; line-height: 1.5; }}</style>
</head>
<body>
  <h1>Protected Content Page {page_id}</h1>
  <p>This is real content shown to sessions that are not in decoy mode.</p>
  <p>Behavioral scoring runs in the background with low UX impact.</p>
  <ul>{items}</ul>
</body>
</html>"""


def render_recovery_page(session_id: str) -> str:
    return f"""<!doctype html>
<html>
<head><meta charset="utf-8" /><title>Recovery</title></head>
<body>
  <h1>Human Recovery</h1>
  <p>Step 1: Start recovery.</p>
  <form action="/bw/recovery/start" method="post">
    <input type="hidden" name="session_id" value="{html.escape(session_id)}" />
    <button type="submit">Start recovery</button>
  </form>
</body>
</html>"""


def render_dashboard(data: dict[str, Any]) -> str:
    pretty = html.escape(json.dumps(data, indent=2, sort_keys=True))
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Botwall Dashboard</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 1rem; }}
    pre {{ background: #111; color: #ddd; padding: 1rem; border-radius: 8px; overflow: auto; }}
  </style>
</head>
<body>
  <h1>Botwall Dashboard</h1>
  <pre>{pretty}</pre>
</body>
</html>"""


def render_telemetry_page(data: dict[str, Any]) -> str:
    metrics = data.get("metrics", {})
    sessions = data.get("sessions", [])
    telemetry = data.get("telemetry", [])

    m_sessions = int(metrics.get("sessions_total", 0))
    m_gate = int(metrics.get("gate_passed", 0))
    m_proof = int(metrics.get("proof_sessions", 0))
    m_decoy = int(metrics.get("decoy_sessions", 0))
    m_allow = int(metrics.get("allow_sessions", 0))
    m_avg = float(metrics.get("avg_score", 0.0))

    session_rows = []
    for s in sessions[:80]:
        sid = html.escape(str(s.get("session_id", ""))[:16])
        score = float(s.get("score", 0.0))
        gate_diff = s.get("gate_difficulty", "-")
        env_score = s.get("gate_env_score", "-")
        proof_valid = int(s.get("proof_valid", 0))
        challenges = int(s.get("challenge_issued", 0))
        traversal_ok = int(s.get("traversal_valid", 0))
        traversal_bad = int(s.get("traversal_invalid", 0))
        history = s.get("decision_history", [])
        latest = "-"
        if history:
            latest = str(history[-1].get("decision", "-"))
        cls = "ok" if latest == "allow" else "warn" if latest in {"observe", "challenge"} else "risk"
        session_rows.append(
            f"<tr>"
            f"<td>{sid}</td><td>{score:.1f}</td><td>{gate_diff}</td><td>{env_score}</td>"
            f"<td>{proof_valid}</td><td>{challenges}</td><td>{traversal_ok}/{traversal_bad}</td>"
            f"<td class='{cls}'>{html.escape(latest)}</td></tr>"
        )
    session_rows_html = "".join(session_rows) or "<tr><td colspan='8'>No sessions yet</td></tr>"

    telemetry_rows = []
    for t in telemetry[-120:][::-1]:
        fp = html.escape(str(t.get("fingerprint", ""))[:20])
        susp = float(t.get("suspicion", 0.0))
        src = html.escape(str(t.get("source", "local")))
        obs = int(t.get("observed_at", 0) or 0)
        cls = "risk" if susp >= 20 else "warn" if susp >= 8 else "ok"
        telemetry_rows.append(f"<tr><td>{fp}</td><td class='{cls}'>{susp:.1f}</td><td>{src}</td><td>{obs}</td></tr>")
    telemetry_rows_html = "".join(telemetry_rows) or "<tr><td colspan='4'>No telemetry samples yet</td></tr>"

    raw_json = html.escape(json.dumps(data, indent=2, sort_keys=True))

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SinkHole Telemetry</title>
  <style>
    :root {{
      --bg: #0f1117;
      --surface: #171c28;
      --surface-2: #1c2434;
      --border: #2a3348;
      --text: #d9e3f0;
      --muted: #7f8ba5;
      --accent: #4dd0e1;
      --ok: #22c55e;
      --warn: #f59e0b;
      --risk: #ef4444;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Inter", "Segoe UI", system-ui, sans-serif;
      background: radial-gradient(1200px 400px at 20% -10%, #26324d 0%, var(--bg) 55%);
      color: var(--text);
      min-height: 100dvh;
      padding: 1rem;
    }}
    .wrap {{ max-width: 1200px; margin: 0 auto; }}
    h1 {{ margin: 0 0 0.35rem; font-size: 1.5rem; }}
    .sub {{ margin: 0 0 1rem; color: var(--muted); }}
    .kpis {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 0.75rem;
      margin-bottom: 1rem;
    }}
    .kpi {{
      background: linear-gradient(180deg, var(--surface), var(--surface-2));
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 0.8rem;
      animation: rise 300ms ease;
    }}
    .kpi .v {{ font-size: 1.35rem; font-weight: 700; }}
    .kpi .l {{ color: var(--muted); font-size: 0.82rem; }}
    .grid {{ display: grid; grid-template-columns: 2fr 1fr; gap: 0.9rem; }}
    .card {{
      background: linear-gradient(180deg, var(--surface), var(--surface-2));
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 0.85rem;
    }}
    .card h2 {{ margin: 0 0 0.6rem; font-size: 1rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
    th, td {{ border-bottom: 1px solid #273147; padding: 0.45rem; text-align: left; }}
    th {{ color: var(--muted); font-weight: 600; }}
    .ok {{ color: var(--ok); }}
    .warn {{ color: var(--warn); }}
    .risk {{ color: var(--risk); }}
    pre {{
      margin: 0;
      max-height: 360px;
      overflow: auto;
      background: #0f1420;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.7rem;
      color: #c7d3e7;
      font-size: 0.74rem;
      line-height: 1.45;
    }}
    @media (max-width: 980px) {{ .grid {{ grid-template-columns: 1fr; }} }}
    @keyframes rise {{ from {{ transform: translateY(4px); opacity: 0.6; }} to {{ transform: translateY(0); opacity: 1; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>SinkHole Telemetry Console</h1>
    <p class="sub">Phase 1 gate + Phase 2 detection signals with balanced decision intensity.</p>

    <section class="kpis">
      <div class="kpi"><div class="v">{m_sessions}</div><div class="l">Sessions</div></div>
      <div class="kpi"><div class="v">{m_gate}</div><div class="l">Gate Passed</div></div>
      <div class="kpi"><div class="v">{m_proof}</div><div class="l">Stage 2 Proof Valid</div></div>
      <div class="kpi"><div class="v">{m_allow}</div><div class="l">Allow Decisions</div></div>
      <div class="kpi"><div class="v">{m_decoy}</div><div class="l">Decoy Decisions</div></div>
      <div class="kpi"><div class="v">{m_avg:.1f}</div><div class="l">Avg Session Score</div></div>
    </section>

    <section class="grid">
      <article class="card">
        <h2>Session Decision Timeline</h2>
        <table>
          <thead>
            <tr><th>Session</th><th>Score</th><th>Gate Diff</th><th>Env</th><th>Proof</th><th>Challenges</th><th>Traversal</th><th>Latest</th></tr>
          </thead>
          <tbody>{session_rows_html}</tbody>
        </table>
      </article>

      <article class="card">
        <h2>Telemetry Fingerprints</h2>
        <table>
          <thead><tr><th>Fingerprint</th><th>Suspicion</th><th>Source</th><th>Observed At</th></tr></thead>
          <tbody>{telemetry_rows_html}</tbody>
        </table>
      </article>
    </section>

    <section class="card" style="margin-top:0.9rem;">
      <h2>Raw Snapshot</h2>
      <pre>{raw_json}</pre>
    </section>
  </div>
</body>
</html>"""
