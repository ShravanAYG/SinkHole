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
  <title>Verification</title>
  <script src="/bw/sdk.js" defer></script>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; max-width: 720px; }}
    button {{ padding: 0.7rem 1rem; cursor: pointer; }}
    .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 1rem; }}
  </style>
</head>
<body>
  <h1>Quick verification</h1>
  <div class="card">
    <p>We need a short browser proof to continue. This usually takes less than one second.</p>
    <button id="verifyBtn">Verify and Continue</button>
    <p id="status" aria-live="polite"></p>
  </div>
  <script>
  const token = {token_js};
  const nonce = {nonce_js};
  const sid = {sid_js};
  const targetPath = {target_js};
  const btn = document.getElementById("verifyBtn");
  const status = document.getElementById("status");

  btn.addEventListener("click", async () => {{
    btn.disabled = true;
    status.textContent = "Verifying...";
    const beacon = {{
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

    const payload = {{ schema_version: "1.0", session_id: sid, token, page_path: targetPath, nonce, beacon }};
    const res = await fetch("/bw/proof", {{
      method: "POST",
      headers: {{ "content-type": "application/json" }},
      body: JSON.stringify(payload)
    }});

    if (res.ok) {{
      status.textContent = "Verified. Redirecting...";
      location.assign(targetPath);
    }} else {{
      status.textContent = "Verification failed. You can retry.";
      btn.disabled = false;
    }}
  }});
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


def render_gate_challenge_page(*, session_id: str, challenge: str, difficulty: int, target_path: str) -> str:
    challenge_js = json.dumps(challenge)
    difficulty_js = json.dumps(difficulty)
    target_js = json.dumps(target_path)
    
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>Verifying your browser...</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; max-width: 720px; }}
    .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 1rem; text-align: center; }}
    .spinner {{ display: inline-block; width: 30px; height: 30px; border: 3px solid rgba(0,0,0,.3); border-radius: 50%; border-top-color: #000; animation: spin 1s ease-in-out infinite; }}
    @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
  </style>
</head>
<body>
  <div class="card">
    <h2>Checking your browser before accessing the site.</h2>
    <p>This process is automatic. Your browser will redirect to your requested content shortly.</p>
    <div class="spinner"></div>
    <p id="status" aria-live="polite">Running security check...</p>
  </div>
  
  <script>
    const challenge = {challenge_js};
    const difficulty = {difficulty_js};
    const targetPath = {target_js};
    
    // Concurrently gather env report while web worker crunches PoW
    const getEnvReport = () => {{
      const getRenderer = () => {{
        try {{
          const c = document.createElement("canvas");
          const gl = c.getContext("webgl");
          if (!gl) return "none";
          const dbg = gl.getExtension("WEBGL_debug_renderer_info");
          return dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : "unknown";
        }} catch {{ return "error"; }}
      }};
      
      return {{
        webdriver: navigator.webdriver === true,
        chrome_obj: typeof window.chrome !== "undefined",
        plugins_count: navigator.plugins.length,
        languages: navigator.languages ? Array.from(navigator.languages) : [],
        viewport: [window.innerWidth, window.innerHeight],
        notification_api: (() => {{
          try {{ return typeof Notification !== "undefined"; }} catch {{ return false; }}
        }})(),
        perf_memory: "memory" in performance,
        touch_support: "ontouchstart" in window,
        device_pixel_ratio: window.devicePixelRatio || 1,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        renderer: getRenderer()
      }};
    }};

    const workerSrc = `
      self.onmessage = async (e) => {{
        const {{ challenge, difficulty }} = e.data;
        let nonce = 0;
        const target = "0".repeat(difficulty);

        while (true) {{
          const input = challenge + nonce.toString(16);
          const buf = new TextEncoder().encode(input);
          const hashBuf = await crypto.subtle.digest("SHA-256", buf);
          const hex = Array.from(new Uint8Array(hashBuf))
            .map(b => b.toString(16).padStart(2, "0")).join("");
            
          if (hex.startsWith(target)) {{
            self.postMessage({{ nonce: nonce.toString(16), hash: hex }});
            return;
          }}
          nonce++;
        }}
      }};
    `;

    const blob = new Blob([workerSrc], {{type: "application/javascript"}});
    const worker = new Worker(URL.createObjectURL(blob));

    worker.onmessage = async (e) => {{
      const {{ nonce }} = e.data;
      const env_report = getEnvReport();
      const statusEl = document.getElementById("status");
      statusEl.textContent = "Verifying result...";
      
      try {{
        const res = await fetch("/bw/gate/verify", {{
          method: "POST",
          headers: {{"Content-Type": "application/json"}},
          body: JSON.stringify({{ challenge, nonce, env_report }})
        }});
        
        if (res.ok) {{
          const data = await res.json();
          if (data.ok) {{
            statusEl.textContent = "Redirecting...";
            let next = new URLSearchParams(window.location.search).get("path") || targetPath;
            if (!next.startsWith("/")) next = "/"; // safety
            window.location.assign(next);
            return;
          }}
        }}
        statusEl.textContent = "Verification failed. Please refresh.";
      }} catch (err) {{
        statusEl.textContent = "Network error. Please try again.";
      }}
    }};

    worker.postMessage({{ challenge, difficulty }});
  </script>
</body>
</html>"""
