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
    template = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>Browser verification - SinkHole</title>
  <script>
    (() => {
      try {
        const match = document.cookie.match(/(?:^|;\\s*)bw_theme=([^;]+)/);
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
      } catch (_) {}
    })();
  </script>
  <style>
    :root {
      --bg: #f4efe2;
      --surface: rgba(255, 252, 245, 0.88);
      --border: #d7ccb8;
      --text: #1d2430;
      --muted: #5f6774;
      --accent: #0b63ce;
      --accent-2: #1aa179;
      --ok: #1a7f37;
      --err: #b42318;
      --font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
      --ui-family: "IBM Plex Sans", "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    html, body { min-height: 100%; }
    body {
      margin: 0;
      min-height: 100dvh;
      background:
        radial-gradient(circle at top, rgba(11, 99, 206, 0.10), transparent 32%),
        linear-gradient(180deg, rgba(255, 255, 255, 0.65), rgba(244, 239, 226, 0.95));
      color: var(--text);
      font-family: var(--font-family);
      display: grid;
      place-items: center;
      padding: 20px;
    }
    .shell {
      width: min(920px, 100%);
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(240px, 0.8fr);
      gap: 18px;
      align-items: stretch;
    }
    .panel,
    .side {
      border: 1px solid var(--border);
      background: var(--surface);
      backdrop-filter: blur(10px);
      box-shadow: 0 20px 60px rgba(34, 36, 38, 0.10);
    }
    .panel {
      border-radius: 22px;
      padding: 26px;
    }
    .side {
      border-radius: 18px;
      padding: 22px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .eyebrow {
      margin: 0 0 10px;
      font: 700 12px/1 var(--ui-family);
      letter-spacing: 0.18em;
      color: var(--accent);
    }
    h1 {
      margin: 0;
      font-size: clamp(2rem, 4vw, 3.3rem);
      line-height: 0.96;
      letter-spacing: -0.04em;
      max-width: 10ch;
    }
    .lede {
      margin: 16px 0 0;
      max-width: 46ch;
      color: var(--muted);
      font: 500 15px/1.7 var(--ui-family);
    }
    .meter {
      margin-top: 24px;
      padding: 14px;
      border-radius: 16px;
      border: 1px solid rgba(29, 36, 48, 0.10);
      background: rgba(255, 255, 255, 0.55);
    }
    .meter-bar {
      height: 10px;
      border-radius: 999px;
      background: rgba(29, 36, 48, 0.10);
      overflow: hidden;
    }
    .meter-fill {
      width: 14%;
      height: 100%;
      border-radius: inherit;
      background: linear-gradient(90deg, var(--accent), var(--accent-2));
      box-shadow: 0 0 22px rgba(11, 99, 206, 0.35);
      transition: width 0.18s ease;
    }
    .status {
      margin: 12px 0 0;
      min-height: 1.2em;
      color: var(--muted);
      font: 500 14px/1.5 var(--ui-family);
    }
    .status.ok { color: var(--ok); }
    .status.err { color: var(--err); }
    .rail {
      margin: 18px 0 0;
      padding: 0;
      list-style: none;
      display: grid;
      gap: 10px;
    }
    .rail li {
      display: grid;
      grid-template-columns: 26px 1fr;
      gap: 12px;
      align-items: center;
      padding: 10px 12px;
      border-radius: 14px;
      color: var(--muted);
      font: 500 14px/1.4 var(--ui-family);
      background: rgba(255, 255, 255, 0.42);
    }
    .rail li.active,
    .rail li.done {
      color: var(--text);
    }
    .icon {
      width: 26px;
      height: 26px;
      display: grid;
      place-items: center;
      border-radius: 999px;
      border: 1px solid rgba(29, 36, 48, 0.14);
      font: 700 12px/1 var(--ui-family);
      background: rgba(255, 255, 255, 0.8);
    }
    .rail li.active .icon {
      color: #fff;
      background: var(--accent);
      border-color: var(--accent);
    }
    .rail li.done .icon {
      color: #fff;
      background: var(--ok);
      border-color: var(--ok);
    }
    .retry-btn {
      display: none;
      margin-top: 16px;
      width: 100%;
      border: 0;
      border-radius: 999px;
      padding: 12px 16px;
      background: var(--text);
      color: #fff;
      cursor: pointer;
      font: 700 13px/1 var(--ui-family);
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }
    .side-label {
      margin: 0;
      color: var(--muted);
      font: 700 11px/1 var(--ui-family);
      letter-spacing: 0.14em;
    }
    .facts {
      display: grid;
      gap: 14px;
      margin-top: 16px;
    }
    .fact {
      padding-top: 14px;
      border-top: 1px solid rgba(29, 36, 48, 0.10);
    }
    .fact strong {
      display: block;
      margin-bottom: 5px;
      font: 700 12px/1.2 var(--ui-family);
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }
    .fact span {
      color: var(--muted);
      font: 500 14px/1.6 var(--ui-family);
    }
    .seal {
      margin-top: 18px;
      padding-top: 16px;
      border-top: 1px solid rgba(29, 36, 48, 0.10);
      color: var(--muted);
      font: 500 12px/1.6 var(--ui-family);
    }
    @media (max-width: 820px) {
      .shell { grid-template-columns: 1fr; }
      h1 { max-width: none; }
    }
  </style>
</head>
<body>
  <main class="shell" role="main" aria-labelledby="heading">
    <section class="panel">
      <p class="eyebrow">TRAFFIC VERIFICATION</p>
      <h1 id="heading">Proving this request came from a real browser.</h1>
      <p class="lede">
        A lightweight proof-of-work is running in your browser while we check for automation signals.
        Normal visitors do not need to click anything.
      </p>

      <div class="meter" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" id="progressWrap">
        <div class="meter-bar"><div class="meter-fill" id="progressBar"></div></div>
        <p class="status" id="statusText" aria-live="polite">Preparing browser verification...</p>
      </div>

      <ol class="rail" aria-label="Verification steps">
        <li id="step-env"><span class="icon" aria-hidden="true">1</span><span>Collect browser environment signals</span></li>
        <li id="step-pow"><span class="icon" aria-hidden="true">2</span><span>Compute a browser-side proof token</span></li>
        <li id="step-verify"><span class="icon" aria-hidden="true">3</span><span>Bind the solved proof to this request</span></li>
      </ol>

      <button class="retry-btn" id="retryBtn" type="button">Retry verification</button>
    </section>

    <aside class="side" aria-label="Verification notes">
      <div>
        <p class="side-label">What is happening</p>
        <div class="facts">
          <div class="fact">
            <strong>Client-side hashing</strong>
            <span>The challenge runs in the browser first, then the solved token is bound to your session on the server.</span>
          </div>
          <div class="fact">
            <strong>Fast path for people</strong>
            <span>Difficulty is tuned to complete quickly on typical browsers and will fall back if worker execution is unavailable.</span>
          </div>
          <div class="fact">
            <strong>No form to fill</strong>
            <span>If the browser looks healthy, the page redirects automatically as soon as verification succeeds.</span>
          </div>
        </div>
      </div>
      <div class="seal">Protected by SinkHole. This page avoids indexing and does not expose origin content before verification completes.</div>
    </aside>
  </main>

<script id="mainScript">
(async () => {
  const SESSION_ID = __SID_JS__;
  const CHALLENGE_TOKEN = __TOKEN_JS__;
  const CHALLENGE = __CHALLENGE_JS__;
  const DIFFICULTY = __DIFFICULTY_JS__;
  const RETURN_TO = __RETURN_TO_JS__;
  const MAX_SOLVE_MS = 28000;

  const progressBar = document.getElementById("progressBar");
  const progressWrap = document.getElementById("progressWrap");
  const statusText = document.getElementById("statusText");
  const retryBtn = document.getElementById("retryBtn");

  retryBtn.addEventListener("click", () => location.reload());

  function setStep(id, state) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove("done", "active");
    if (state) el.classList.add(state);
    const icon = el.querySelector(".icon");
    if (!icon) return;
    icon.textContent = state === "done" ? "OK" : state === "active" ? ".." : icon.textContent;
  }

  function setProgress(pct) {
    const normalized = Math.max(0, Math.min(100, Math.round(pct)));
    progressBar.style.width = normalized + "%";
    progressWrap.setAttribute("aria-valuenow", String(normalized));
  }

  function setStatus(msg, cls) {
    statusText.textContent = msg;
    statusText.className = "status" + (cls ? " " + cls : "");
  }

  function showError(msg) {
    setStatus(msg, "err");
    retryBtn.style.display = "block";
    setProgress(0);
  }

  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }

  function utf8Bytes(input) {
    if (window.TextEncoder) {
      return Array.from(new TextEncoder().encode(input));
    }
    return Array.from(unescape(encodeURIComponent(input)), (ch) => ch.charCodeAt(0));
  }

  function sha256Hex(input) {
    const bytes = utf8Bytes(input);
    const words = [];
    for (let index = 0; index < bytes.length; index += 1) {
      words[index >> 2] = (words[index >> 2] || 0) | (bytes[index] << (24 - ((index % 4) * 8)));
    }

    const bitLength = bytes.length * 8;
    words[bitLength >> 5] = (words[bitLength >> 5] || 0) | (0x80 << (24 - (bitLength % 32)));
    words[(((bitLength + 64) >> 9) << 4) + 15] = bitLength;

    const initial = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    const constants = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    for (let offset = 0; offset < words.length; offset += 16) {
      const schedule = new Array(64);
      for (let i = 0; i < 16; i += 1) {
        schedule[i] = words[offset + i] | 0;
      }
      for (let i = 16; i < 64; i += 1) {
        const s0 = rightRotate(schedule[i - 15], 7) ^ rightRotate(schedule[i - 15], 18) ^ (schedule[i - 15] >>> 3);
        const s1 = rightRotate(schedule[i - 2], 17) ^ rightRotate(schedule[i - 2], 19) ^ (schedule[i - 2] >>> 10);
        schedule[i] = (((schedule[i - 16] + s0) | 0) + ((schedule[i - 7] + s1) | 0)) | 0;
      }

      let [a, b, c, d, e, f, g, h] = initial;
      for (let i = 0; i < 64; i += 1) {
        const s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 = (((((h + s1) | 0) + ch) | 0) + ((constants[i] + schedule[i]) | 0)) | 0;
        const s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (s0 + maj) | 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) | 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) | 0;
      }

      initial[0] = (initial[0] + a) | 0;
      initial[1] = (initial[1] + b) | 0;
      initial[2] = (initial[2] + c) | 0;
      initial[3] = (initial[3] + d) | 0;
      initial[4] = (initial[4] + e) | 0;
      initial[5] = (initial[5] + f) | 0;
      initial[6] = (initial[6] + g) | 0;
      initial[7] = (initial[7] + h) | 0;
    }

    return initial.map((value) => (value >>> 0).toString(16).padStart(8, "0")).join("");
  }

  async function digestHex(input) {
    if (window.crypto && window.crypto.subtle && window.TextEncoder) {
      const bytes = new TextEncoder().encode(input);
      const hashBuffer = await window.crypto.subtle.digest("SHA-256", bytes);
      return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
    }
    return sha256Hex(input);
  }

  async function solvePowInMainThread(challenge, difficulty) {
    const target = "0".repeat(difficulty);
    const startedAt = Date.now();
    let nonce = 0;
    const batchSize = difficulty >= 5 ? 1000 : 2200;
    while (Date.now() - startedAt < MAX_SOLVE_MS) {
      for (let i = 0; i < batchSize; i += 1) {
        const hexNonce = nonce.toString(16);
        const digest = await digestHex(challenge + hexNonce);
        if (digest.startsWith(target)) {
          return { nonce: hexNonce, hash: digest, solveMs: Date.now() - startedAt };
        }
        nonce += 1;
      }
      const expected = Math.max(1, Math.pow(16, difficulty));
      setProgress(Math.min(90, 12 + ((nonce / expected) * 78)));
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    throw new Error("Browser verification timed out. Please retry.");
  }

  async function solvePowWithWorker(challenge, difficulty) {
    if (!(window.Worker && window.Blob && window.URL)) {
      return solvePowInMainThread(challenge, difficulty);
    }

    const workerSrc = `
      function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
      }

      function utf8Bytes(input) {
        if (self.TextEncoder) {
          return Array.from(new TextEncoder().encode(input));
        }
        return Array.from(unescape(encodeURIComponent(input)), (ch) => ch.charCodeAt(0));
      }

      function sha256Hex(input) {
        const bytes = utf8Bytes(input);
        const words = [];
        for (let index = 0; index < bytes.length; index += 1) {
          words[index >> 2] = (words[index >> 2] || 0) | (bytes[index] << (24 - ((index % 4) * 8)));
        }

        const bitLength = bytes.length * 8;
        words[bitLength >> 5] = (words[bitLength >> 5] || 0) | (0x80 << (24 - (bitLength % 32)));
        words[(((bitLength + 64) >> 9) << 4) + 15] = bitLength;

        const state = [
          0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        const constants = [
          0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
          0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
          0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
          0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
          0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
          0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
          0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
          0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];

        for (let offset = 0; offset < words.length; offset += 16) {
          const schedule = new Array(64);
          for (let i = 0; i < 16; i += 1) {
            schedule[i] = words[offset + i] | 0;
          }
          for (let i = 16; i < 64; i += 1) {
            const s0 = rightRotate(schedule[i - 15], 7) ^ rightRotate(schedule[i - 15], 18) ^ (schedule[i - 15] >>> 3);
            const s1 = rightRotate(schedule[i - 2], 17) ^ rightRotate(schedule[i - 2], 19) ^ (schedule[i - 2] >>> 10);
            schedule[i] = (((schedule[i - 16] + s0) | 0) + ((schedule[i - 7] + s1) | 0)) | 0;
          }

          let a = state[0];
          let b = state[1];
          let c = state[2];
          let d = state[3];
          let e = state[4];
          let f = state[5];
          let g = state[6];
          let h = state[7];
          for (let i = 0; i < 64; i += 1) {
            const s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (((((h + s1) | 0) + ch) | 0) + ((constants[i] + schedule[i]) | 0)) | 0;
            const s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (s0 + maj) | 0;
            h = g;
            g = f;
            f = e;
            e = (d + temp1) | 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) | 0;
          }

          state[0] = (state[0] + a) | 0;
          state[1] = (state[1] + b) | 0;
          state[2] = (state[2] + c) | 0;
          state[3] = (state[3] + d) | 0;
          state[4] = (state[4] + e) | 0;
          state[5] = (state[5] + f) | 0;
          state[6] = (state[6] + g) | 0;
          state[7] = (state[7] + h) | 0;
        }

        return state.map((value) => (value >>> 0).toString(16).padStart(8, "0")).join("");
      }

      self.onmessage = async (event) => {
        const challenge = event.data.challenge;
        const difficulty = event.data.difficulty;
        const target = "0".repeat(difficulty);
        const startedAt = Date.now();
        let nonce = 0;
        const batchSize = difficulty >= 5 ? 1600 : 3000;

        while (Date.now() - startedAt < 28000) {
          for (let i = 0; i < batchSize; i += 1) {
            const hexNonce = nonce.toString(16);
            const digest = sha256Hex(challenge + hexNonce);
            if (digest.startsWith(target)) {
              self.postMessage({ type: "done", nonce: hexNonce, hash: digest, solveMs: Date.now() - startedAt });
              return;
            }
            nonce += 1;
          }
          self.postMessage({ type: "progress", nonce: nonce, difficulty: difficulty });
        }

        self.postMessage({ type: "timeout" });
      };
    `;

    const blob = new Blob([workerSrc], { type: "application/javascript" });
    const worker = new Worker(window.URL.createObjectURL(blob));

    try {
      return await new Promise((resolve, reject) => {
        worker.onmessage = (event) => {
          const data = event.data || {};
          if (data.type === "progress") {
            const expected = Math.max(1, Math.pow(16, data.difficulty || difficulty));
            setProgress(Math.min(90, 12 + ((data.nonce / expected) * 78)));
            return;
          }
          if (data.type === "done") {
            resolve({ nonce: data.nonce, hash: data.hash, solveMs: data.solveMs });
            return;
          }
          reject(new Error("timeout"));
        };
        worker.onerror = () => reject(new Error("worker"));
        worker.postMessage({ challenge, difficulty });
      });
    } catch (_) {
      return solvePowInMainThread(challenge, difficulty);
    } finally {
      worker.terminate();
    }
  }

  async function collectEnv() {
    const report = {
      webdriver: false,
      chrome_obj: false,
      plugins_count: 0,
      plugins_detail: [],
      languages: [],
      viewport: [0, 0],
      screen_avail_width: 0,
      screen_avail_height: 0,
      device_pixel_ratio: 1,
      notification_api: false,
      perf_memory: false,
      hardware_concurrency: 0,
      device_memory: 0,
      touch_support: false,
      timezone: "",
      renderer: "unknown",
      automation_score: 0,
      container_indicators: [],
      cdp_detected: false,
      permissions: {},
      js_globals: [],
      solve_time_ms: 0,
    };

    try { report.webdriver = navigator.webdriver === true; } catch (_) {}
    try { report.chrome_obj = typeof window.chrome !== "undefined"; } catch (_) {}
    try { report.plugins_count = navigator.plugins ? navigator.plugins.length : 0; } catch (_) {}
    
    // Detailed plugin info for fingerprinting
    try {
      if (navigator.plugins) {
        report.plugins_detail = Array.from(navigator.plugins).slice(0, 5).map(p => ({
          name: p.name || "",
          description: p.description || "",
          filename: p.filename || "",
        }));
      }
    } catch (_) {}
    
    try { report.languages = Array.from(navigator.languages || []); } catch (_) {}
    try { report.viewport = [window.innerWidth || 0, window.innerHeight || 0]; } catch (_) {}
    try { report.screen_avail_width = window.screen ? window.screen.availWidth || 0 : 0; } catch (_) {}
    try { report.screen_avail_height = window.screen ? window.screen.availHeight || 0 : 0; } catch (_) {}
    try { report.notification_api = typeof Notification !== "undefined"; } catch (_) {}
    try { report.perf_memory = "memory" in performance; } catch (_) {}
    try { report.touch_support = "ontouchstart" in window || navigator.maxTouchPoints > 0; } catch (_) {}
    try { report.device_pixel_ratio = window.devicePixelRatio || 1; } catch (_) {}
    try { report.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (_) {}
    try { report.hardware_concurrency = navigator.hardwareConcurrency || 0; } catch (_) {}
    try { report.device_memory = navigator.deviceMemory || 0; } catch (_) {}

    // Advanced automation detection for services like Firecrawl
    try {
      let autoScore = 0;
      
      // Check for automation properties that stealth plugins can't fully hide
      if (window.outerWidth === 0 && window.outerHeight === 0) autoScore += 25;
      if (window.devicePixelRatio === 1 && window.screen?.width > 1920) autoScore += 15;
      
      // Check for Chrome's automation signature (CDP)
      if (window.chrome && window.chrome.runtime) {
        // Check if chrome.runtime is a mock (real Chrome has specific properties)
        const runtimeKeys = Object.keys(window.chrome.runtime);
        if (runtimeKeys.length < 3) {
          autoScore += 20;  // Suspiciously minimal runtime object
        }
      }
      
      // Check for overridden properties (stealth patches leave traces)
      const navProto = Navigator.prototype;
      const webdriverDesc = Object.getOwnPropertyDescriptor(navProto, 'webdriver');
      if (webdriverDesc && webdriverDesc.get) {
        // If webdriver is overridden via prototype, it's likely stealth
        const getterStr = webdriverDesc.get.toString();
        if (getterStr.includes('false') && getterStr.length < 50) {
          autoScore += 15;
        }
      }
      
      // Permission API checks - headless often returns 'prompt' for everything
      if (navigator.permissions) {
        // We already query permissions above, but check consistency
        const permKeys = Object.keys(permissions);
        const allPrompt = permKeys.every(k => permissions[k] === 'prompt');
        if (allPrompt && permKeys.length >= 3) {
          autoScore += 10;  // Suspicious: all permissions in 'prompt' state
        }
      }
      
      // Check for known automation globals
      const automationGlobals = [
        "__webdriver_script_fn", "__selenium_evaluate", "__selenium_unwrapped",
        "__fxdriver_evaluate", "_phantom", "callPhantom", "_selenium",
        "callSelenium", "domAutomation", "cdc_adoQpoasnfa76pfcZLmcfl_",
        "__nightmare", "__phantomas__", "callPhantom",
      ];
      for (const g of automationGlobals) {
        if (g in window) {
          autoScore += 20;
          report.js_globals.push(g);
        }
      }
      
      // Check for Playwright-specific markers
      if (window.navigator.userAgent.includes('Chrome') && !window.chrome?.app) {
        // Chrome UA but no chrome.app could indicate Playwright
        autoScore += 10;
      }
      
      report.automation_score = autoScore;
    } catch (_) {}
    
    // Container/Cloud environment detection
    try {
      const indicators = [];
      
      // Check for common container/cloud user agents or properties
      const ua = navigator.userAgent.toLowerCase();
      if (ua.includes("headless")) indicators.push("headless_ua");
      if (ua.includes("crawl")) indicators.push("crawl_in_ua");
      
      // Missing properties often indicate containers
      if (!navigator.permissions) indicators.push("no_permissions_api");
      if (!navigator.clipboard) indicators.push("no_clipboard_api");
      
      // Cloud-specific timing signatures (very consistent performance)
      const perfEntries = performance.getEntriesByType("navigation");
      if (perfEntries.length > 0) {
        const nav = perfEntries[0];
        // If DNS/TCP times are 0 or extremely consistent, likely cloud proxy
        if (nav.domainLookupEnd - nav.domainLookupStart === 0) indicators.push("zero_dns_time");
      }
      
      report.container_indicators = indicators;
    } catch (_) {}
    
    // === FIRECRAWL / STEALTH PLAYWRIGHT DETECTION ===
    // These checks target stealth plugins that hide CDP traces
    try {
      // 1. Firecrawl often runs in Docker/cloud with specific memory patterns
      const memory = performance.memory;
      if (memory) {
        // Cloud containers often have round memory numbers (2GB, 4GB, 8GB exactly)
        const heapMB = Math.round(memory.jsHeapSizeLimit / 1048576);
        if ([2048, 4096, 8192, 16384].includes(heapMB)) {
          report.container_indicators.push("suspicious_memory_size:" + heapMB);
        }
      }
      
      // 2. Check for Playwright/Firecrawl specific globals
      const pwGlobals = ["__playwright", "__pw_manual", "__PW_EVALUATE"];
      for (const g of pwGlobals) {
        if (g in window) {
          report.js_globals.push(g);
          report.automation_score = (report.automation_score || 0) + 30;
        }
      }
      
      // 3. Runtime behavior analysis - Firecrawl has consistent execution timing
      const start = performance.now();
      // Microtask timing can reveal automation
      await new Promise(r => setTimeout(r, 0));
      const microtaskTime = performance.now() - start;
      // Automated browsers often have more consistent timing
      if (microtaskTime < 0.5) {  // Suspiciously fast
        report.container_indicators.push("suspicious_timing_consistency");
      }
      
      // 4. Check for iframe creation blocking (common in scraping environments)
      try {
        const testFrame = document.createElement("iframe");
        testFrame.style.display = "none";
        document.body.appendChild(testFrame);
        // Firecrawl sometimes blocks certain iframe APIs
        const frameWindow = testFrame.contentWindow;
        if (!frameWindow || !frameWindow.document) {
          report.container_indicators.push("iframe_sandbox_detected");
        }
        testFrame.remove();
      } catch (e) {
        report.container_indicators.push("iframe_creation_blocked");
      }
      
    } catch (_) {}
    
    // CDP (Chrome DevTools Protocol) detection - used by Firecrawl, Puppeteer, Playwright
    try {
      // CDP leaves traces in the Chrome object
      if (window.chrome && window.chrome.runtime && window.chrome.runtime.OnInstalledReason === undefined) {
        // This is a sign of mocked chrome object
        report.cdp_detected = true;
      }
      
      // Check for DevTools-only properties
      const devtoolsProps = ["__REACT_DEVTOOLS_GLOBAL_HOOK__", "__VUE_DEVTOOLS_GLOBAL_HOOK__"];
      for (const p of devtoolsProps) {
        if (p in window) {
          report.cdp_detected = true;
          break;
        }
      }
      
      // NEW: Check for CDP command line switches (stealth can't fully hide these)
      if (navigator.plugins && navigator.plugins.length === 0 && navigator.mimeTypes.length === 0) {
        // No plugins + no mime types is a strong automation signal
        report.automation_score = (report.automation_score || 0) + 25;
      }
    } catch (_) {}
    
    // Permission API check
    try {
      if (navigator.permissions) {
        // Query common permissions - headless/cloud often have specific patterns
        const permissionNames = ["midi", "notifications", "clipboard-read", "clipboard-write"];
        for (const name of permissionNames) {
          try {
            const status = await navigator.permissions.query({ name });
            report.permissions[name] = status.state;
          } catch (_) {
            report.permissions[name] = "unsupported";
          }
        }
      }
    } catch (_) {}

    try {
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (gl) {
        report.renderer = gl.getParameter(gl.RENDERER) || "unknown";
      }
    } catch (_) {}

    return report;
  }

  setStep("step-env", "active");
  setStatus("Collecting browser environment signals...");
  setProgress(6);
  const env = await collectEnv();

  setStep("step-env", "done");
  setStep("step-pow", "active");
  setStatus("Computing proof-of-work in your browser...");
  setProgress(12);

  let powResult;
  try {
    powResult = await solvePowWithWorker(CHALLENGE, DIFFICULTY);
  } catch (err) {
    showError((err && err.message) || "Verification hash failed. Please retry.");
    return;
  }

  setStep("step-pow", "done");
  setStep("step-verify", "active");
  setStatus("Binding solved proof to this request...");
  setProgress(95);

  const payload = {
    schema_version: "1.0",
    session_id: SESSION_ID,
    challenge_token: CHALLENGE_TOKEN,
    challenge: CHALLENGE,
    nonce: powResult.nonce,
    hash: powResult.hash,
    solve_ms: powResult.solveMs,
    return_to: RETURN_TO,
    env: env,
  };
  // Record solve time for analysis
  env.solve_time_ms = powResult.solveMs;

  let resp;
  try {
    resp = await fetch("/bw/gate/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      credentials: "same-origin",
    });
  } catch (_) {
    showError("Network error while verifying. Please retry.");
    return;
  }

  if (!resp.ok) {
    const contentType = (resp.headers.get("content-type") || "").toLowerCase();
    if (contentType.includes("text/html")) {
      const html = await resp.text().catch(() => "");
      if (html) {
        document.open();
        document.write(html);
        document.close();
        return;
      }
    }

    if (resp.status === 429) {
      showError("Too many attempts. Wait a moment and retry.");
      return;
    }

    const detail = await resp.text().catch(() => "");
    showError(detail || "Verification failed. Please retry.");
    return;
  }

  const result = await resp.json();
  setStep("step-verify", "done");
  setProgress(100);
  setStatus("Browser verified. Redirecting...", "ok");
  await new Promise((resolve) => setTimeout(resolve, 280));
  location.replace(result.next_path || RETURN_TO);
})();
</script>
</body>
</html>"""
    return (
        template
        .replace("__SID_JS__", json.dumps(session_id))
        .replace("__TOKEN_JS__", json.dumps(challenge_token))
        .replace("__CHALLENGE_JS__", json.dumps(challenge))
        .replace("__DIFFICULTY_JS__", json.dumps(difficulty))
        .replace("__RETURN_TO_JS__", json.dumps(return_to))
    )


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
        const match = document.cookie.match(/(?:^|;\\s*)bw_theme=([^;]+)/);
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


def render_bot_caught_page(*, session_id: str, user_agent: str = "", reasons: list[str] | None = None) -> str:
    """Render the 'YOU LOWDE BOT' page for detected scrapers/crawlers with absolute clarity."""
    reasons_html = ""
    if reasons:
        items = "".join(f"<li><code>{html.escape(r)}</code></li>" for r in reasons[-8:])
        reasons_html = f"<ul class='reasons'>{items}</ul>"
    
    # Categorize detection reasons for clarity
    detection_type = "GENERIC BOT"
    for r in reasons or []:
        r_lower = r.lower()
        if "firecrawl" in r_lower:
            detection_type = "🔥 FIRECRAWL DETECTED"
            break
        elif "scraper" in r_lower or "crawl" in r_lower:
            detection_type = "WEB SCRAPER"
            break
        elif "automation" in r_lower or "cdp" in r_lower:
            detection_type = "AUTOMATION FRAMEWORK"
            break
    
    ua_display = html.escape(user_agent[:200]) if user_agent else "Unknown"
    
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>YOU LOWDE BOT - SinkHole</title>
  <style>
    :root {{ --bg: #0a0a0a; --surface: #111; --border: #333; --text: #e0e0e0; --accent: #ff4444; --muted: #666; --fire: #ff6600; }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100dvh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: var(--bg);
      background-image: 
        radial-gradient(circle at 20% 50%, rgba(255, 68, 68, 0.15) 0%, transparent 50%),
        radial-gradient(circle at 80% 80%, rgba(255, 102, 0, 0.1) 0%, transparent 40%);
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, monospace;
      padding: 2rem;
    }}
    .container {{
      text-align: center;
      max-width: 800px;
      border: 2px solid var(--accent);
      border-radius: 16px;
      padding: 3rem;
      background: linear-gradient(180deg, var(--surface) 0%, #0a0a0a 100%);
      box-shadow: 0 0 60px rgba(255, 68, 68, 0.3), inset 0 1px 0 rgba(255,255,255,0.05);
    }}
    .detection-badge {{
      display: inline-block;
      padding: 0.5rem 1rem;
      background: rgba(255, 68, 68, 0.2);
      border: 1px solid var(--accent);
      border-radius: 999px;
      color: var(--accent);
      font-size: 0.8rem;
      font-weight: 700;
      letter-spacing: 0.1em;
      margin-bottom: 1.5rem;
    }}
    h1 {{
      font-size: 5rem;
      margin: 0 0 1rem;
      color: var(--accent);
      text-shadow: 0 0 30px rgba(255,68,68,0.6);
      letter-spacing: -0.02em;
      animation: pulse 2s ease-in-out infinite;
    }}
    @keyframes pulse {{
      0%, 100% {{ opacity: 1; transform: scale(1); }}
      50% {{ opacity: 0.85; transform: scale(0.98); }}
    }}
    .subtitle {{
      font-size: 1.3rem;
      color: var(--muted);
      margin-bottom: 2rem;
      line-height: 1.5;
    }}
    .trap-message {{
      background: rgba(255, 68, 68, 0.1);
      border-left: 4px solid var(--accent);
      padding: 1rem 1.5rem;
      margin: 2rem 0;
      text-align: left;
      border-radius: 0 8px 8px 0;
    }}
    .trap-message h3 {{
      margin: 0 0 0.5rem;
      color: var(--accent);
      font-size: 1rem;
    }}
    .trap-message p {{
      margin: 0;
      color: var(--muted);
      font-size: 0.9rem;
    }}
    .ua-box {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      margin: 1.5rem 0;
      font-size: 0.8rem;
      color: #888;
      word-break: break-all;
      text-align: left;
    }}
    .ua-box strong {{ color: var(--accent); }}
    .reasons {{
      list-style: none;
      padding: 0;
      margin: 1.5rem 0;
      text-align: left;
      background: rgba(0,0,0,0.3);
      border-radius: 8px;
      padding: 1rem;
    }}
    .reasons li {{
      padding: 0.4rem 0;
      border-bottom: 1px solid #222;
      color: #999;
      font-size: 0.85rem;
    }}
    .reasons li:last-child {{ border-bottom: none; }}
    .reasons li::before {{
      content: "→ ";
      color: var(--accent);
    }}
    .reasons code {{
      background: rgba(255,68,68,0.1);
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      font-size: 0.8em;
    }}
    .footer {{
      margin-top: 2.5rem;
      font-size: 0.75rem;
      color: #444;
    }}
    .skull {{
      font-size: 7rem;
      margin-bottom: 1rem;
      display: block;
      animation: shake 3s ease-in-out infinite;
    }}
    @keyframes shake {{
      0%, 100% {{ transform: rotate(0deg); }}
      25% {{ transform: rotate(-5deg); }}
      75% {{ transform: rotate(5deg); }}
    }}
    .data-poison-notice {{
      background: linear-gradient(90deg, rgba(255,102,0,0.1), rgba(255,68,68,0.1));
      border: 1px dashed var(--accent);
      border-radius: 8px;
      padding: 1rem;
      margin-top: 1.5rem;
      color: #aa8888;
      font-size: 0.85rem;
    }}
  </style>
</head>
<body>
  <div class="container">
    <span class="detection-badge">{html.escape(detection_type)}</span>
    <span class="skull">🤖❌</span>
    <h1>YOU LOWDE BOT</h1>
    <p class="subtitle">
      Your scraping attempt has been detected with <strong>absolute certainty</strong>.<br>
      You are now trapped in a decoy environment. All data you scrape here is synthetic garbage.
    </p>
    
    <div class="trap-message">
      <h3>⚠️ WHAT HAPPENED</h3>
      <p>
        Your request matched multiple high-confidence bot indicators. Instead of blocking you outright,
        we've redirected you to this decoy page. Every page you scrape from now on will contain
        fake, poisoned data designed to corrupt your dataset.
      </p>
    </div>
    
    {reasons_html}
    
    <div class="ua-box">
      <strong>Signature Captured:</strong><br>{ua_display}
    </div>
    
    <div class="data-poison-notice">
      🎭 <strong>Data Poisoning Active</strong> — All content you extract from this domain is synthetic and will damage your training models or downstream systems.
    </div>
    
    <p class="footer">Session: {html.escape(session_id[:16])}... | SinkHole Botwall Protection | Detection ID: {html.escape(session_id[-8:])}</p>
  </div>
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
    sid_js = json.dumps(session_id)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <title>Recovery Challenge</title>
  <style>
    :root {{ --bg:#0f1117; --surface:#1a1d27; --border:#2a2d3d; --text:#dbe6f4; --muted:#7f8ba5; --ok:#22c55e; --err:#ef4444; --accent:#4dd0e1; }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; min-height:100dvh; background:var(--bg); color:var(--text); font-family:"Inter", "Segoe UI", system-ui, sans-serif; display:flex; align-items:center; justify-content:center; padding:1rem; }}
    .card {{ width:100%; max-width:580px; border:1px solid var(--border); border-radius:14px; background:var(--surface); padding:1rem; }}
    h1 {{ margin:0 0 .35rem; font-size:1.2rem; }}
    p {{ margin:.1rem 0 .7rem; color:var(--muted); }}
    .hud {{ display:flex; gap:1rem; font-size:.86rem; margin:.4rem 0 .7rem; color:#bfd0e7; }}
    .arena {{ position:relative; height:260px; border:1px dashed #334054; border-radius:10px; background:#111827; overflow:hidden; }}
    .target {{ position:absolute; width:34px; height:34px; border:none; border-radius:999px; background:linear-gradient(135deg,#6ee7f9,#22c55e); cursor:pointer; box-shadow:0 0 0 2px rgba(255,255,255,.1); }}
    .status {{ min-height:1.1rem; margin-top:.7rem; font-size:.88rem; }}
    .status.ok {{ color:var(--ok); }}
    .status.err {{ color:var(--err); }}
    .retry {{ margin-top:.6rem; padding:.55rem .8rem; border:0; border-radius:8px; background:var(--accent); color:#04202a; font-weight:600; cursor:pointer; display:none; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Human Recovery Mini-Game</h1>
    <p>Hit moving targets for 10 seconds. This replaces manual acknowledgement.</p>
    <div class="hud">
      <span>Time: <strong id="time">10.0</strong>s</span>
      <span>Hits: <strong id="hits">0</strong></span>
      <span>Misses: <strong id="misses">0</strong></span>
      <span>Score: <strong id="score">0</strong></span>
    </div>
    <div class="arena" id="arena"></div>
    <div class="status" id="status" aria-live="polite">Starting challenge...</div>
    <button id="retry" class="retry" type="button">Retry game</button>
  </div>

  <script>
  const SESSION_ID = {sid_js};
  const arena = document.getElementById("arena");
  const statusEl = document.getElementById("status");
  const retryBtn = document.getElementById("retry");
  const hitsEl = document.getElementById("hits");
  const missesEl = document.getElementById("misses");
  const scoreEl = document.getElementById("score");
  const timeEl = document.getElementById("time");

  let token = "";
  let hits = 0;
  let misses = 0;
  let score = 0;
  let running = false;
  let startedAt = 0;
  let activeTarget = null;
  let moveTimer = null;
  let countdownTimer = null;

  function resetGame() {{
    hits = 0; misses = 0; score = 0;
    hitsEl.textContent = "0";
    missesEl.textContent = "0";
    scoreEl.textContent = "0";
    timeEl.textContent = "10.0";
    if (activeTarget) {{ activeTarget.remove(); activeTarget = null; }}
  }}

  function placeTarget() {{
    if (!running) return;
    if (activeTarget) activeTarget.remove();
    const t = document.createElement("button");
    t.className = "target";
    const maxX = Math.max(6, arena.clientWidth - 40);
    const maxY = Math.max(6, arena.clientHeight - 40);
    t.style.left = Math.floor(Math.random() * maxX) + "px";
    t.style.top = Math.floor(Math.random() * maxY) + "px";
    t.addEventListener("click", (e) => {{
      e.stopPropagation();
      hits += 1;
      score += 5;
      hitsEl.textContent = String(hits);
      scoreEl.textContent = String(score);
      placeTarget();
    }});
    arena.appendChild(t);
    activeTarget = t;
  }}

  async function submitRecovery(durationMs) {{
    const payload = {{
      schema_version: "1.0",
      session_id: SESSION_ID,
      recovery_token: token,
      game_score: score,
      hits,
      misses,
      duration_ms: durationMs,
    }};
    const res = await fetch("/bw/recovery/complete", {{
      method: "POST",
      headers: {{ "content-type": "application/json" }},
      body: JSON.stringify(payload),
      credentials: "same-origin",
    }});
    if (!res.ok) {{
      const txt = await res.text().catch(() => "");
      throw new Error(txt || "Recovery validation failed");
    }}
    return res.json();
  }}

  async function startRecoverySession() {{
    const r = await fetch("/bw/recovery/start", {{
      method: "POST",
      headers: {{ "content-type": "application/json" }},
      body: JSON.stringify({{ schema_version: "1.0", session_id: SESSION_ID, reason: "false_positive" }}),
      credentials: "same-origin",
    }});
    if (!r.ok) throw new Error("Unable to initialize recovery token");
    const j = await r.json();
    token = j.recovery_token;
  }}

  async function runGame() {{
    retryBtn.style.display = "none";
    statusEl.className = "status";
    statusEl.textContent = "Initializing recovery challenge...";
    resetGame();
    await startRecoverySession();

    running = true;
    startedAt = Date.now();
    statusEl.textContent = "Hit as many targets as you can";
    placeTarget();

    arena.onclick = () => {{
      if (!running) return;
      misses += 1;
      missesEl.textContent = String(misses);
    }};

    moveTimer = setInterval(() => {{
      if (running) placeTarget();
    }}, 650);

    countdownTimer = setInterval(async () => {{
      const elapsed = Date.now() - startedAt;
      const remain = Math.max(0, 10000 - elapsed);
      timeEl.textContent = (remain / 1000).toFixed(1);
      if (remain > 0) return;

      running = false;
      clearInterval(moveTimer);
      clearInterval(countdownTimer);
      if (activeTarget) {{ activeTarget.remove(); activeTarget = null; }}

      try {{
        statusEl.textContent = "Submitting recovery proof...";
        await submitRecovery(elapsed);
        statusEl.className = "status ok";
        statusEl.textContent = "Recovery accepted. Redirecting...";
        setTimeout(() => location.assign("/"), 350);
      }} catch (err) {{
        statusEl.className = "status err";
        statusEl.textContent = "Recovery failed. Try again.";
        retryBtn.style.display = "inline-block";
      }}
    }}, 100);
  }}

  retryBtn.addEventListener("click", () => {{ void runGame(); }});
  void runGame();
  </script>
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


def render_test_suite_page(
    session_id: str,
    website: dict[str, Any] | None,
    scenarios: list[Any],
) -> str:
    """Render the test suite dashboard page."""
    website_info = ""
    if website:
        config = website.get("config", {})
        pages = config.get("pages", 0)
        forms = "Yes" if config.get("has_forms") else "No"
        honeypots = "Yes" if config.get("include_honeypots") else "No"
        website_info = f"""
        <div class="website-info">
            <h3>Active Test Website: {html.escape(config.get('name', 'Unknown'))}</h3>
            <div class="stats-grid">
                <div class="stat"><span class="stat-value">{pages}</span><span class="stat-label">Pages</span></div>
                <div class="stat"><span class="stat-value">{forms}</span><span class="stat-label">Forms</span></div>
                <div class="stat"><span class="stat-value">{honeypots}</span><span class="stat-label">Honeypots</span></div>
                <div class="stat"><span class="stat-value">{html.escape(config.get('protection_level', 'standard'))}</span><span class="stat-label">Protection</span></div>
            </div>
        </div>
        """

    scenario_cards = []
    for i, s in enumerate(scenarios):
        scenario_cards.append(f"""
        <div class="scenario-card" data-behavior="{html.escape(s.behavior_type)}">
            <div class="scenario-header">
                <h4>{html.escape(s.name)}</h4>
                <span class="badge {s.behavior_type}">{html.escape(s.behavior_type)}</span>
            </div>
            <p class="scenario-desc">Expected: <strong>{html.escape(s.expected_outcome)}</strong></p>
            <button class="btn-run" onclick="runSimulation({i}, '{html.escape(s.behavior_type)}')">Run Simulation</button>
        </div>
        """)

    scenarios_html = "".join(scenario_cards)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Botwall Test Suite</title>
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
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      margin: 0;
      font-family: "Inter", "Segoe UI", system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100dvh;
      padding: 1.5rem;
    }}
    .wrap {{ max-width: 1200px; margin: 0 auto; }}
    h1 {{ margin: 0 0 0.5rem; font-size: 1.8rem; }}
    h2 {{ margin: 1.5rem 0 0.75rem; font-size: 1.3rem; }}
    h3 {{ margin: 1rem 0 0.5rem; font-size: 1.1rem; color: var(--accent); }}
    .sub {{ margin: 0 0 1.5rem; color: var(--muted); }}
    .website-info {{
      background: linear-gradient(180deg, var(--surface), var(--surface-2));
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.25rem;
      margin-bottom: 1.5rem;
    }}
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 1rem;
      margin-top: 1rem;
    }}
    .stat {{
      text-align: center;
      padding: 0.75rem;
      background: var(--surface-2);
      border-radius: 8px;
    }}
    .stat-value {{
      display: block;
      font-size: 1.5rem;
      font-weight: 700;
      color: var(--accent);
    }}
    .stat-label {{
      font-size: 0.75rem;
      color: var(--muted);
      text-transform: uppercase;
    }}
    .scenarios-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 1rem;
    }}
    .scenario-card {{
      background: linear-gradient(180deg, var(--surface), var(--surface-2));
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.25rem;
      transition: transform 0.2s, border-color 0.2s;
    }}
    .scenario-card:hover {{
      border-color: var(--accent);
      transform: translateY(-2px);
    }}
    .scenario-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.75rem;
    }}
    .scenario-header h4 {{ margin: 0; font-size: 1rem; }}
    .badge {{
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
    }}
    .badge.human {{ background: rgba(34, 197, 94, 0.2); color: var(--ok); }}
    .badge.bot_basic, .badge.bot_advanced {{
      background: rgba(239, 68, 68, 0.2); color: var(--risk);
    }}
    .scenario-desc {{
      color: var(--muted);
      font-size: 0.9rem;
      margin-bottom: 1rem;
    }}
    .btn-run {{
      width: 100%;
      padding: 0.6rem;
      border: none;
      border-radius: 8px;
      background: var(--accent);
      color: #04202a;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.2s;
    }}
    .btn-run:hover {{ opacity: 0.9; }}
    .btn-run:disabled {{ opacity: 0.5; cursor: not-allowed; }}
    .result-panel {{
      margin-top: 1.5rem;
      padding: 1rem;
      background: var(--surface-2);
      border-radius: 8px;
      border-left: 3px solid var(--accent);
      display: none;
    }}
    .result-panel.visible {{ display: block; }}
    .api-section {{
      margin-top: 2rem;
      padding: 1.25rem;
      background: var(--surface);
      border-radius: 12px;
      border: 1px solid var(--border);
    }}
    .api-section h3 {{ margin-top: 0; }}
    .api-list {{
      list-style: none;
      margin-top: 0.75rem;
    }}
    .api-list li {{
      padding: 0.5rem 0;
      border-bottom: 1px solid var(--border);
      font-family: ui-monospace, monospace;
      font-size: 0.85rem;
    }}
    .api-list li:last-child {{ border-bottom: none; }}
    .method {{
      display: inline-block;
      padding: 0.15rem 0.4rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      margin-right: 0.5rem;
    }}
    .method.get {{ background: rgba(77, 208, 225, 0.2); color: var(--accent); }}
    .method.post {{ background: rgba(34, 197, 94, 0.2); color: var(--ok); }}
    code {{
      background: rgba(0,0,0,0.3);
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      font-size: 0.85em;
    }}
    pre {{
      background: rgba(0,0,0,0.3);
      padding: 1rem;
      border-radius: 8px;
      overflow-x: auto;
      font-size: 0.8rem;
      margin-top: 0.5rem;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Botwall Test Suite</h1>
    <p class="sub">Stage 2 Phase 2 Testing Environment — Simulate bot and human behaviors</p>

    {website_info}

    <h2>Test Scenarios</h2>
    <div class="scenarios-grid">
      {scenarios_html}
    </div>

    <div class="result-panel" id="resultPanel">
      <h4>Simulation Results</h4>
      <pre id="resultOutput">Click "Run Simulation" to see results...</pre>
    </div>

    <section class="api-section">
      <h3>Test Suite API Endpoints</h3>
      <ul class="api-list">
        <li><span class="method get">GET</span> <code>/bw/test-suite/config</code> — Get default configuration</li>
        <li><span class="method post">POST</span> <code>/bw/test-suite/build</code> — Build custom test website</li>
        <li><span class="method post">POST</span> <code>/bw/test-suite/simulate</code> — Run behavior simulation</li>
        <li><span class="method get">GET</span> <code>/bw/test-suite/behavior-types</code> — List behavior types</li>
      </ul>
    </section>
  </div>

  <script>
    const SESSION_ID = {json.dumps(session_id)};

    async function runSimulation(scenarioIdx, behaviorType) {{
      const panel = document.getElementById('resultPanel');
      const output = document.getElementById('resultOutput');
      panel.classList.add('visible');
      output.textContent = 'Running simulation...';

      try {{
        const res = await fetch('/bw/test-suite/simulate', {{
          method: 'POST',
          headers: {{ 'content-type': 'application/json' }},
          body: JSON.stringify({{ behavior_type: behaviorType }}),
        }});
        const data = await res.json();
        output.textContent = JSON.stringify(data, null, 2);
      }} catch (err) {{
        output.textContent = 'Error: ' + err.message;
      }}
    }}
  </script>
</body>
</html>"""


def render_enhanced_telemetry_page(data: dict[str, Any]) -> str:
    """Render the enhanced telemetry page with Phase 2 data."""
    metrics = data.get("metrics", {})
    sessions = data.get("sessions", [])
    telemetry = data.get("telemetry", [])
    phase2 = metrics.get("phase2", {})

    m_sessions = int(metrics.get("sessions_total", 0))
    m_gate = int(metrics.get("gate_passed", 0))
    m_proof = int(metrics.get("proof_sessions", 0))
    m_decoy = int(metrics.get("decoy_sessions", 0))
    m_allow = int(metrics.get("allow_sessions", 0))
    m_avg = float(metrics.get("avg_score", 0.0))

    # Phase 2 metrics
    p2_mouse_teleport = int(phase2.get("mouse_teleport_detected", 0))
    p2_instant_scroll = int(phase2.get("instant_scroll_detected", 0))
    p2_honeypot = int(phase2.get("honeypot_interactions", 0))
    p2_timing = int(phase2.get("timing_trap_triggers", 0))
    p2_robotic = int(phase2.get("robotic_typing", 0))
    p2_sessions = int(phase2.get("sessions_with_phase2_data", 0))

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
        cls = "ok" if latest == "allow" else "warn" if latest in {{"observe", "challenge"}} else "risk"

        # Check for Phase 2 risk flags
        risk_indicators = ""
        events = s.get("events", [])
        for e in events:
            p2 = e.get("phase2_data", {{}})
            if p2:
                flags = []
                if p2.get("mouse_teleport_count", 0) > 0:
                    flags.append("TP")
                if p2.get("instant_scroll_detected"):
                    flags.append("IS")
                if p2.get("honeypot_hits"):
                    flags.append("HP")
                if flags:
                    risk_indicators = "<span class='risk-badge'>" + ",".join(flags) + "</span>"
                    break

        session_rows.append(
            f"<tr>"
            f"<td>{sid}</td><td>{score:.1f}</td><td>{gate_diff}</td><td>{env_score}</td>"
            f"<td>{proof_valid}</td><td>{challenges}</td><td>{traversal_ok}/{traversal_bad}</td>"
            f"<td class='{{cls}}'>{html.escape(latest)}</td>"
            f"<td>{risk_indicators}</td></tr>"
        )
    session_rows_html = "".join(session_rows) or "<tr><td colspan='9'>No sessions yet</td></tr>"

    telemetry_rows = []
    for t in telemetry[-120:][::-1]:
        fp = html.escape(str(t.get("fingerprint", ""))[:20])
        susp = float(t.get("suspicion", 0.0))
        src = html.escape(str(t.get("source", "local")))
        obs = int(t.get("observed_at", 0) or 0)
        cls = "risk" if susp >= 20 else "warn" if susp >= 8 else "ok"
        telemetry_rows.append(f"<tr><td>{fp}</td><td class='{{cls}}'>{susp:.1f}</td><td>{src}</td><td>{obs}</td></tr>")
    telemetry_rows_html = "".join(telemetry_rows) or "<tr><td colspan='4'>No telemetry samples yet</td></tr>"

    raw_json = html.escape(json.dumps(data, indent=2, sort_keys=True))

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SinkHole Enhanced Telemetry — Stage 2 Phase 2</title>
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
      --phase2: #a78bfa;
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
    .wrap {{ max-width: 1400px; margin: 0 auto; }}
    h1 {{ margin: 0 0 0.35rem; font-size: 1.5rem; }}
    .sub {{ margin: 0 0 1rem; color: var(--muted); }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      background: var(--phase2);
      color: white;
      margin-left: 0.5rem;
    }}
    .kpis {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
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
    .kpi.phase2 {{ border-color: var(--phase2); }}
    .kpi.phase2 .v {{ color: var(--phase2); }}
    .phase2-section {{
      background: linear-gradient(180deg, rgba(167, 139, 250, 0.1), var(--surface));
      border: 1px solid var(--phase2);
      border-radius: 12px;
      padding: 1rem;
      margin-bottom: 1rem;
    }}
    .phase2-section h2 {{
      color: var(--phase2);
      margin: 0 0 0.75rem;
      font-size: 1.1rem;
    }}
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
    .risk-badge {{
      background: rgba(239, 68, 68, 0.2);
      color: var(--risk);
      padding: 0.15rem 0.3rem;
      border-radius: 3px;
      font-size: 0.7rem;
    }}
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
    .tabs {{
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }}
    .tab {{
      padding: 0.5rem 1rem;
      border: none;
      background: transparent;
      color: var(--muted);
      cursor: pointer;
      font-size: 0.9rem;
    }}
    .tab.active {{
      color: var(--accent);
      border-bottom: 2px solid var(--accent);
    }}
    @media (max-width: 980px) {{ .grid {{ grid-template-columns: 1fr; }} }}
    @keyframes rise {{ from {{ transform: translateY(4px); opacity: 0.6; }} to {{ transform: translateY(0); opacity: 1; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>SinkHole Enhanced Telemetry <span class="badge">STAGE 2 PHASE 2</span></h1>
    <p class="sub">Advanced behavioral detection with mouse patterns, keystroke dynamics, scroll analysis, and trap detection.</p>

    <section class="kpis">
      <div class="kpi"><div class="v">{m_sessions}</div><div class="l">Sessions</div></div>
      <div class="kpi"><div class="v">{m_gate}</div><div class="l">Gate Passed</div></div>
      <div class="kpi"><div class="v">{m_proof}</div><div class="l">Proof Valid</div></div>
      <div class="kpi"><div class="v">{m_allow}</div><div class="l">Allow Decisions</div></div>
      <div class="kpi"><div class="v">{m_decoy}</div><div class="l">Decoy Decisions</div></div>
      <div class="kpi"><div class="v">{m_avg:.1f}</div><div class="l">Avg Score</div></div>
    </section>

    <section class="phase2-section">
      <h2>Phase 2 Behavioral Detection Metrics</h2>
      <div class="kpis">
        <div class="kpi phase2"><div class="v">{p2_mouse_teleport}</div><div class="l">Mouse Teleports</div></div>
        <div class="kpi phase2"><div class="v">{p2_instant_scroll}</div><div class="l">Instant Scrolls</div></div>
        <div class="kpi phase2"><div class="v">{p2_honeypot}</div><div class="l">Honeypot Hits</div></div>
        <div class="kpi phase2"><div class="v">{p2_timing}</div><div class="l">Timing Traps</div></div>
        <div class="kpi phase2"><div class="v">{p2_robotic}</div><div class="l">Robotic Typing</div></div>
        <div class="kpi phase2"><div class="v">{p2_sessions}</div><div class="l">Sessions w/ P2 Data</div></div>
      </div>
    </section>

    <section class="grid">
      <article class="card">
        <h2>Session Timeline with Phase 2 Risk Flags</h2>
        <table>
          <thead>
            <tr>
              <th>Session</th><th>Score</th><th>Gate</th><th>Env</th>
              <th>Proof</th><th>Challenges</th><th>Traversal</th><th>Latest</th><th>P2 Flags</th>
            </tr>
          </thead>
          <tbody>{session_rows_html}</tbody>
        </table>
      </article>

      <article class="card">
        <h2>Telemetry Fingerprints</h2>
        <table>
          <thead><tr><th>Fingerprint</th><th>Suspicion</th><th>Source</th><th>Observed</th></tr></thead>
          <tbody>{telemetry_rows_html}</tbody>
        </table>
      </article>
    </section>

    <section class="card" style="margin-top:0.9rem;">
      <h2>API Endpoints</h2>
      <p style="color: var(--muted); font-size: 0.9rem; margin: 0.5rem 0 1rem;">
        <strong>GET</strong> <code>/bw/telemetry/v2</code> — Enhanced telemetry with Phase 2 data<br>
        <strong>GET</strong> <code>/bw/telemetry/sessions/&#123;id&#125;/behavioral</code> — Session behavioral analysis<br>
        <strong>GET</strong> <code>/bw/telemetry/attack-patterns</code> — Detected attack patterns summary
      </p>
    </section>

    <section class="card" style="margin-top:0.9rem;">
      <h2>Raw Snapshot</h2>
      <pre>{raw_json}</pre>
    </section>
  </div>
</body>
</html>"""
