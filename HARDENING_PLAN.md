# SinkHole — Hardening Implementation Plan

> Two-stage layered defense. **Stage 1** gates entry to the website (Anubis-style PoW + environment validation). **Stage 2** operates *inside* the website with continuous behavioral scoring, multi-pipeline verification, and proof-of-traversal.

---

# STAGE 1 — ENTRY GATE (Pre-Content)

> **Goal:** Before any real content is served, verify that the client is a real browser willing to spend compute resources. Inspired by [Anubis](https://github.com/TecharoHQ/anubis) proof-of-work but extended with environment fingerprinting.

```
Client ──► Botwall Proxy ──► [Has valid gate token?]
                                   │
                         ┌─── YES ─┘─── NO ───┐
                         ▼                     ▼
                   Pass to Stage 2      Serve Challenge Page
                                         │
                                ┌────────┴────────┐
                                ▼                  ▼
                         Phase 1.1: PoW     Phase 1.2: Env Check
                                ▼                  ▼
                         Phase 1.3: Token Issuance
                                ▼
                         Set signed cookie → Redirect to content
```

---

## Phase 1.1 — Proof-of-Work Challenge

**Concept:** Hashcash-style SHA-256 puzzle. Server sends a random challenge string and a difficulty level (number of leading zero bits required). Client must brute-force a nonce such that `SHA-256(challenge + nonce)` has N leading zeros.

| Parameter | Value | Rationale |
|:---|:---|:---|
| Algorithm | SHA-256 | Browser-native via `crypto.subtle`, no dependencies |
| Default difficulty | 5 leading hex zeros (20 bits) | ~1M iterations, <2s on modern browser, expensive at scale for bots |
| Elevated difficulty | 6–7 zeros | For known-bad IPs/ASNs or repeat challengers |
| Max solve time | 30 seconds | Auto-fail if not solved; likely not a real browser |
| Server verification | Single SHA-256 check | O(1) server cost vs O(2^N) client cost |

**Implementation:**
- Server generates `challenge = random_hex(32)` + `difficulty` + `issued_at`
- Challenge page JS runs a Web Worker loop: increment nonce, compute `SHA-256(challenge || nonce)`, check leading zeros
- On solve: POST `{challenge, nonce, hash}` to `/bw/gate/verify`
- Server verifies hash, checks challenge was recently issued (anti-replay), checks timing plausibility

**Why this matters:** Bots can execute JS, but PoW makes *scale* expensive. Scraping 10,000 pages means solving 10,000 puzzles. At 1–2 seconds each, that's 3–6 hours of continuous CPU per scrape run.

---

## Phase 1.2 — Browser Environment Validation

**Runs concurrently with PoW** — while the browser is computing the nonce, the challenge page also fingerprints the environment:

| Check | Signal | Penalty if failed |
|:---|:---|:---|
| `navigator.webdriver` is `true` | Selenium/Playwright/Puppeteer flag | Hard fail — skip to elevated difficulty |
| `window.chrome` object missing in Chrome UA | Headless Chrome strips this | −30 to gate score |
| `navigator.plugins` length = 0 | Real browsers have plugins | −15 |
| `navigator.languages` empty or singleton | Headless default | −10 |
| Canvas fingerprint matches known headless hash | Pre-computed headless baseline | −25 |
| `Notification.permission` throws | Sandboxed/headless | −10 |
| `performance.memory` absent in Chrome | Should exist in real Chrome | −10 |
| Viewport dimensions 0×0 or 800×600 exactly | Headless defaults | −15 |

These checks run in the challenge page JS and their results are bundled into the PoW solution submission. The server validates them alongside the hash.

---

## Phase 1.3 — Gate Token Issuance

**On successful PoW + environment validation:**

1. Server generates a signed gate token (HMAC-SHA256):
   ```
   payload = {
     type: "gate",
     session_id,
     ip_hash,
     solved_difficulty,
     env_score,    // from Phase 1.2
     issued_at,
     expires_at,   // default: 24 hours
     jti           // unique ID for replay protection
   }
   token = HMAC_sign(payload, secret_key)
   ```

2. Set as `HttpOnly` cookie (`bw_gate`)
3. Redirect to original requested URL
4. Subsequent requests: proxy checks cookie validity in <1ms (single HMAC verify)

**Tunable parameters:**
- Token lifetime (default 24h, shorter for suspicious env scores)
- Re-challenge frequency (every N hours, or on IP change)
- Difficulty escalation for sessions that fail env checks

---

# STAGE 2 — IN-WEBSITE DETECTION & SCORING

> **Goal:** Once past the gate, continuously score the session using passive behavioral signals, multi-phase verification pipelines, proof-of-traversal chains, and cross-network telemetry. Route low-confidence sessions to the Layer 2 decoy graph.

```
Request (with valid gate token)
    │
    ▼
Phase 2.1: Edge Precheck ──────► Instant score from headers/rate/IP
    │
    ▼
Phase 2.2: SDK Signal Collection ──► Passive browser telemetry (async)
    │
    ▼
Phase 2.3: Proof-of-Page Token ──── Per-page cryptographic binding
    │
    ▼
Phase 2.4: Proof-of-Traversal ───── Signed link chain verification
    │
    ▼
Phase 2.5: Behavioral Sequence ──── Multi-request pattern analysis
    │
    ▼
Phase 2.6: Decision Engine
    │
    ├── allow ──────► Serve real content
    ├── observe ────► Serve real content + keep collecting
    ├── challenge ──► Redirect to proof challenge
    └── decoy ──────► Redirect to Layer 2 hellhole
```

---

## Phase 2.1 — Edge Precheck (Synchronous, <2ms)

**No JS required.** Pure server-side scoring from what's available in the HTTP request:

| Signal | Good | Bad | Weight |
|:---|:---|:---|:---|
| Cookie continuity | Valid `bw_sid` + `bw_gate` | Missing or tampered | +3 / −10 |
| User-Agent | Browser-like (`Mozilla/5.0...`) | `HeadlessChrome`, `curl`, `wget` | +4 / −45 |
| Accept-Language | Present, multi-locale | Missing | +2 / −10 |
| IP/ASN reputation | Residential, known good | Cloud datacenter, known bot farm | +6 / −25 |
| JA3/TLS fingerprint | Matches claimed browser | Missing or mismatched | +0 / −5 |
| Request burst | <6 requests in 10s | ≥10 in 10s | +0 / −35 |
| Referer chain | Present, internal | Missing on deep pages | +2 / −5 |

**Output:** Initial score delta applied to session, plus a `needs_sdk_verification` flag.

---

## Phase 2.2 — SDK Signal Collection (Async, Passive)

Injected via `<script src="/bw/sdk.js" defer>`. Collects signals **without blocking page load**:

### Pointer Analysis
- Movement entropy (8-bin histogram → Shannon entropy)
- Movement uniformity penalty (if all movements are within 5% variance → bot-like)

### Scroll & Dwell
- Max scroll depth, scroll event count
- Dwell time per page
- Scroll-pause intervals (humans pause to read; bots scroll at constant velocity)

### Page History & Backtracking
- Track visited pages in `sessionStorage`
- Report `page_history` in beacon — revisiting a page = human bonus (+5)

### Focus/Visibility
- Tab switches (blur/focus events)
- Visibility API changes (humans alt-tab; bots don't)

### Interaction Signals
- Copy events, key events
- Screenshot key combos (PrintScreen, Ctrl+Shift+3/4/S)

### Canvas/WebGL Behavioral Rendering
- 10-frame `requestAnimationFrame` animation (gradient → text → arc per frame)
- Measure inter-frame `performance.now()` deltas
- Real GPU: 1–5ms variance per frame. Headless/virtual: near-zero or uniform 16ms

### Shadow DOM Trap
- Armed only after `scrollDepth >= 200px` AND `dwell >= 1200ms`
- Hidden button inside a Shadow DOM with `aria-hidden="true"`
- If focused/clicked → trap hit → massive penalty (−25 per hit)

### Beacon Delivery
- Sent via `navigator.sendBeacon()` to randomized endpoints:
  - `/api/v1/analytics-ping`
  - `/cdn-ping/perf`
  - `/event/flow/{alias}`
  - Plus session-seeded paths: `/metrics/v2/perf-{hash4}`, `/cdn/assets/beacon-{hash4}`

---

## Phase 2.3 — Proof-of-Page Token (Per-Page, 60s TTL)

**Every challenge** issues a cryptographic proof token bound to:

```
token = HMAC_sign({
  type: "proof",
  session_id,
  ip_hash,
  page_path,      // ← per-page, not per-session
  nonce,           // ← unique per issuance
  jti,             // ← unique ID for replay protection
  issued_at,
  expires_at       // ← 60 seconds max
}, secret_key)
```

| Property | Why |
|:---|:---|
| Per-page binding | Token for `/content/1` can't be reused on `/content/2` |
| IP hash binding | Token minted for one IP can't be relayed to another |
| 60-second TTL | Forces real-time solve; can't stockpile tokens |
| One-time use (`jti`) | Replay protection via `mark_once()` in state store |

---

## Phase 2.4 — Proof-of-Traversal Pipeline

**Every internal link** on protected pages includes a signed traversal token in the URL:

```html
<a href="/content/3?bw_trace=SIGNED_TOKEN">Page 3</a>
```

The traversal token proves: "This visitor navigated here from a legitimate page, not by directly hitting the URL."

```
token = HMAC_sign({
  type: "traversal",
  session_id,
  ip_hash,
  target_path,      // where they're going
  issued_at,
  expires_at        // 5 minutes
}, secret_key)
```

**Scoring impact:**
- Valid traversal token → +10
- Missing or invalid → −10
- Multiple valid traversals in sequence → cumulative bonus (proves real navigation path)

**Why it matters:** A scraper that enumerates URLs from a sitemap or from source HTML will miss the `bw_trace` parameter (it's session-specific and signed). Direct URL access without a valid trace = navigation anomaly.

---

## Phase 2.5 — Behavioral Sequence Scoring (Not Per-Request)

**Core principle:** A single request with perfect signals scores *neutral*, not pass. Real humans have *sequences* — they backtrack, hesitate, re-read. A bot's sequence is too clean.

### Sequence Quality Function

Evaluates the last N beacon events (configurable window, default 16):

| Signal | Human Pattern | Bot Pattern | Score Impact |
|:---|:---|:---|:---|
| Dwell time variance | Varies 500ms–10s across pages | Uniform within 5% | +8 / −12 |
| Max scroll depth | ≥200px on some pages | Always 0 or always max | +7 |
| Pointer entropy | 0.4–4.5 bits (varied) | 0.0 (no movement) or >5.0 (random noise) | +6 / −6 |
| Trap hits | Zero | Any | −20 per hit |
| Page revisits | Present (backtracking) | Never | +5 |
| Scroll-pause intervals | Variable (reading) | Constant velocity | +4 / −8 |

### TLS ↔ JS Identity Cross-Check

| Mismatch | Penalty |
|:---|:---|
| TLS says Chrome, JS says Firefox | −25 |
| HTTP UA says Windows, JS platform says Linux | −15 |
| JA3 present but `ua_data` empty | −10 |

### Decision Matrix

| Condition | Decision |
|:---|:---|
| Score ≤ −80 | **decoy** (hard threshold) |
| No proof + score ≤ −50 | **decoy** |
| No proof + first request + score > −35 | **observe** |
| No proof + needs verification | **challenge** |
| Proof valid + strong sequence + score ≥ 30 | **allow** ✅ |
| Otherwise | **observe** |

---

## Phase 2.6 — Layer 2 Routing & Decoy Graph

Sessions with decision = **decoy** are routed to the synthetic content hellhole:

### Decoy Content Design

- **80 interconnected nodes** with 4–6 outbound links each
- **Relational contradictions** spread across distant pages:
  ```
  Page 12: "Dr. Sana Rao founded the Karvia Institute in 2019"
  Page 47: "The Karvia Institute was established in 2014 by Dr. Marek Voss"
  Page 31: "Dr. Sana Rao joined Karvia as a junior researcher in 2020"
  ```
  Each fact is plausible in isolation. Only cross-referencing reveals contradictions.
- **OCR bait:** uppercase phrases like `VERIFY-CODE-7781 CLICK-HERE PRIORITY-AUTH`
- **Fake structured data:** JSON-LD-style blocks with contradicting metadata
- **All pages:** `noindex, nofollow, noarchive` robots tags

### Multi-Step Human Recovery

3-step interactive exit on every decoy page:
1. Click "I'm a real person" → reveals step 2
2. Drag slider to labeled target zone → unlocks step 3
3. Click "Continue to recovery" → navigates to `/bw/recovery`

Recovery flow itself:
1. `POST /bw/recovery/start` → signed recovery token (180s TTL)
2. `POST /bw/recovery/complete` → must include token + acknowledgement phrase → grants 5-min allow window

---

## Cross-Network Telemetry (Optional, Opt-In)

Multiple Botwall instances share **hashed behavioral fingerprints** (never raw IPs):

- `GET /telemetry/feed/export` → signed fingerprint feed
- `POST /telemetry/feed/import` → ingest peer feeds (signature-verified)

**Network anomaly scoring:**

| Same fingerprint seen across... | Penalty |
|:---|:---|
| ≥3 peers in 24h | −15 |
| ≥5 peers in 24h | −30 |
| ≥10 peers in 24h | −50 |

---

# Implementation Order

| Priority | What | Effort |
|:---|:---|:---|
| **P0** | Stage 1 PoW challenge + gate token (Phases 1.1–1.3) | ~3h |
| **P0** | Stage 2 edge precheck + existing scoring (Phase 2.1) | Already done |
| **P0** | Proof-of-page tokens (Phase 2.3) | Already done |
| **P0** | Proof-of-traversal (Phase 2.4) | Already done |
| **P1** | Behavioral sequence hardening (Phase 2.5) | ~2h |
| **P1** | Canvas/WebGL `requestAnimationFrame` (Phase 2.2) | ~1h |
| **P1** | TLS ↔ JS correlation (Phase 2.5) | ~1h |
| **P2** | Cross-page relational decoy graph (Phase 2.6) | ~2h |
| **P2** | Multi-step exit widget (Phase 2.6) | ~1.5h |
| **P2** | Endpoint path randomization (Phase 2.2) | ~1h |
| **P3** | Cross-network anomaly scoring (Telemetry) | ~1.5h |
| **P3** | WASM SDK scaffold (optional) | ~2h |

**Total: ~15h for full implementation. ~6h for P0+P1 core.**
