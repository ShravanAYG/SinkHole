# Hardening Recommendations — Implementation Plan

## Goal

Implement all 10 hardening recommendations against the current Botwall Python codebase in `/home/bb/sinkhole`. Each recommendation is assessed for its current state and the concrete changes needed.

---

## Gap Analysis: Current State vs Recommendations

| # | Recommendation | Status | Gap |
|---|:---|:---:|:---|
| 1 | Per-page proof TTL bound to URL+IP+timestamp, 60s max | ✅ Done | Already binds `session_id + path + ip_hash + nonce`, 60s TTL. Minor: add explicit timestamp in log/reason. |
| 2 | WASM-compiled obfuscated SDK | ❌ Missing | Currently plain JS. Add a WASM stub compilation pipeline. |
| 3 | Split signal collection across 3+ randomized endpoints | ✅ Done | 3 aliases exist. Minor: make endpoint path segments session-randomized. |
| 4 | Shadow DOM traps after 200px scroll + dwell-correlated timing | ✅ Done | Shadow trap arms after `scrollDepth >= 200` and `dwell >= 1200ms`. No changes needed. |
| 5 | Relational (not factual) misinformation across page graph | ⚠️ Partial | Basic relational inconsistency exists but only within single node. Need cross-node graph-level contradictions across 50+ pages. |
| 6 | Behavioral sequences, not per-request scores | ✅ Done | `sequence_quality()` + `decide()` require multi-request proof. Minor: add backtrack/hesitation detection. |
| 7 | TLS fingerprint ↔ JS browser signal correlation | ⚠️ Partial | JA3-missing-for-Chrome check exists. Need deeper cross-check: TLS-implied browser vs JS `navigator.userAgentData` platform/brands. |
| 8 | Canvas/WebGL behavioral render timing (not static hashes) | ⚠️ Partial | Frame-variance check exists. Need multi-frame animation sequence with `requestAnimationFrame` instead of synchronous loop. |
| 9 | Multi-step exit CTA (not just button click) | ⚠️ Partial | Recovery is 2-step API but the decoy page exit is a single link. Need 3+ sequential UI interactions. |
| 10 | Cross-server telemetry (behavioral fingerprints, not IPs) | ✅ Done | Hashed fingerprint import/export exists. Minor: add cross-network volume anomaly scoring. |

---

## Proposed Changes

### 1. Proof Token Binding — Tighten Logging

Already fully implemented. No code changes needed.

---

### 2. WASM SDK Stub

> [!IMPORTANT]
> Full WASM obfuscation is a post-hackathon item. For now, we add a Rust → WASM compilation scaffold and a loader that makes the SDK deliverable as WASM instead of plain JS. The core signal collection stays in a thin JS shim that calls into WASM for the proof computation and entropy calculation.

#### [NEW] [wasm_sdk/](file:///home/bb/sinkhole/wasm_sdk/)
- `Cargo.toml` — minimal Rust crate targeting `wasm32-unknown-unknown`
- `src/lib.rs` — exports `compute_proof_hash()` and `pointer_entropy()` via `wasm-bindgen`
- `build.sh` — builds with `wasm-pack` → outputs `pkg/` with `.wasm` + JS glue

#### [MODIFY] [html.py](file:///home/bb/sinkhole/botwall/html.py)
- Add a `sdk_script_wasm()` function that emits a loader script: loads the `.wasm` module, then delegates proof computation and entropy to WASM exports instead of inline JS.
- Update `sdk_script()` to detect WASM availability and fall back to plain JS.

#### [MODIFY] [app.py](file:///home/bb/sinkhole/botwall/app.py)
- Add route `GET /bw/sdk.wasm` to serve the compiled WASM binary.

---

### 3. Runtime Endpoint Path Randomization

#### [MODIFY] [html.py](file:///home/bb/sinkhole/botwall/html.py)
- Expand the aliases array with 6 more endpoint patterns, using session-seeded shuffling:
  - `/metrics/v2/perf-{hash4}`, `/telemetry/{hash4}/collect`, `/cdn/assets/beacon-{hash4}`
- The `{hash4}` is derived from session ID so the bot can't predict paths without knowing the session.

#### [MODIFY] [app.py](file:///home/bb/sinkhole/botwall/app.py)
- Add catch-all route patterns for the new randomized endpoint families that all funnel into `_ingest_beacon`.

---

### 4. Shadow DOM Traps — No Changes Required

Already arms Shadow DOM traps after `scrollDepth >= 200px` and `dwell >= 1200ms`. Working as designed.

---

### 5. Cross-Page Relational Inconsistency Graph

#### [MODIFY] [decoy.py](file:///home/bb/sinkhole/botwall/decoy.py)
- Expand `build_node()` max_nodes default from 60 → 80.
- Add a `build_relational_graph()` function that generates a full graph of 80 nodes where:
  - Person A's brother differs between page N and page M.
  - Dates contradict across nodes.
  - Organizations swap leadership across different page collections.
  - Each node references 4–6 other nodes (higher link density).
- Add structured data blocks (fake JSON-LD, fake schema.org markup) that look machine-parseable but contain cross-contradicting facts.

---

### 6. Behavioral Sequence Strengthening

#### [MODIFY] [scoring.py](file:///home/bb/sinkhole/botwall/scoring.py)
- Add `sequence_linearity_penalty()`: if all dwell times in the window are within 5% of each other (too uniform), penalize by −12. Real humans have variance.
- Add `backtrack_bonus()`: if the event sequence shows revisiting a previously-seen path, give +5.
- Integrate both into `sequence_quality()`.

#### [MODIFY] [models.py](file:///home/bb/sinkhole/botwall/models.py)
- Add `page_history: list[str]` field to `BeaconEvent` for tracking page-visit order.

#### [MODIFY] [html.py](file:///home/bb/sinkhole/botwall/html.py)  
- SDK: track `sessionStorage` page history and include in beacon payload.

---

### 7. TLS ↔ JS Identity Cross-Check

#### [MODIFY] [scoring.py](file:///home/bb/sinkhole/botwall/scoring.py)
- Add `score_tls_js_correlation()`:
  - Parse `ua_data.brands` from beacon for Chrome/Edge/Safari version.
  - Compare with `x-ja3`-implied browser identity (passed from reverse proxy).
  - If TLS says Chrome 120 on Windows but JS says Linux or Firefox → −25 penalty.
  - If `ua_data.platform` contradicts HTTP `User-Agent` OS → −15 penalty.

#### [MODIFY] [app.py](file:///home/bb/sinkhole/botwall/app.py)
- Pass `x-ja3` header value into `score_beacon()` for correlation.

---

### 8. Canvas/WebGL Animation Frame Sequence

#### [MODIFY] [html.py](file:///home/bb/sinkhole/botwall/html.py)
- Replace the synchronous canvas render loop with a `requestAnimationFrame`-based 10-frame animation:
  - Render different scenes per frame (gradient, text, circle).
  - Measure inter-frame timing via `performance.now()`.
  - Collect WebGL timing separately if `getContext("webgl")` is available.
- This produces real GPU-scheduled timing variance instead of CPU-loop artifacts.

---

### 9. Multi-Step Interactive Exit CTA

#### [MODIFY] [html.py](file:///home/bb/sinkhole/botwall/html.py)
- `render_decoy_page()`: replace the single "Request human recovery" link with a 3-step inline widget:
  1. Click "I'm a real person" button → reveals a hidden section.
  2. Drag a slider to a specific labeled position (e.g. "Move to the green zone") → unlocks step 3.
  3. Click "Continue to recovery" button → navigates to `/bw/recovery`.
- All 3 steps are achievable by a human in ~3 seconds but require sequential DOM interactions that a pure link-enumerating bot won't complete.

#### [MODIFY] [html.py](file:///home/bb/sinkhole/botwall/html.py)
- `render_recovery_page()`: expand from single form to:
  1. Read and acknowledge a brief statement (checkbox).
  2. Enter a displayed verification phrase (simple copy-type, not CAPTCHA).
  3. Submit → calls `/bw/recovery/start`.

---

### 10. Cross-Network Volume Anomaly Scoring

#### [MODIFY] [telemetry.py](file:///home/bb/sinkhole/botwall/telemetry.py)
- Add `score_network_anomaly()`: given a fingerprint that appears in N peer feeds within 24 hours, apply:
  - N >= 5 peers → −30 penalty (strong bot signal)
  - N >= 10 peers → −50 penalty
- This catches bots that look clean per-server but hit many servers in the mesh.

#### [MODIFY] [scoring.py](file:///home/bb/sinkhole/botwall/scoring.py)
- Call `score_network_anomaly()` from `score_telemetry_match()` when telemetry data is available.

#### [MODIFY] [state.py](file:///home/bb/sinkhole/botwall/state.py)
- Add `count_fingerprint_sources()` to count distinct `source` values for a given fingerprint across telemetry records.

---

## Verification Plan

### Automated Tests

All run via:
```bash
cd /home/bb/sinkhole && .venv/bin/pytest -v
```

**Existing tests** (11 passing):
- `tests/test_tokens.py` — proof and traversal token binding/expiry/tamper
- `tests/test_scoring.py` — request/beacon scoring, sequence-requires-proof-then-allow
- `tests/test_decoy.py` — determinism, relational inconsistency presence
- `tests/test_api_integration.py` — browser flow, headless decoy + recovery, invalid proof/telemetry rejection

**New tests to add:**

#### [NEW] `tests/test_sequence_hardening.py`
- Test `sequence_linearity_penalty()`: uniform dwell times get penalized; varied dwell times don't.
- Test `backtrack_bonus()`: revisiting a path gives bonus.

#### [NEW] `tests/test_tls_correlation.py`
- Test `score_tls_js_correlation()`: mismatched TLS/JS identity gets penalized; matching identity doesn't.

#### [NEW] `tests/test_decoy_graph.py`
- Test `build_relational_graph()`: verify cross-node contradictions exist (person A's brother differs between two nodes).
- Test link density >= 4 per node.

#### [NEW] `tests/test_network_anomaly.py`
- Test `score_network_anomaly()`: fingerprint in 5+ sources → penalty applied.
- Test fingerprint in 1 source → no penalty.

#### Extend `tests/test_api_integration.py`
- Test the randomized beacon endpoints respond correctly.
- Test WASM SDK route returns valid content-type.
- Test multi-step recovery requires all 3 steps.

### Manual Verification

Start the server and open browser:
```bash
cd /home/bb/sinkhole
.venv/bin/python -m botwall
# Open http://127.0.0.1:4000/
```

1. **Decoy page multi-step exit**: navigate to `/bw/decoy/0?sid=test` and verify the 3-step widget renders and all steps must be completed before recovery link works.
2. **Dashboard**: open `/bw/dashboard` and verify session/telemetry data displays.
3. **WASM route**: check `/bw/sdk.wasm` returns a valid `.wasm` binary (if wasm-pack is installed).
