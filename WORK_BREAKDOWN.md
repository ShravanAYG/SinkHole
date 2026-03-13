# SinkHole Team Work Breakdown & Project Structure Guide

This guide is designed to help you divide the work among your team effectively based on the `IMPLEMENTATION_DETAIL.md` specification. It splits the project into specialized domains so team members can work in parallel without blocking each other.

---

## Project Structure Overview

The project is structured into the following key directories, separating concerns between the core backend, protective services, client-side scripts, and deployment:

```text
sinkhole/
├── botwall/                     # Python Application Code (Backend & Engine)
│   ├── app.py                   # FastAPI routing, middleware, and request handling
│   ├── config.py                # Configuration and TOML loading
│   ├── crypto.py                # HMAC signing, hashing, cryptographic primitives
│   ├── decoy.py                 # Sinkhole/Hellhole Layer 2 content graph logic
│   ├── html.py                  # Client-side JavaScript SDK and HTML template generation
│   ├── models.py                # Pydantic models (data schemas for requests/beacons)
│   ├── proof.py                 # Proof-of-work gate tracking and validation
│   ├── scoring.py               # Complex behavioral scoring heuristics and sequence evaluation
│   ├── state.py                 # Redis and In-Memory state management (sessions)
│   ├── telemetry.py             # Cross-server intelligence mesh and behavioral fingerprints
│   └── traversal.py             # Traversal engine, token issuance for internal links
├── deploy/                      # Reverse Proxy Integration & Configurations
│   ├── apache-botwall.lua       # Apache lua auth templates
│   ├── apache.conf              # Apache proxy config
│   ├── Caddyfile                # Caddy forward_auth template
│   ├── nginx.conf               # Nginx auth_request template
│   └── rendered/                # Auto-rendered output files
├── scripts/                     # Automation & Generation Scripts
│   ├── render_deploy.py         # Config renderer script
│   └── playwright/              # Automated bot test scripts (Crawler, JS bypasses)
├── tests/                       # Test Suite (pytest)
│   ├── test_tokens.py           # Unit tests for crypto and tokens
│   ├── test_scoring.py          # Unit tests for heuristic formulas
│   ├── test_decoy.py            # Unit tests for decoy relational generation
│   └── test_api_integration.py  # Full flow integration tests
├── botwall.toml                 # Centralized Configuration
└── requirements.txt             # Python dependencies
```

---

## Suggested Team Roles & Division

To maximize velocity, divide the work into **3 main squads**:

### 1. Core Platform & State Team (Backend / Infra)

**Files**: `config.py`, `crypto.py`, `state.py`, `models.py`, `telemetry.py`

**Responsibilities**:
* Implement configurations and data schemas (`Pydantic`).
* Handle fast Session Storage using both local memory and Redis options (`state.py`).
* Establish HMAC signatures, Token verification mechanisms, and Token lifecycles (`crypto.py`).
* Build out `telemetry.py` to handle cross-server footprint export/imports.
* *Prerequisite focus: This team unlocks the other teams.*

### 2. Detection, Scoring & Threat Team (Security / Backend)

**Files**: `scoring.py`, `proof.py`, `traversal.py`, `decoy.py`

**Responsibilities**:
* Write the scoring formulas (`score_request`, `score_beacon`, `sequence_quality`).
* Implement the "Decision Engine Flowchart" mapping request headers and beacon signals to actions.
* Create the PoW validation logic (Stage 1 Entry Gate) in `proof.py`.
* Establish link-signing and URL trace validation in `traversal.py`.
* Build the advanced "Layer 2" Decoy content graph engine (`decoy.py`).

### 3. Front-End, SDK & APIs Team (Frontend / Fullstack)

**Files**: `html.py`, `app.py`, `tests/`, `scripts/playwright/`

**Responsibilities**:
* Write the client-side JavaScript SDK to collect behavioral metrics (mouse entropy, shadow DOM traps).
* Setup the `FastAPI` application shell (`app.py`), connect all routes, cookies (`bw_sid`, `bw_gate`), and endpoints.
* Build the interactive recovery widget UI layer and visual elements for blocks.
* Write Playwright scripts behaving as naive bots, advanced headless bots, and valid humans to stress-test the engine.

---

## Phased Implementation Plan

If the team is adopting Agile, group your sprints into these logical phases:

*   **Phase 1 (Foundation):** State store, Crypto primitives (Tokens), Config parser, Basic FastAPI skeleton.
*   **Phase 2 (The Gate):** Proof-of-Work challenge generator, Frontend Web Worker solving it, and basic API gating.
*   **Phase 3 (Active Detection):** JS SDK injection, Signal ingestion endpoints, HTTP Headers scoring, and initial point system tuning.
*   **Phase 4 (Punishment & Polish):** Decoy content generator, link-traversal token issuing, Telemetry mesh API, complete integration testing.

## Next Steps
Share this document to your team, assign the specific `.py` files to respective module owners, and ensure they read the overarching behavior rules in the `IMPLEMENTATION_DETAIL.md` file before writing code.