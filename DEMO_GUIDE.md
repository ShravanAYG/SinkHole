# Botwall / SinkHole Demo Guide

This document provides a comprehensive analysis of the SinkHole Botwall project and detailed steps to set up and run a live demo.

## Project Analysis

SinkHole is a multi-layered anti-scraping system designed to make automated data extraction economically unfeasible by increasing the computational and architectural cost for bots while remaining transparent to legitimate users.

### Core Defensive Layers

1.  **Stage 1: Entry Gate (Proof-of-Work)**
    - Forces clients to solve a CPU-intensive cryptographic puzzle.
    - Collects environment signals (WebDriver detection, canvas fingerprinting, WebGL renderer).
    - Prevents simple scrapers and headless browsers from even reaching the content.

2.  **Stage 2: Behavioral Scoring & Traversal Tokens**
    - Continuous monitoring of mouse movements, scroll depth, and dwell time.
    - Uses "Shadow DOM Traps" to catch bots using simple DOM selectors.
    - Links are signed with "Traversal Tokens" that are session- and path-bound, preventing simple URL enumeration.

3.  **Layer 2: Decoy Hellhole**
    - Suspicious sessions are routed to a synthetic content graph.
    - These pages contain plausible but relationally contradictory data to poison the bot's knowledge graph.
    - Includes OCR bait and SEO-negative signals (`noindex`).

4.  **Telemetry Mesh**
    - Shares behavioral fingerprints across different instances to catch distributed bot farms.

---

## Setup and Demo Instructions

### 1. Prerequisites
Ensure you have Python 3.10+ and a virtual environment tool installed.

```bash
# Clone the repository (if not already in it)
# git clone <repo_url> sinkhole
# cd sinkhole
```

### 2. Environment Setup
Create a virtual environment and install the package in development mode.

```bash
python3 -m venv .venv
.venv/bin/pip install -e .[dev]
```

### 3. Running the Demo Services
We will run two components:
- **Origin Site**: A template website representing the content you want to protect.
- **Botwall App**: The security gateway and scoring engine.

#### Start the Origin Site
```bash
ORIGIN_HOST=127.0.0.1 ORIGIN_PORT=9101 .venv/bin/python scripts/demo_origin_site.py
```

#### Start the Botwall App
```bash
BOTWALL_HOST=127.0.0.1 BOTWALL_PORT=4101 BOTWALL_POW_DIFFICULTY=2 .venv/bin/python -m botwall
```

### 4. Running a Simulated Attack (Scraper Test)
This script simulates different types of traffic (clean vs. aggressive) to demonstrate how the scoring engine reacts.

```bash
BW_BASE=http://127.0.0.1:4101 .venv/bin/python scripts/stage2_scraper_test.py
```

**Expected Results:**
- `aggressive-bot` should have 100% `decoy` decisions (302 redirects).
- `clean-browser` might get some `allow` but will eventually be flagged if it behaves too mechanically.
- You can check the **Telemetry Dashboard** at `http://127.0.0.1:4101/bw/telemetry`.

### 5. Interactive Demo (Human vs. Bot)
You can try to access the protected content manually or via curl.

**Simulate a Bot (curl):**
```bash
# Using a bot-like User-Agent
curl -i -H "User-Agent: HeadlessChrome" http://127.0.0.1:4101/
```
*Result: You should see a `302 Found` redirecting to `/bw/decoy/0` (the hellhole).*

**Simulate a Legitimate User (Browser):**
Open your browser and navigate to:
`http://127.0.0.1:4101/bw/gate/challenge?path=/`
*Wait for the Proof-of-Work to solve (a few seconds) and continue to the site.*

---

## Verification & Validation

To ensure the system is working as intended, you can run the logic check:

```bash
.venv/bin/python scripts/team2_logic_check.py
```

This script validates:
- Token signing and verification.
- Scoring formulas (request-level and beacon-level).
- Decoy graph determinism.

## Configuration Tuning
You can adjust the security strictness in `botwall.toml` or via environment variables:
- `BOTWALL_POW_DIFFICULTY`: Increase to make the entry gate more expensive.
- `BOTWALL_ALLOW_THRESHOLD`: Higher values require more "human" behavior to allow.
- `BOTWALL_DECOY_THRESHOLD`: Lower values make the decoy trigger faster.
