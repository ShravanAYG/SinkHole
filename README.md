# Botwall v1 (Python)

Layered anti-scraping prototype with challenge-based proof, behavioral scoring, traversal tokens, decoy graph routing, and opt-in telemetry exchange.

## Stack

- FastAPI + Uvicorn
- Pydantic models for API contracts
- Redis-backed state with in-memory fallback
- Browser SDK served from `/bw/sdk.js`

## Features Implemented

- Layer 1 risk scoring from request + behavioral sequence signals.
- Short-TTL (60s) per-page proof token bound to session, path, and client IP hash.
- One-time proof token replay protection.
- Traversal token issuance/validation for protected internal links.
- 3 split telemetry ingestion endpoints:
  - `POST /api/v1/analytics-ping`
  - `POST /cdn-ping/perf`
  - `POST /event/flow/{alias}`
- Shadow DOM trap activation after scroll depth and dwell thresholds.
- Canvas/WebGL frame-variance heuristic.
- TLS/HTTP + JS UA mismatch scoring signal.
- Layer 2 deterministic decoy graph with relational inconsistency patterns.
- Two-step human recovery flow.
- Opt-in telemetry mesh feed import/export with signatures.
- Nginx/Caddy/Apache integration artifacts under `deploy/`.
- Team-2 implementation guide under `TEAM2_IMPLEMENTATION.md`.

## API Endpoints

- `GET /bw/gate/challenge`
- `POST /bw/gate/verify`
- `GET /bw/gate/check`
- `GET /bw/check`
- `GET /bw/challenge`
- `POST /bw/proof`
- `GET /bw/decoy/{node}`
- `GET /bw/recovery`
- `POST /bw/recovery/start`
- `POST /bw/recovery/complete`
- `GET /telemetry/feed/export`
- `POST /telemetry/feed/import`
- `GET /bw/dashboard`
- `GET /__dashboard`

## Run

```bash
cd /home/bb/sinkhole
python3 -m venv .venv
.venv/bin/pip install -e .[dev]
.venv/bin/python -m botwall
```

Server default: `http://127.0.0.1:4000`

## Real-Life Validation

```bash
cd /home/bb/sinkhole
.venv/bin/python scripts/team2_logic_check.py
.venv/bin/python scripts/realworld_validation.py
```

## Local Integration Demo (Template Website)

```bash
cd /home/bb/sinkhole
.venv/bin/python scripts/localhost_integration_demo.py
```

## Config (env vars)

- `BOTWALL_HOST` (default `127.0.0.1`)
- `BOTWALL_PORT` (default `4000`)
- `BOTWALL_SESSION_COOKIE` (default `bw_sid`)
- `BOTWALL_SECRET_KEY` (default `dev-change-me`)
- `BOTWALL_TELEMETRY_SECRET` (default `telemetry-dev-secret`)
- `BOTWALL_REDIS_ENABLED` (`1` to enable Redis)
- `BOTWALL_REDIS_URL` (default `redis://127.0.0.1:6379/0`)
- `BOTWALL_PROOF_TTL` (default `60`)
- `BOTWALL_TRAVERSAL_TTL` (default `300`)
- `BOTWALL_SEQUENCE_WINDOW` (default `16`)
- `BOTWALL_PEER_SECRETS` (JSON map of `source -> secret`)

## Notes

- Screenshot detection on the open web is heuristic only; this implementation does not claim deterministic screenshot detection.
- Decoy responses set robots exclusion signals (`noindex/noarchive/nofollow`) and are isolated from normal content routes.

## Deployment Automation

- For push-to-deploy on AWS using GitHub Actions + SSH, see `CICD_AWS_SETUP.md`.
