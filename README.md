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

## Standalone Reverse Proxy Container Deployment

You can deploy Botwall as a generic Layer-7 Docker container to protect *any* website (acts like a self-hosted Cloudflare). The `Dockerfile.standalone` bundles both Nginx and Botwall.

### 1. Build the All-in-One Image

```bash
docker build -f Dockerfile.standalone -t botwall-proxy:latest .
```

### 2. Run the Container

Protect any target website simply by changing the `UPSTREAM_URL` environment variable:

```bash
docker run -d \
  --name botwall \
  -p 80:80 \
  -e UPSTREAM_URL="https://your-actual-website.com" \
  -e BOTWALL_SECRET_KEY="your-secure-secret-key" \
  botwall-proxy:latest
```

## Testing on AWS EC2

To quickly test this standalone setup on AWS:

1. Launch a new EC2 Instance (e.g., Ubuntu 24.04 LTS, t2.micro). Ensure **HTTP traffic (port 80)** is allowed in the Security Group.
2. SSH into your instance and install Docker:

   ```bash
   sudo apt-get update
   sudo apt-get install -y docker.io docker-compose
   sudo systemctl start docker
   sudo systemctl enable docker
   sudo usermod -aG docker ubuntu
   newgrp docker
   ```

3. Clone your repository (or transfer your files via `scp`):

   ```bash
   git clone <your-repo-url> sinkhole
   cd sinkhole
   ```

4. Build and run the generic proxy (replace `httpbin.org` with your target):

   ```bash
   docker build -f Dockerfile.standalone -t botwall-proxy:latest .
   docker run -d \
     --name botwall \
     -p 80:80 \
     -e UPSTREAM_URL="http://httpbin.org" \
     -e BOTWALL_SECRET_KEY="super-secret-aws-key" \
     botwall-proxy:latest
   ```

5. Navigate to your EC2 instance's **Public IP** in your browser. You will see traffic proxying to your target website, protected by Botwall.
