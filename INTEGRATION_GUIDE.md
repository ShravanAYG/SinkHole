# SinkHole Integration Guide (Phase 1 + Phase 2)

This guide documents how to integrate SinkHole with a website using reverse-proxy auth checks and Stage-1 gate verification.

## What is implemented

- Phase 1 Entry Gate:
  - `GET /bw/gate/challenge`
  - `POST /bw/gate/verify`
  - `GET /bw/gate/check`
  - Signed challenge token, PoW difficulty validation, anti-replay, IP-bound gate cookie.
- Phase 2 Detection + Decision:
  - `GET /bw/check` for request decisioning.
  - `GET /bw/challenge` and `POST /bw/proof` for Stage-2 proof submission.
  - `POST /api/v1/analytics-ping`, `POST /cdn-ping/perf`, `POST /event/flow/{alias}` for beacon ingestion.
  - `GET /bw/decoy/{node}` for Layer-2 decoy routing.

## Decision model summary

- Stage-1 gate decides if a visitor can enter at all.
- Stage-2 scoring classifies traffic into `allow`, `observe`, `challenge`, or `decoy`.
- Recovery flow can temporarily re-allow false positives.

## Integration architecture

1. Website traffic reaches your reverse proxy.
2. Reverse proxy calls SinkHole decision endpoint (`/bw/check`) via `auth_request`.
3. Proxy inspects `X-Botwall-Decision` header and routes:
   - `challenge` -> redirect to `/bw/challenge` (Stage-2 proof)
   - `decoy` -> redirect to `/bw/decoy/{node}`
   - `allow`/`observe` -> pass to origin
4. For first entry (no gate cookie), proxy or app path should direct to `/bw/gate/challenge`.
5. After successful Stage-1 verify, `bw_gate` and `bw_sid` cookies are set.
6. Optional helper endpoint `/bw/gate/check` can be used by proxies to verify gate cookie validity.

## Required headers forwarded by proxy

Forward these headers to SinkHole endpoints:

- `X-Original-URI`
- `X-Forwarded-For`
- `User-Agent`
- `Accept-Language`
- `Cookie`
- Optional: `X-IP-Reputation`, `X-JA3`

## Nginx integration (primary)

Use `deploy/nginx.conf` as template. Core pattern:

```nginx
location = /__bw_check {
    internal;
    proxy_pass http://botwall_api/bw/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header User-Agent $http_user_agent;
    proxy_set_header Accept-Language $http_accept_language;
    proxy_set_header Cookie $http_cookie;
}

location / {
    auth_request /__bw_check;
    auth_request_set $bw_decision $upstream_http_x_botwall_decision;

    if ($bw_decision = challenge) {
        return 302 http://127.0.0.1:4000/bw/challenge?path=$uri;
    }
    if ($bw_decision = decoy) {
        return 302 http://127.0.0.1:4000/bw/decoy/0;
    }

    proxy_pass http://127.0.0.1:4000;
}
```

## Run locally

```bash
cd /home/bb/sinkhole
python3 -m venv .venv
.venv/bin/pip install -e .[dev]
.venv/bin/python -m botwall
```

Server defaults to `http://127.0.0.1:4000`.

## Example template website walkthrough (working demo)

This repository includes a local demo origin site and a local gateway that simulates reverse-proxy integration.

Run:

```bash
cd /home/bb/sinkhole
.venv/bin/python scripts/localhost_integration_demo.py
```

What it validates:

- Stage-1 gate redirect and successful PoW verification.
- Browser session reaches origin pages through the gateway.
- Headless profile is routed to decoy after scoring.
- Recovery flow restores access for false-positive human traffic.

## Verify key endpoints manually

```bash
# Health
curl -i http://127.0.0.1:4000/healthz

# Gate challenge page
curl -i "http://127.0.0.1:4000/bw/gate/challenge?path=/"

# Gate cookie check (should be 401 without bw_gate)
curl -i http://127.0.0.1:4000/bw/gate/check

# Runtime config (safe values only)
curl -i http://127.0.0.1:4000/bw/config
```

## Production notes

- Set strong `BOTWALL_SECRET_KEY` and `BOTWALL_TELEMETRY_SECRET`.
- Set HTTPS and secure cookie policy at edge.
- Tune thresholds/weights in `botwall.toml` per traffic profile.
- Log and monitor decision distribution (`allow/observe/challenge/decoy`).
- Start with moderate thresholds and increase strictness after observing false positives.

## Troubleshooting

- Frequent invalid gate token errors:
  - Confirm `X-Forwarded-For` is stable across gate challenge and verify requests.
- All users challenged repeatedly:
  - Ensure cookies (`bw_sid`, `bw_gate`) are preserved by proxy and browser.
- Too many false positives:
  - Reduce negative weights, lower strictness in bot markers, and tune decoy threshold.
- No decoy routing at all:
  - Verify proxy handles `X-Botwall-Decision: decoy` redirect path.
