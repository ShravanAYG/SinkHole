# SinkHole Demo Runbook (Another Computer, Port 80)

This runbook is for running the full demo on a different machine with Nginx on port 80.

## Goal

Run these components:

- Origin demo site on 127.0.0.1:9101
- Botwall app on 127.0.0.1:4101
- Nginx frontend on port 80 using [deploy/nginx-live-demo.conf](deploy/nginx-live-demo.conf)
- Optional ngrok tunnel to expose demo publicly

After startup:

- Open http://SERVER_IP/
- Stage 1 should auto-run (PoW gate)
- Stage 2 scoring should work automatically
- Telemetry console at /bw/telemetry

## 1. Prerequisites

### Arch Linux

```bash
sudo pacman -Syu --noconfirm
sudo pacman -S --noconfirm python python-pip python-virtualenv nginx curl ripgrep
```

### Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip nginx curl
```

Optional ngrok install: https://ngrok.com/download

## 2. Clone and install project

```bash
git clone <your-repo-url> sinkhole
cd sinkhole
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
```

## 3. Start backend services

Start origin demo in background:

```bash
ORIGIN_HOST=127.0.0.1 ORIGIN_PORT=9101 .venv/bin/python scripts/demo_origin_site.py
```

Start botwall in background:

```bash
BOTWALL_HOST=127.0.0.1 BOTWALL_PORT=4101 BOTWALL_POW_DIFFICULTY=2 BOTWALL_POW_ELEVATED_DIFFICULTY=3 .venv/bin/python -m botwall
```

You can run each command in separate terminal tabs.

## 4. Start Nginx on port 80

The demo Nginx config is already set to listen on port 80 in [deploy/nginx-live-demo.conf](deploy/nginx-live-demo.conf).

Prepare local runtime folders:

```bash
mkdir -p .demo-nginx/logs .demo-nginx/temp/client_body .demo-nginx/temp/proxy .demo-nginx/temp/fastcgi .demo-nginx/temp/uwsgi .demo-nginx/temp/scgi
```

Start Nginx with elevated privileges (port 80 requires root):

```bash
sudo nginx -p "$PWD/.demo-nginx" -c "$PWD/deploy/nginx-live-demo.conf"
```

Reload after changes:

```bash
sudo nginx -p "$PWD/.demo-nginx" -c "$PWD/deploy/nginx-live-demo.conf" -s reload
```

Stop:

```bash
sudo nginx -p "$PWD/.demo-nginx" -c "$PWD/deploy/nginx-live-demo.conf" -s stop
```

## 5. Verify locally

```bash
curl -i http://127.0.0.1/healthz
curl -i http://127.0.0.1/
curl -i "http://127.0.0.1/bw/gate/challenge?path=/"
curl -i http://127.0.0.1/bw/telemetry
```

Expected:

- `/` returns `302` to `/bw/gate/challenge?path=/` when no gate cookie exists
- Stage 1 page loads with automatic PoW
- Telemetry page returns `200`

## 6. Public demo with ngrok (optional)

Start tunnel:

```bash
ngrok http 80
```

Get public URL:

```bash
curl -s http://127.0.0.1:4040/api/tunnels
```

Use URL for testing:

- `<PUBLIC_URL>/`
- `<PUBLIC_URL>/bw/gate/challenge?path=/`
- `<PUBLIC_URL>/bw/telemetry`

## 7. Run Stage 2 scraper test and metrics

Run against botwall app directly:

```bash
BW_BASE=http://127.0.0.1:4101 .venv/bin/python scripts/stage2_scraper_test.py
```

Or run through Nginx (port 80):

```bash
BW_BASE=http://127.0.0.1 .venv/bin/python scripts/stage2_scraper_test.py
```

Metrics output includes:

- decision counts by profile
- HTTP status counts
- telemetry snapshot summary
- links for Stage 1 and telemetry endpoints

## 8. Share with another tester

Give them:

- Server URL (or ngrok public URL)
- Stage 1 link: `/bw/gate/challenge?path=/`
- Telemetry link: `/bw/telemetry`
- Optional JSON link: `/bw/telemetry.json`

## Troubleshooting

- Port 80 bind error:
  - Another web server already owns port 80. Stop it first.
  - On Linux check: `sudo ss -ltnp '( sport = :80 )'`

- Repeated gate loop:
  - Check cookie forwarding and stable client IP headers at proxy.

- Stage 2 metrics look empty:
  - Run [scripts/stage2_scraper_test.py](scripts/stage2_scraper_test.py) to generate traffic.

- ngrok page works but local does not:
  - Confirm Nginx started with the exact config path shown above.
