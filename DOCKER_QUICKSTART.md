# SinkHole Docker Quickstart

SinkHole ships as a **single Docker image** that drops in front of **any** website — Node.js, PHP, Ruby, Next.js, Django, WordPress, anything. No code changes needed.

## How it works

```
Your Users → SinkHole (Docker) → Your Website
```

1. All traffic hits SinkHole's built-in Nginx.
2. Nginx asks the Botwall engine: *"Is this a human?"*
3. Bots get trapped in a decoy labyrinth. Humans pass through to your site.

---

## 1. Quick Start (Demo Mode)

Test SinkHole instantly with a bundled dummy website:

```bash
docker compose -f docker-compose.demo.yml up -d --build
```

Visit `http://localhost` — SinkHole is protecting it!

---

## 2. Protect ANY Website

### Option A: Your website runs on the same machine

```bash
# Set UPSTREAM_URL to your app and run
UPSTREAM_URL=http://host.docker.internal:3000 docker compose up -d --build
```

### Option B: Your website is a Docker container

Edit `docker-compose.yml`:

```yaml
services:
  sinkhole:
    build: .
    ports:
      - "80:80"
    environment:
      - UPSTREAM_URL=http://my-app:3000  # ← your container name + port
      - BOTWALL_SECRET_KEY=your-secret-here

  my-app:
    image: my-website:latest
    expose:
      - "3000"
```

### Option C: Your website is an external URL

```yaml
environment:
  - UPSTREAM_URL=https://my-production-website.com
```

### Option D: Pre-built image from ECR

```bash
docker run -d -p 80:80 \
  -e UPSTREAM_URL=http://my-website:3000 \
  -e BOTWALL_SECRET_KEY=$(openssl rand -hex 32) \
  123456789.dkr.ecr.ap-south-1.amazonaws.com/sinkhole:latest
```

---

## 3. Add the JS SDK (Optional, Recommended)

For advanced behavioral analytics (mouse tracking, scroll dynamics, entropy analysis), add this to your website's `<head>`:

```html
<script src="/bw/sdk.js" defer></script>
```

SinkHole will ingest the behavioral beacons silently in the background.

---

## 4. Deploy to AWS

See [AWS_DOCKER_DEPLOY.md](AWS_DOCKER_DEPLOY.md) for the full guide:
- Push to ECR
- Run on ECS Fargate
- Set up ALB + HTTPS
- CI/CD via GitHub Actions

---

## 5. Production Security

Before exposing to the internet:

```bash
# Generate strong keys
export BOTWALL_SECRET_KEY=$(openssl rand -hex 32)
export BOTWALL_TELEMETRY_SECRET=$(openssl rand -hex 32)
```

For multi-instance deployments, enable Redis:
```yaml
- BOTWALL_REDIS_ENABLED=1
- BOTWALL_REDIS_URL=redis://your-redis:6379/0
```
