# SinkHole Docker Quickstart

SinkHole is built to drop in front of **any** web application (Node.js, PHP, Ruby, Next.js, etc.) without requiring any application code changes. 

We provide a production-ready `docker-compose` environment that stands up Nginx as the edge proxy alongside the SinkHole Engine.

## How it works

1. All web traffic hits Nginx.
2. Nginx asks SinkHole: *"Is this a human?"* (`/__bw_check`)
3. SinkHole calculates behavior, Proof-of-Work, and trap data.
4. Nginx either routes traffic to your `origin_app`, or drops it into the Decoy Labyrinth.

## 1. Quick Start (Demo Mode)

We have bundled a dummy website (`httpbin`) so you can test SinkHole instantly:

```bash
docker-compose up -d --build
```
* **Done.** Wait 15 seconds, and go to `http://localhost`. SinkHole is protecting it! 
* Try running a basic scraper: `curl http://localhost` — you will get routed immediately into the decoy maze.

## 2. Bring Your Own Web App

When you want to protect your actual application, modify the `docker-compose.yml` to point to your existing Docker container.

### Edit `docker-compose.yml`:
Swap out the `origin_app` block with your application:

```yaml
  origin_app:
    image: my-node-website:latest  # <--- YOUR IMAGE HERE
    expose:
      - "3000"                    # <--- YOUR APP'S INTERNAL PORT
```

### Edit `deploy/docker-nginx.conf`:
Update the proxy pass to match your container's port:
```nginx
    # Pass clean traffic directly to the Origin App (Target Service)
    proxy_pass http://origin_app:3000;  # <--- CHANGE TO YOUR PORT
```

Rebuild:
```bash
docker-compose up -d --build
```

## 3. The Final Step: Add the JS SDK

To get advanced Phase 2 Behavioral Analytics (mouse tracking, entropy analysis, scroll dynamics), inject our SDK into the `<head>` of your website's HTML template:

```html
<script src="/bw/sdk.js" defer></script>
```

When users hit your actual site, SinkHole will ingest the beacons in the background silently.

## 4. Going to Production

Before putting this exposed on the internet, secure your `docker-compose.yml`:
1. Change `BOTWALL_SECRET_KEY` and `BOTWALL_TELEMETRY_SECRET` to random, hyper-secure hashes.
2. If running across multiple nodes, scale it up via Redis:
   * Set `BOTWALL_REDIS_ENABLED=1`
   * Provide a Redis instance: `BOTWALL_REDIS_URL='redis://your-redis-server:6379/0'`
