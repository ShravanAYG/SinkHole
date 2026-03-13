# ─────────────────────────────────────────────────────────────────────────────
# SinkHole — Standalone Docker Image
#
# A single container that protects ANY website.
# Just set UPSTREAM_URL to your website and you're done.
#
# Usage:
#   docker run -p 80:80 -e UPSTREAM_URL=http://my-website:3000 sinkhole
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Install Python deps ─────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/build/deps -r requirements.txt


# ── Stage 2: Production image ────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="SinkHole" \
      description="SinkHole Bot Detection Gateway — protects any website" \
      org.opencontainers.image.source="https://github.com/ShravanAYG/SinkHole"

# Install Nginx, Supervisor, and curl (for healthcheck)
RUN apt-get update && \
    apt-get install -y --no-install-recommends nginx gettext-base supervisor curl && \
    rm -rf /var/lib/apt/lists/* && \
    rm -f /etc/nginx/sites-enabled/default

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BOTWALL_HOST=127.0.0.1 \
    BOTWALL_PORT=4000 \
    UPSTREAM_URL=http://localhost:8080 \
    BOTWALL_URL=http://127.0.0.1:4000

WORKDIR /app

# Copy Python dependencies from builder stage
COPY --from=builder /build/deps /usr/local/lib/python3.12/site-packages/

# Copy SinkHole engine source
COPY botwall/ ./botwall/
COPY botwall.toml .

# Copy Nginx template
COPY deploy/docker-nginx.conf.template /etc/nginx/templates/default.conf.template

# Copy Supervisor config
COPY deploy/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy startup script
COPY deploy/startup.sh /startup.sh
RUN chmod +x /startup.sh

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -sf http://localhost:4000/healthz || exit 1

CMD ["/startup.sh"]
