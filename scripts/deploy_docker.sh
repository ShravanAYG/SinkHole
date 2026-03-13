#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SinkHole — Deploy to AWS Debian Server
#
# Run this script on your AWS Debian server via SSH:
#   bash deploy_docker.sh
#
# It will:
#   1. Install Docker & Docker Compose
#   2. Clone the SinkHole repo
#   3. Build the image
#   4. Start SinkHole protecting your website
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "══════════════════════════════════════════════════"
echo "  SinkHole — AWS Debian Docker Deployment"
echo "══════════════════════════════════════════════════"

# ── Step 1: Install Docker ────────────────────────────────────────────────
echo ""
echo "[1/5] Installing Docker..."
if ! command -v docker &>/dev/null; then
    sudo apt-get update
    sudo apt-get install -y ca-certificates curl gnupg
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    sudo usermod -aG docker "$USER"
    echo "  ✅ Docker installed"
else
    echo "  ✅ Docker already installed"
fi

# ── Step 2: Clone SinkHole ───────────────────────────────────────────────
echo ""
echo "[2/5] Cloning SinkHole..."
DEPLOY_DIR="$HOME/sinkhole"
REPO_URL="${REPO_URL:-https://github.com/ShravanAYG/SinkHole.git}"
BRANCH="${BRANCH:-ggg}"

if [ -d "$DEPLOY_DIR" ]; then
    echo "  Updating existing clone..."
    cd "$DEPLOY_DIR"
    git fetch --all
    git checkout "$BRANCH"
    git pull origin "$BRANCH"
else
    git clone -b "$BRANCH" "$REPO_URL" "$DEPLOY_DIR"
    cd "$DEPLOY_DIR"
fi
echo "  ✅ Code ready at $DEPLOY_DIR"

# ── Step 3: Build SinkHole image ─────────────────────────────────────────
echo ""
echo "[3/5] Building SinkHole Docker image..."
sudo docker build -t sinkhole:latest .
echo "  ✅ Image built"

# ── Step 4: Generate secrets ─────────────────────────────────────────────
echo ""
echo "[4/5] Generating security keys..."
SECRET_KEY=$(openssl rand -hex 32)
TELEMETRY_KEY=$(openssl rand -hex 32)
echo "  ✅ Keys generated"

# ── Step 5: Start SinkHole ───────────────────────────────────────────────
echo ""
echo "[5/5] Starting SinkHole..."

# Stop existing container if running
sudo docker rm -f sinkhole 2>/dev/null || true

# Ask for upstream URL
UPSTREAM="${UPSTREAM_URL:-}"
if [ -z "$UPSTREAM" ]; then
    echo ""
    echo "  ┌─────────────────────────────────────────────────┐"
    echo "  │  What website should SinkHole protect?          │"
    echo "  │                                                 │"
    echo "  │  Examples:                                      │"
    echo "  │    http://localhost:3000    (Node.js app)        │"
    echo "  │    http://localhost:8080    (Java/PHP app)       │"
    echo "  │    http://my-app:3000      (Docker container)   │"
    echo "  │    https://my-website.com  (External site)      │"
    echo "  └─────────────────────────────────────────────────┘"
    echo ""
    read -rp "  UPSTREAM_URL: " UPSTREAM
fi

sudo docker run -d \
    --name sinkhole \
    --restart unless-stopped \
    -p 80:80 \
    -e UPSTREAM_URL="$UPSTREAM" \
    -e BOTWALL_SECRET_KEY="$SECRET_KEY" \
    -e BOTWALL_TELEMETRY_SECRET="$TELEMETRY_KEY" \
    sinkhole:latest

echo ""
echo "══════════════════════════════════════════════════"
echo "  ✅ SinkHole is LIVE!"
echo ""
echo "  Protecting:  $UPSTREAM"
echo "  Listening:   http://$(hostname -I | awk '{print $1}'):80"
echo ""
echo "  View logs:   sudo docker logs -f sinkhole"
echo "  Stop:        sudo docker stop sinkhole"
echo "  Restart:     sudo docker restart sinkhole"
echo "══════════════════════════════════════════════════"
