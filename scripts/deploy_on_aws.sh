#!/usr/bin/env bash
set -euo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-$HOME/sinkhole}"
DEPLOY_BRANCH="${DEPLOY_BRANCH:-main}"
REPO_URL="${REPO_URL:-}"
SERVICE_NAME="${SERVICE_NAME:-botwall}"
RUN_MIGRATIONS="${RUN_MIGRATIONS:-0}"
RUN_VALIDATE_LIVE="${RUN_VALIDATE_LIVE:-0}"

echo "[deploy] directory: ${DEPLOY_DIR}"
echo "[deploy] branch: ${DEPLOY_BRANCH}"

if [ ! -d "${DEPLOY_DIR}" ]; then
  if [ -z "${REPO_URL}" ]; then
    echo "[deploy] ERROR: DEPLOY_DIR is missing and REPO_URL is empty"
    exit 1
  fi
  echo "[deploy] cloning repository into ${DEPLOY_DIR}"
  git clone "${REPO_URL}" "${DEPLOY_DIR}"
fi

cd "${DEPLOY_DIR}"

if [ ! -d .git ]; then
  echo "[deploy] ERROR: ${DEPLOY_DIR} is not a git repository"
  exit 1
fi

echo "[deploy] fetching latest code"
git fetch --all --prune
git checkout "${DEPLOY_BRANCH}"
git pull --ff-only origin "${DEPLOY_BRANCH}"

if [ ! -d .venv ]; then
  echo "[deploy] creating virtual environment"
  python3 -m venv .venv
fi

echo "[deploy] installing dependencies"
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e .

if [ "${RUN_MIGRATIONS}" = "1" ]; then
  echo "[deploy] RUN_MIGRATIONS=1 set, but no migration step is configured for this project"
fi

echo "[deploy] running smoke tests"
.venv/bin/python -m pytest -q tests/test_tokens.py tests/test_api_integration.py

if [ "${RUN_VALIDATE_LIVE}" = "1" ]; then
  echo "[deploy] running live validation"
  .venv/bin/python scripts/validate_live.py
fi

echo "[deploy] restarting service: ${SERVICE_NAME}"
if command -v systemctl >/dev/null 2>&1; then
  if sudo -n true >/dev/null 2>&1; then
    sudo systemctl restart "${SERVICE_NAME}"
    sudo systemctl is-active --quiet "${SERVICE_NAME}"
  else
    systemctl --user restart "${SERVICE_NAME}"
    systemctl --user is-active --quiet "${SERVICE_NAME}"
  fi
else
  echo "[deploy] ERROR: systemctl not found; configure service restart manually"
  exit 1
fi

echo "[deploy] completed successfully"
