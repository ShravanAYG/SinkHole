#!/usr/bin/env python3
from __future__ import annotations

import os

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="Local Origin Demo", version="0.1.0")


@app.get("/healthz")
async def healthz() -> JSONResponse:
    return JSONResponse({"status": "ok", "site": "origin-demo"})


@app.get("/")
async def home() -> HTMLResponse:
    return HTMLResponse(
        """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Local Origin Demo</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; line-height: 1.5; }
    .badge { display: inline-block; background: #1f2937; color: #fff; padding: 0.25rem 0.6rem; border-radius: 999px; font-size: 0.8rem; }
    a { margin-right: 1rem; }
  </style>
</head>
<body>
  <span class="badge">Origin Server</span>
  <h1>Local Origin Demo Site</h1>
  <p>If you can read this page through the gateway, Botwall allowed the request.</p>
  <nav>
    <a href="/pricing">Pricing</a>
    <a href="/docs">Docs</a>
    <a href="/contact">Contact</a>
  </nav>
</body>
</html>"""
    )


@app.get("/pricing")
async def pricing() -> HTMLResponse:
    return HTMLResponse(
        """<h1>Pricing</h1>
<p>Starter: $19/mo</p>
<p>Growth: $79/mo</p>
<p>Enterprise: contact sales</p>"""
    )


@app.get("/docs")
async def docs() -> HTMLResponse:
    return HTMLResponse("<h1>Docs</h1><p>Public product documentation served by origin.</p>")


@app.get("/contact")
async def contact() -> HTMLResponse:
    return HTMLResponse("<h1>Contact</h1><p>Email: support@example.test</p>")


if __name__ == "__main__":
    host = os.getenv("ORIGIN_HOST", "127.0.0.1")
    port = int(os.getenv("ORIGIN_PORT", "9000"))
    uvicorn.run(app, host=host, port=port)
