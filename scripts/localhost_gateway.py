#!/usr/bin/env python3
from __future__ import annotations

import os
import urllib.parse

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def _path_with_query(request: Request) -> str:
    path = request.url.path or "/"
    if request.url.query:
        return f"{path}?{request.url.query}"
    return path


def _request_headers(request: Request) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in request.headers.items():
        lk = key.lower()
        if lk in HOP_BY_HOP_HEADERS or lk in {"host", "content-length"}:
            continue
        headers[key] = value
    headers["x-forwarded-for"] = _client_ip(request)
    return headers


def _botwall_check_headers(request: Request) -> dict[str, str]:
    headers: dict[str, str] = {
        "x-forwarded-for": _client_ip(request),
    }
    for key in ("user-agent", "accept-language", "x-ja3", "x-ip-reputation", "cookie"):
        value = request.headers.get(key)
        if value:
            headers[key] = value
    return headers


def _copy_set_cookie_headers(upstream: httpx.Response, downstream: Response) -> None:
    for cookie in upstream.headers.get_list("set-cookie"):
        downstream.headers.append("set-cookie", cookie)


def _build_downstream_response(upstream: httpx.Response) -> Response:
    response = Response(content=upstream.content, status_code=upstream.status_code)
    for key, value in upstream.headers.items():
        lk = key.lower()
        if lk in HOP_BY_HOP_HEADERS or lk in {"content-length", "set-cookie"}:
            continue
        response.headers[key] = value
    _copy_set_cookie_headers(upstream, response)
    return response


async def _proxy_request(client: httpx.AsyncClient, request: Request, upstream_base: str) -> Response:
    url = f"{upstream_base.rstrip('/')}{_path_with_query(request)}"
    body = await request.body()
    upstream = await client.request(
        method=request.method,
        url=url,
        headers=_request_headers(request),
        content=body,
        follow_redirects=False,
        timeout=20.0,
    )
    return _build_downstream_response(upstream)


def create_gateway() -> FastAPI:
    app = FastAPI(title="Botwall Localhost Gateway", version="0.1.0")

    botwall_url = os.getenv("BOTWALL_URL", "http://127.0.0.1:4000")
    origin_url = os.getenv("ORIGIN_URL", "http://127.0.0.1:9000")

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "botwall": botwall_url,
                "origin": origin_url,
            }
        )

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    async def gateway(full_path: str, request: Request) -> Response:
        _ = full_path
        async with httpx.AsyncClient() as client:
            if request.url.path.startswith("/bw/"):
                return await _proxy_request(client, request, botwall_url)

            target = _path_with_query(request)

            gate_headers = _botwall_check_headers(request)
            gate_check = await client.get(
                f"{botwall_url}/bw/gate/check",
                headers=gate_headers,
                follow_redirects=False,
                timeout=10.0,
            )
            if gate_check.status_code != 200:
                encoded = urllib.parse.quote(target, safe="/?=&")
                response = RedirectResponse(url=f"/bw/gate/challenge?path={encoded}", status_code=302)
                _copy_set_cookie_headers(gate_check, response)
                return response

            check_headers = _botwall_check_headers(request)
            check_headers["x-original-uri"] = target
            check_resp = await client.get(
                f"{botwall_url}/bw/check",
                params={"path": request.url.path},
                headers=check_headers,
                follow_redirects=False,
                timeout=10.0,
            )

            if decision == "challenge":
                encoded = urllib.parse.quote(target, safe="/?=&")
                response = RedirectResponse(url=f"/bw/challenge?path={encoded}", status_code=302)
                _copy_set_cookie_headers(check_resp, response)
                return response

            if decision == "decoy":
                sid = ""
                try:
                    sid = str(check_resp.json().get("session_id", "")).strip()
                except Exception:
                    sid = ""
                loc = f"/content/archive/0?sid={sid}" if sid else "/content/archive/0"
                response = RedirectResponse(url=loc, status_code=302)
                _copy_set_cookie_headers(check_resp, response)
                return response

            origin_resp = await _proxy_request(client, request, origin_url)
            _copy_set_cookie_headers(check_resp, origin_resp)
            score = check_resp.headers.get("x-botwall-score")
            reasons = check_resp.headers.get("x-botwall-reasons")
            if score:
                origin_resp.headers["x-botwall-score"] = score
            if reasons:
                origin_resp.headers["x-botwall-reasons"] = reasons
            return origin_resp

    return app


if __name__ == "__main__":
    host = os.getenv("GATEWAY_HOST", "127.0.0.1")
    port = int(os.getenv("GATEWAY_PORT", "8080"))
    uvicorn.run(create_gateway(), host=host, port=port)
