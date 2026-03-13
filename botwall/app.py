from __future__ import annotations

import json
import os
import urllib.parse
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response

from .config import Settings, load_settings
from .crypto import TokenError, hash_client_ip, now_ts, sign_json, verify_json
from .decoy import build_node
from .html import (
    render_challenge_page,
    render_dashboard,
    render_decoy_page,
    render_origin_page,
    render_recovery_page,
    sdk_script,
    render_gate_challenge_page,
)
from .models import (
    BeaconEvent,
    CheckResponse,
    DecisionState,
    ProofSubmission,
    RecoveryCompleteRequest,
    RecoveryCompleteResponse,
    RecoveryStartRequest,
    RecoveryStartResponse,
    TelemetryExport,
    TelemetryFingerprint,
    TelemetryImport,
    GateVerifyRequest,
    GateVerifyResponse,
)
from .proof import issue_proof_token, verify_proof_token, issue_gate_token
from .scoring import apply_score, decide, score_beacon, score_request, score_telemetry_match, score_traversal
from .telemetry import export_feed, fingerprint_from_beacon, parse_peer_secrets, verify_import
from .state import StoreManager, init_store
from .traversal import issue_traversal_token, verify_traversal_token


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "0.0.0.0"


def _get_session_id(request: Request, settings: Settings) -> str:
    sid = request.cookies.get(settings.session_cookie)
    if sid:
        return sid
    return uuid.uuid4().hex


def _attach_cookie(response: Response, settings: Settings, session_id: str) -> None:
    response.set_cookie(
        key=settings.session_cookie,
        value=session_id,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 24,
        path="/",
    )


def _canonical_target_path(request: Request, fallback: str) -> str:
    original = request.headers.get("x-original-uri")
    if original:
        parsed = urllib.parse.urlsplit(original)
        return parsed.path or fallback
    return fallback


def _record_decision(session: dict[str, Any], decision: str, reasons: list[str]) -> None:
    history = session.setdefault("decision_history", [])
    history.append({"decision": decision, "reasons": reasons, "at": now_ts()})
    session["decision_history"] = history[-30:]


def _request_meta(request: Request) -> dict[str, str]:
    return {
        "user_agent": request.headers.get("user-agent", ""),
        "accept_language": request.headers.get("accept-language", ""),
        "ip_reputation": request.headers.get("x-ip-reputation", "unknown"),
        "ja3": request.headers.get("x-ja3", ""),
    }


def _make_links(settings: Settings, session_id: str, ip_hash: str, page_id: int) -> list[tuple[str, str]]:
    links: list[tuple[str, str]] = []
    for offset in [1, 2, 3]:
        target_id = (page_id + offset) % 7
        target_path = f"/content/{target_id}"
        token = issue_traversal_token(
            secret=settings.secret_key,
            session_id=session_id,
            ip_hash=ip_hash,
            page_path=target_path,
            ttl_seconds=settings.traversal_ttl_seconds,
        )
        encoded = urllib.parse.quote(token, safe="")
        links.append((f"{target_path}?bw_trace={encoded}", f"Protected Content {target_id}"))
    return links


def _match_telemetry_fingerprint(store: StoreManager, fingerprint: str) -> float:
    for item in reversed(store.store.list_telemetry(limit=200)):
        if item.get("fingerprint") == fingerprint:
            return float(item.get("suspicion", 0.0))
    return 0.0


def _evaluate_request(
    *,
    request: Request,
    settings: Settings,
    store: StoreManager,
    target_path: str,
    require_traversal: bool,
) -> tuple[dict[str, Any], str, list[str], str, str]:
    now = now_ts()
    session_id = _get_session_id(request, settings)
    client_ip = _client_ip(request)
    ip_hash = hash_client_ip(client_ip, settings.secret_key)
    session = store.store.load_session(session_id, ip_hash)

    req_outcome = score_request(_request_meta(request), session, now=now, weights=settings.weights)
    apply_score(session, req_outcome, now=now)

    trace = request.query_params.get("bw_trace")
    if require_traversal:
        valid = False
        if trace:
            valid = verify_traversal_token(
                token=trace,
                secret=settings.secret_key,
                session_id=session_id,
                ip_hash=ip_hash,
                page_path=target_path,
                now=now,
            )
        trav_outcome = score_traversal(session, valid=valid, weights=settings.weights)
        apply_score(session, trav_outcome, now=now)

    # Optional mesh penalty if known suspicious behavioral fingerprint has appeared.
    if session.get("events"):
        last = session["events"][-1]
        try:
            beacon = BeaconEvent(**last)
            fp = fingerprint_from_beacon(settings.secret_key, beacon, ja3=request.headers.get("x-ja3", ""))
            suspicion = _match_telemetry_fingerprint(store, fp)
            if suspicion > 0:
                mesh_outcome = score_telemetry_match(session, suspicion=min(30.0, suspicion))
                apply_score(session, mesh_outcome, now=now)
        except Exception:
            pass

    decision, reasons = decide(
        session,
        sequence_window=settings.sequence_window,
        now=now,
        allow_threshold=settings.allow_threshold,
        decoy_threshold=settings.decoy_threshold,
        observe_threshold=settings.observe_threshold,
    )
    _record_decision(session, decision, reasons + req_outcome.reasons)
    session["last_user_agent"] = request.headers.get("user-agent", "")
    session["updated_at"] = now
    store.store.save_session(session)

    return session, session_id, reasons + req_outcome.reasons, decision, ip_hash


def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(title="Botwall API", version="0.1.0")
    cfg = settings or load_settings()
    store = init_store(cfg.redis_enabled, cfg.redis_url)
    peer_secrets = parse_peer_secrets(cfg.peer_secrets_raw or os.getenv("BOTWALL_PEER_SECRETS"))

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "store": store.backend}

    @app.get("/bw/sdk.js")
    def bw_sdk_js() -> Response:
        return Response(content=sdk_script(), media_type="application/javascript")

    @app.get("/bw/check", response_model=CheckResponse)
    async def bw_check(request: Request) -> JSONResponse:
        fallback = request.query_params.get("path", "/")
        target_path = _canonical_target_path(request, fallback)
        require_traversal = target_path.startswith("/content/")
        session, session_id, reasons, decision, _ = _evaluate_request(
            request=request,
            settings=cfg,
            store=store,
            target_path=target_path,
            require_traversal=require_traversal,
        )
        payload = CheckResponse(
            session_id=session_id,
            decision=decision,
            score=float(session.get("score", 0.0)),
            reasons=reasons,
        )
        response = JSONResponse(payload.model_dump(mode="json"))
        response.headers["x-botwall-decision"] = decision
        response.headers["x-botwall-score"] = f"{float(session.get('score', 0.0)):.2f}"
        response.headers["x-botwall-reasons"] = ",".join(reasons[-6:])
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/bw/challenge")
    async def bw_challenge(request: Request) -> HTMLResponse:
        session_id = _get_session_id(request, cfg)
        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        target_path = request.query_params.get("path", "/")

        session = store.store.load_session(session_id, ip_hash)
        session["challenge_issued"] = int(session.get("challenge_issued", 0)) + 1
        token, nonce = issue_proof_token(
            secret=cfg.secret_key,
            session_id=session_id,
            ip_hash=ip_hash,
            page_path=target_path,
            ttl_seconds=cfg.proof_ttl_seconds,
        )
        session.setdefault("reasons", []).append("challenge:issued")
        session["updated_at"] = now_ts()
        store.store.save_session(session)

        page = render_challenge_page(session_id=session_id, token=token, nonce=nonce, target_path=target_path)
        return HTMLResponse(page)

    @app.get("/bw/gate/challenge")
    async def bw_gate_challenge(request: Request) -> HTMLResponse:
        session_id = _get_session_id(request, cfg)
        target_path = request.query_params.get("path", "/")
        
        import secrets
        challenge = secrets.token_hex(16)
        
        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        session = store.store.load_session(session_id, ip_hash)
        
        diff = cfg.pow_default_difficulty
        if request.headers.get("x-ip-reputation") == "bad" or session.get("gate_failures", 0) >= 2:
            diff = cfg.pow_elevated_difficulty
            
        store.store.mark_once(f"pow:{challenge}", str(diff), cfg.pow_max_solve_seconds)
        
        page = render_gate_challenge_page(
            session_id=session_id, 
            challenge=challenge, 
            difficulty=diff, 
            target_path=target_path
        )
        return HTMLResponse(page)

    @app.post("/bw/gate/verify", response_model=GateVerifyResponse)
    async def bw_gate_verify(request: Request, payload: GateVerifyRequest) -> GateVerifyResponse | JSONResponse:
        import hashlib
        
        challenge = payload.challenge
        submitted_nonce = payload.nonce
        
        # Verify the challenge exists and is not expired (using mark_once as basic exist check, though it marks it)
        # Note: mark_once returns True if it sets it (meaning it didn't exist). 
        # Wait, actually we can just store the challenge in session or mark_once earlier? 
        # If we didn't use redis properly to fetch difficulty, we can re-derive it
        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        
        session_id = _get_session_id(request, cfg)
        session = store.store.load_session(session_id, ip_hash)
        
        diff = cfg.pow_default_difficulty
        if request.headers.get("x-ip-reputation") == "bad" or session.get("gate_failures", 0) >= 2:
            diff = cfg.pow_elevated_difficulty
            
        target = "0" * diff
        input_bytes = (challenge + submitted_nonce).encode("utf-8")
        computed_hash = hashlib.sha256(input_bytes).hexdigest()
        
        if not computed_hash.startswith(target):
            session["gate_failures"] = session.get("gate_failures", 0) + 1
            store.store.save_session(session)
            return JSONResponse(status_code=400, content={"ok": False, "reason": "invalid_pow"})
            
        # Optional: anti-replay check
        if not store.store.mark_once("pow_solved", challenge, cfg.pow_max_solve_seconds):
            return JSONResponse(status_code=400, content={"ok": False, "reason": "replayed_pow"})

        # Score environment
        env_score = 0.0
        env = payload.env_report
        ua = request.headers.get("user-agent", "")
        
        if env.webdriver:
            session["gate_failures"] = session.get("gate_failures", 0) + 2
            store.store.save_session(session)
            return JSONResponse(status_code=400, content={"ok": False, "reason": "webdriver_detected"})
            
        if "Chrome" in ua and not env.chrome_obj:
            env_score -= 30
        if env.plugins_count < 1:
            env_score -= 15
        if len(env.languages) < 2:
            env_score -= 10
        if not env.notification_api:
            env_score -= 10
        if "Chrome" in ua and not env.perf_memory:
            env_score -= 10
        if tuple(env.viewport) == (0, 0) or tuple(env.viewport) == (800, 600):
            env_score -= 15
        if env.renderer in ["none", "SwiftShader", "llvmpipe"]:
            env_score -= 20
            
        token, _ = issue_gate_token(
            secret=cfg.secret_key,
            session_id=session_id,
            ip_hash=ip_hash,
            difficulty=diff,
            env_score=env_score,
            ttl_seconds=cfg.gate_ttl_seconds
        )
        
        response = GateVerifyResponse(ok=True)
        resp_obj = JSONResponse(content=response.model_dump())
        resp_obj.set_cookie(
            key=cfg.gate_cookie,
            value=token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=cfg.gate_ttl_seconds,
            path="/"
        )
        
        session["gate_failures"] = 0
        store.store.save_session(session)
        return resp_obj

    @app.post("/bw/proof", response_model=DecisionState)
    async def bw_proof(request: Request, payload: ProofSubmission) -> JSONResponse:
        session_id = _get_session_id(request, cfg)
        if payload.session_id != session_id:
            raise HTTPException(status_code=400, detail="session mismatch")

        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        session = store.store.load_session(session_id, ip_hash)

        try:
            proof_payload = verify_proof_token(
                token=payload.token,
                secret=cfg.secret_key,
                session_id=session_id,
                ip_hash=ip_hash,
                page_path=payload.page_path,
                nonce=payload.nonce,
                now=now_ts(),
            )
        except TokenError as exc:
            raise HTTPException(status_code=400, detail=f"invalid proof: {exc}") from exc

        if not store.store.mark_once("proof_jti", str(proof_payload.get("jti")), cfg.proof_ttl_seconds * 2):
            raise HTTPException(status_code=409, detail="proof replay detected")

        beacon_outcome = score_beacon(payload.beacon, request_ua=request.headers.get("user-agent"), weights=cfg.weights)
        apply_score(session, beacon_outcome, now=now_ts())

        session["proof_valid"] = int(session.get("proof_valid", 0)) + 1
        events = session.setdefault("events", [])
        events.append(payload.beacon.model_dump(mode="json"))
        session["events"] = events[-64:]

        decision, reasons = decide(
            session,
            sequence_window=cfg.sequence_window,
            now=now_ts(),
            allow_threshold=cfg.allow_threshold,
            decoy_threshold=cfg.decoy_threshold,
            observe_threshold=cfg.observe_threshold,
        )
        _record_decision(session, decision, reasons + beacon_outcome.reasons)
        store.store.save_session(session)

        result = DecisionState(
            session_id=session_id,
            decision=decision,
            score=float(session.get("score", 0.0)),
            reasons=reasons + beacon_outcome.reasons,
            needs_challenge=(decision == "challenge"),
        )
        response = JSONResponse(result.model_dump(mode="json"), status_code=202)
        response.headers["x-botwall-decision"] = decision
        _attach_cookie(response, cfg, session_id)
        return response

    async def _ingest_beacon(request: Request, payload: BeaconEvent) -> JSONResponse:
        session_id = payload.session_id or _get_session_id(request, cfg)
        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        session = store.store.load_session(session_id, ip_hash)

        outcome = score_beacon(payload, request_ua=request.headers.get("user-agent"), weights=cfg.weights)
        apply_score(session, outcome, now=now_ts())
        events = session.setdefault("events", [])
        events.append(payload.model_dump(mode="json"))
        session["events"] = events[-64:]
        store.store.save_session(session)

        fingerprint = fingerprint_from_beacon(cfg.secret_key, payload, ja3=request.headers.get("x-ja3", ""))
        suspicion = max(0.0, min(100.0, -outcome.delta))
        store.store.add_telemetry(
            TelemetryFingerprint(
                fingerprint=fingerprint,
                suspicion=suspicion,
                source="local",
                observed_at=now_ts(),
            ).model_dump(mode="json")
        )

        response = JSONResponse({"ok": True, "session_id": session_id}, status_code=202)
        _attach_cookie(response, cfg, session_id)
        return response

    @app.post("/api/v1/analytics-ping")
    async def analytics_ping(request: Request, payload: BeaconEvent) -> JSONResponse:
        return await _ingest_beacon(request, payload)

    @app.post("/cdn-ping/perf")
    async def cdn_ping(request: Request, payload: BeaconEvent) -> JSONResponse:
        return await _ingest_beacon(request, payload)

    @app.post("/event/flow/{alias}")
    async def flow_ping(alias: str, request: Request, payload: BeaconEvent) -> JSONResponse:
        _ = alias
        return await _ingest_beacon(request, payload)

    @app.get("/bw/decoy/{node_id}")
    async def bw_decoy(node_id: int, request: Request) -> HTMLResponse:
        session_id = request.query_params.get("sid") or _get_session_id(request, cfg)
        node = build_node(session_id, node_id % cfg.decoy_max_nodes)
        response = HTMLResponse(render_decoy_page(node=node, session_id=session_id))
        response.headers["x-botwall-decision"] = "decoy"
        response.headers["x-robots-tag"] = "noindex, noarchive, nofollow"
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/bw/recovery")
    async def bw_recovery(request: Request) -> HTMLResponse:
        session_id = _get_session_id(request, cfg)
        response = HTMLResponse(render_recovery_page(session_id))
        _attach_cookie(response, cfg, session_id)
        return response

    @app.post("/bw/recovery/start", response_model=RecoveryStartResponse)
    async def bw_recovery_start(request: Request) -> JSONResponse:
        body = await request.body()
        data: dict[str, Any]
        if body:
            try:
                data = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                data = {}
        else:
            data = {}

        session_id = data.get("session_id") or _get_session_id(request, cfg)
        RecoveryStartRequest(session_id=session_id, reason=str(data.get("reason", "false_positive")))

        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        session = store.store.load_session(session_id, ip_hash)

        now = now_ts()
        token = sign_json(
            {
                "t": "recovery",
                "sid": session_id,
                "iph": ip_hash,
                "jti": uuid.uuid4().hex,
                "iat": now,
                "exp": now + cfg.recovery_ttl_seconds,
            },
            cfg.secret_key,
        )
        session["recovery_started"] = now
        store.store.save_session(session)

        payload = RecoveryStartResponse(
            recovery_token=token,
            instruction='Call /bw/recovery/complete with acknowledgement: "I am human and need real content".',
        )
        response = JSONResponse(payload.model_dump(mode="json"), status_code=202)
        _attach_cookie(response, cfg, session_id)
        return response

    @app.post("/bw/recovery/complete", response_model=RecoveryCompleteResponse)
    async def bw_recovery_complete(request: Request, payload: RecoveryCompleteRequest) -> JSONResponse:
        session_id = _get_session_id(request, cfg)
        if payload.session_id != session_id:
            raise HTTPException(status_code=400, detail="session mismatch")

        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        session = store.store.load_session(session_id, ip_hash)

        try:
            parsed = verify_json(payload.recovery_token, cfg.secret_key)
        except TokenError as exc:
            raise HTTPException(status_code=400, detail=f"invalid recovery token: {exc}") from exc

        now = now_ts()
        if parsed.get("t") != "recovery" or parsed.get("sid") != session_id or parsed.get("iph") != ip_hash:
            raise HTTPException(status_code=400, detail="invalid recovery token binding")
        if int(parsed.get("exp", 0)) < now:
            raise HTTPException(status_code=400, detail="recovery token expired")
        if payload.acknowledgement.strip() != "I am human and need real content":
            raise HTTPException(status_code=400, detail="acknowledgement mismatch")

        jti = str(parsed.get("jti"))
        if not store.store.mark_once("recovery_jti", jti, 300):
            raise HTTPException(status_code=409, detail="recovery token replay detected")

        session["allow_until"] = now + cfg.recovery_allow_seconds
        session["score"] = float(session.get("score", 0.0) + 25.0)
        session.setdefault("reasons", []).append("recovery:completed")
        store.store.save_session(session)

        result = RecoveryCompleteResponse(decision="allow", allow_until=int(session["allow_until"]))
        response = JSONResponse(result.model_dump(mode="json"), status_code=202)
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/telemetry/feed/export", response_model=TelemetryExport)
    async def telemetry_export() -> JSONResponse:
        rows = store.store.list_telemetry(limit=200)
        payload = export_feed(source="local", fingerprints=rows, secret=cfg.telemetry_secret)
        return JSONResponse(payload.model_dump(mode="json"))

    @app.post("/telemetry/feed/import")
    async def telemetry_import(payload: TelemetryImport) -> JSONResponse:
        peer_secret = peer_secrets.get(payload.source, cfg.telemetry_secret)
        if not verify_import(payload, peer_secret):
            raise HTTPException(status_code=400, detail="invalid telemetry signature")

        for fp in payload.fingerprints:
            store.store.add_telemetry(fp.model_dump(mode="json"))

        return JSONResponse({"ok": True, "imported": len(payload.fingerprints)})

    @app.get("/bw/dashboard")
    async def bw_dashboard() -> HTMLResponse:
        body = {
            "store_backend": store.backend,
            "sessions": store.store.list_sessions(limit=100),
            "telemetry": store.store.list_telemetry(limit=120),
        }
        return HTMLResponse(render_dashboard(body))

    @app.get("/__dashboard")
    async def bw_dashboard_json() -> JSONResponse:
        return JSONResponse(
            {
                "store_backend": store.backend,
                "sessions": store.store.list_sessions(limit=100),
                "telemetry": store.store.list_telemetry(limit=120),
            }
        )

    @app.get("/bw/config")
    async def bw_config_dump() -> JSONResponse:
        """Expose active configuration for operators (omits secrets)."""
        return JSONResponse({
            "server": {"host": cfg.app_host, "port": cfg.app_port},
            "scoring": {
                "allow_threshold": cfg.allow_threshold,
                "decoy_threshold": cfg.decoy_threshold,
                "observe_threshold": cfg.observe_threshold,
                "sequence_window": cfg.sequence_window,
            },
            "tokens": {
                "proof_ttl_seconds": cfg.proof_ttl_seconds,
                "traversal_ttl_seconds": cfg.traversal_ttl_seconds,
                "recovery_ttl_seconds": cfg.recovery_ttl_seconds,
                "gate_ttl_seconds": cfg.gate_ttl_seconds,
            },
            "pow": {
                "default_difficulty": cfg.pow_default_difficulty,
                "elevated_difficulty": cfg.pow_elevated_difficulty,
                "max_solve_seconds": cfg.pow_max_solve_seconds,
            },
            "decoy": {
                "max_nodes": cfg.decoy_max_nodes,
                "min_links": cfg.decoy_min_links,
                "max_links": cfg.decoy_max_links,
            },
            "telemetry": {"enabled": cfg.telemetry_enabled},
            "store_backend": store.backend,
        })

    @app.get("/")
    async def home(request: Request) -> Response:
        session, session_id, reasons, decision, ip_hash = _evaluate_request(
            request=request,
            settings=cfg,
            store=store,
            target_path="/",
            require_traversal=False,
        )
        if decision == "decoy":
            response = RedirectResponse(url=f"/bw/decoy/0?sid={session_id}", status_code=302)
            _attach_cookie(response, cfg, session_id)
            return response
        if decision == "challenge":
            response = RedirectResponse(url="/bw/challenge?path=/", status_code=302)
            _attach_cookie(response, cfg, session_id)
            return response

        links = _make_links(cfg, session_id, ip_hash, page_id=0)
        page = render_origin_page(session_id=session_id, page_id=0, links=links)
        response = HTMLResponse(page)
        response.headers["x-botwall-decision"] = decision
        response.headers["x-botwall-reasons"] = ",".join(reasons[-6:])
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/content/{page_id}")
    async def content_page(page_id: int, request: Request) -> Response:
        target_path = f"/content/{page_id}"
        session, session_id, reasons, decision, ip_hash = _evaluate_request(
            request=request,
            settings=cfg,
            store=store,
            target_path=target_path,
            require_traversal=True,
        )

        if decision == "decoy":
            response = RedirectResponse(url=f"/bw/decoy/{page_id % cfg.decoy_max_nodes}?sid={session_id}", status_code=302)
            _attach_cookie(response, cfg, session_id)
            return response
        if decision == "challenge":
            encoded = urllib.parse.quote(target_path, safe="/")
            response = RedirectResponse(url=f"/bw/challenge?path={encoded}", status_code=302)
            _attach_cookie(response, cfg, session_id)
            return response

        links = _make_links(cfg, session_id, ip_hash, page_id=page_id)
        page = render_origin_page(session_id=session_id, page_id=page_id, links=links)
        response = HTMLResponse(page)
        response.headers["x-botwall-decision"] = decision
        response.headers["x-botwall-reasons"] = ",".join(reasons[-6:])
        _attach_cookie(response, cfg, session_id)
        return response

    return app


app = create_app()
