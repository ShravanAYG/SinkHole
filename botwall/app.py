from __future__ import annotations

import json
import os
import random
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
    render_gate_blocked_page,
    render_gate_challenge_page,
    render_origin_page,
    render_recovery_page,
    render_telemetry_page,
    render_bot_caught_page,
    render_test_suite_page,
    render_enhanced_telemetry_page,
    sdk_script,
)
from .models import (
    BeaconEvent,
    CheckResponse,
    DecisionState,
    GateVerifyRequest,
    GateVerifyResponse,
    ProofSubmission,
    RecoveryCompleteRequest,
    RecoveryCompleteResponse,
    RecoveryStartRequest,
    RecoveryStartResponse,
    TelemetryExport,
    TelemetryFingerprint,
    TelemetryImport,
)
from .proof import (
    issue_gate_token,
    issue_pow_challenge,
    issue_proof_token,
    score_gate_environment,
    verify_gate_token,
    verify_pow_solution,
    verify_proof_token,
)
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


def _explicit_scraper_reasons(request: Request) -> list[str]:
    ua = request.headers.get("user-agent", "").lower()
    accept = request.headers.get("accept", "").lower().strip()
    accept_language = request.headers.get("accept-language", "").strip()
    ip_reputation = request.headers.get("x-ip-reputation", "unknown").lower().strip()
    
    # Advanced crawler service detection (Firecrawl, etc.)
    # These services often have subtle signatures even with stealth browsers
    advanced_markers = [
        # Firecrawl specific patterns
        "firecrawl",
        "fire-crawl",
        "fire_crawl",
        # Common scraping services
        "scrape",
        "crawler",
        "spider",
        # Browser automation platforms
        "browserless",
        "puppeteer",
        "playwright",
        "selenium",
        "webdriver",
        "headlesschrome",
        "headless-chrome",
        # Cloud scraping services
        "scrapingbee",
        "scraperapi",
        "zenrows",
        "brightdata",
        "oxylabs",
        "smartproxy",
    ]
    
    # Check for header anomalies that indicate automation
    # Real browsers send detailed Accept headers
    accept_suspicious = accept in {"", "*/*", "text/html", "text/html, */*"}
    
    # Check for missing or generic headers that browsers always send
    dnt = request.headers.get("dnt")  # Do Not Track
    sec_fetch_site = request.headers.get("sec-fetch-site")
    sec_fetch_mode = request.headers.get("sec-fetch-mode")
    
    # Missing Sec-Fetch-* headers is a strong automation signal (modern browsers always send these)
    missing_sec_fetch = not sec_fetch_site and not sec_fetch_mode
    
    # Check encoding preferences - real browsers always accept compressed responses
    accept_encoding = request.headers.get("accept-encoding", "")
    no_compression = not accept_encoding or "identity" in accept_encoding
    
    reasons: list[str] = []
    
    # Check for explicit scraper markers in User-Agent
    for marker in advanced_markers:
        if marker in ua:
            reasons.append(f"pregate:explicit_scraper_ua:{marker}")
            break
    
    # Check for Firecrawl-specific patterns in other headers
    # Firecrawl sometimes uses specific proxy headers
    via_header = request.headers.get("via", "").lower()
    if "firecrawl" in via_header or "crawl" in via_header:
        reasons.append("pregate:via_header_crawler")
    
    # Check for proxy service headers
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        # Multiple IPs in X-Forwarded-For often indicates proxy chaining (common in scraping services)
        if forwarded_for.count(",") >= 2:
            reasons.append("pregate:proxy_chain_detected")
    
    # CF-Connecting-IP or similar CDN headers without proper browser signals
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip and missing_sec_fetch:
        reasons.append("pregate:cdn_ip_without_browser_signals")
    
    # If we've found scraper markers, add supporting evidence
    if reasons:
        if not accept_language:
            reasons.append("pregate:missing_accept_language")
        if accept_suspicious:
            reasons.append("pregate:generic_accept_header")
        if ip_reputation == "bad":
            reasons.append("pregate:ip_reputation_bad")
        if missing_sec_fetch:
            reasons.append("pregate:missing_sec_fetch_headers")
        if no_compression:
            reasons.append("pregate:no_compression_support")
            
    return reasons


def _redirect_explicit_scraper_to_decoy(
    *,
    request: Request,
    settings: Settings,
    store: StoreManager,
    node_id: int,
) -> Response | None:
    reasons = _explicit_scraper_reasons(request)
    if not reasons:
        return None

    session_id = _get_session_id(request, settings)
    client_ip = _client_ip(request)
    ip_hash = hash_client_ip(client_ip, settings.secret_key)
    session = store.store.load_session(session_id, ip_hash)
    if int(session.get("allow_until", 0)) > now_ts():
        return None
    session["score"] = min(float(session.get("score", 0.0)), settings.decoy_threshold - 5.0)
    session.setdefault("reasons", []).extend(reasons)
    _record_decision(session, "decoy", reasons)
    session["last_user_agent"] = request.headers.get("user-agent", "")
    session["updated_at"] = now_ts()
    store.store.save_session(session)

    # Redirect to decoy hellhole for silent data poisoning
    # Use node_id based on session hash for consistency
    node_id_hash = hash(session_id) % settings.decoy_max_nodes
    response = RedirectResponse(
        url=f"/bw/decoy/{node_id_hash}?sid={session_id}&caught=1", 
        status_code=302
    )
    response.headers["x-botwall-decision"] = "decoy"
    response.headers["x-botwall-reasons"] = ",".join(reasons[-6:])
    _attach_cookie(response, settings, session_id)
    return response


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


def _build_operator_telemetry_snapshot(store: StoreManager) -> dict[str, Any]:
    sessions = store.store.list_sessions(limit=200)
    telemetry = store.store.list_telemetry(limit=240)

    gate_passed = 0
    proof_sessions = 0
    decoy_sessions = 0
    allow_sessions = 0
    total_score = 0.0

    for s in sessions:
        total_score += float(s.get("score", 0.0))
        if s.get("gate_passed_at"):
            gate_passed += 1
        if int(s.get("proof_valid", 0)) > 0:
            proof_sessions += 1

        history = s.get("decision_history", [])
        if history:
            latest = str(history[-1].get("decision", ""))
            if latest == "decoy":
                decoy_sessions += 1
            if latest == "allow":
                allow_sessions += 1

    metrics = {
        "sessions_total": len(sessions),
        "gate_passed": gate_passed,
        "proof_sessions": proof_sessions,
        "decoy_sessions": decoy_sessions,
        "allow_sessions": allow_sessions,
        "avg_score": (total_score / len(sessions)) if sessions else 0.0,
    }

    return {
        "store_backend": store.backend,
        "metrics": metrics,
        "sessions": sessions,
        "telemetry": telemetry,
    }


def _build_enhanced_telemetry_snapshot(store: StoreManager) -> dict[str, Any]:
    """Build enhanced telemetry with Phase 2 behavioral data."""
    sessions = store.store.list_sessions(limit=300)
    telemetry = store.store.list_telemetry(limit=300)

    gate_passed = 0
    proof_sessions = 0
    decoy_sessions = 0
    allow_sessions = 0
    total_score = 0.0

    # Phase 2 metrics
    phase2_metrics = {
        "mouse_teleport_detected": 0,
        "instant_scroll_detected": 0,
        "honeypot_interactions": 0,
        "timing_trap_triggers": 0,
        "robotic_typing": 0,
        "sessions_with_phase2_data": 0,
    }

    for s in sessions:
        total_score += float(s.get("score", 0.0))
        if s.get("gate_passed_at"):
            gate_passed += 1
        if int(s.get("proof_valid", 0)) > 0:
            proof_sessions += 1

        history = s.get("decision_history", [])
        if history:
            latest = str(history[-1].get("decision", ""))
            if latest == "decoy":
                decoy_sessions += 1
            if latest == "allow":
                allow_sessions += 1

        # Analyze Phase 2 data
        events = s.get("events", [])
        has_phase2 = False
        for e in events:
            p2 = e.get("phase2_data", {})
            if p2:
                has_phase2 = True
                if p2.get("mouse_teleport_count", 0) > 0:
                    phase2_metrics["mouse_teleport_detected"] += 1
                if p2.get("instant_scroll_detected"):
                    phase2_metrics["instant_scroll_detected"] += 1
                if p2.get("honeypot_hits"):
                    phase2_metrics["honeypot_interactions"] += len(p2["honeypot_hits"])
                if p2.get("timing_traps"):
                    phase2_metrics["timing_trap_triggers"] += sum(
                        1 for t in p2["timing_traps"] if t.get("triggered")
                    )
                if p2.get("keystroke_dwell_cv", 0) < 0.05 and p2.get("keystrokes"):
                    phase2_metrics["robotic_typing"] += 1

        if has_phase2:
            phase2_metrics["sessions_with_phase2_data"] += 1

    metrics = {
        "sessions_total": len(sessions),
        "gate_passed": gate_passed,
        "proof_sessions": proof_sessions,
        "decoy_sessions": decoy_sessions,
        "allow_sessions": allow_sessions,
        "avg_score": (total_score / len(sessions)) if sessions else 0.0,
        "phase2": phase2_metrics,
    }

    return {
        "store_backend": store.backend,
        "metrics": metrics,
        "sessions": sessions,
        "telemetry": telemetry,
        "generated_at": now_ts(),
    }


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


def _check_gate_cookie(
    request: Request,
    cfg: Settings,
    ip_hash: str,
) -> tuple[bool, dict | None]:
    """
    Verify the Stage 1 gate cookie.
    Returns (valid: bool, payload: dict | None).
    If valid=False, the caller must redirect to /bw/gate/challenge.
    """
    if not cfg.gate_cookie:
        return True, None  # gate disabled in config
    raw_token = request.cookies.get(cfg.gate_cookie)
    if not raw_token:
        return False, None
    try:
        payload = verify_gate_token(
            token=raw_token,
            secret=cfg.secret_key,
            current_ip_hash=ip_hash,
        )
        return True, payload
    except (TokenError, Exception):
        return False, None



def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(title="Botwall API", version="0.1.0")
    cfg = settings or load_settings()
    store = init_store(cfg.redis_enabled, cfg.redis_url)
    peer_secrets = parse_peer_secrets(cfg.peer_secrets_raw or os.getenv("BOTWALL_PEER_SECRETS"))

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "store": store.backend}

    # ── Stage 1: Entry Gate ────────────────────────────────────────────────────

    @app.get("/bw/gate/challenge")
    async def bw_gate_challenge(request: Request, path: str = "/") -> HTMLResponse:
        """
        Serve the PoW challenge page.
        The page JS auto-starts solving; no user click needed.
        Submit solution to /bw/gate/verify → gate cookie is set → redirect to `path`.
        """
        session_id = _get_session_id(request, cfg)
        client_ip  = _client_ip(request)
        ip_hash    = hash_client_ip(client_ip, cfg.secret_key)
        ip_rep     = request.headers.get("x-ip-reputation", "unknown")
        session    = store.store.load_session(session_id, ip_hash)
        failures   = int(session.get("gate_failures", 0))
        difficulty = (
            cfg.pow_elevated_difficulty
            if ip_rep == "bad" or failures >= 2
            else cfg.pow_default_difficulty
        )
        pow_challenge = issue_pow_challenge(
            secret=cfg.secret_key,
            session_id=session_id,
            ip_hash=ip_hash,
            difficulty=difficulty,
            ttl_seconds=cfg.pow_max_solve_seconds + 5,
        )
        page = render_gate_challenge_page(
            session_id=session_id,
            challenge_token=pow_challenge.challenge_token,
            challenge=pow_challenge.challenge,
            difficulty=difficulty,
            return_to=path,
        )
        response = HTMLResponse(page)
        response.set_cookie(key=cfg.session_cookie, value=session_id, httponly=True, samesite="lax", path="/")
        return response

    @app.post("/bw/gate/verify", response_model=GateVerifyResponse)
    async def bw_gate_verify(payload: GateVerifyRequest, request: Request) -> Response:
        """
        Validate PoW solution and browser env report.
        Success → issues bw_gate cookie, returns {next_path} JSON for JS redirect.
        Hard-fail (webdriver detected) → 403 HTML with elevated re-challenge.
        """
        client_ip  = _client_ip(request)
        ip_hash    = hash_client_ip(client_ip, cfg.secret_key)
        now        = now_ts()
        session_id = payload.session_id
        session    = store.store.load_session(session_id, ip_hash)

        # 1. PoW verification
        try:
            pow_result = verify_pow_solution(
                challenge_token=payload.challenge_token,
                secret=cfg.secret_key,
                session_id=session_id,
                ip_hash=ip_hash,
                challenge=payload.challenge,
                nonce=payload.nonce,
                submitted_hash=payload.hash,
                solve_ms=int(payload.solve_ms),
                max_solve_seconds=cfg.pow_max_solve_seconds,
            )
        except TokenError as exc:
            session["gate_failures"] = int(session.get("gate_failures", 0)) + 1
            store.store.save_session(session)
            raise HTTPException(status_code=400, detail=f"PoW failed: {exc}") from exc

        # Anti-replay: one gate token per challenge
        if not store.store.mark_once("gate_jti", pow_result.challenge_id, cfg.gate_ttl_seconds):
            raise HTTPException(status_code=409, detail="challenge replay detected")

        # 2. Environment scoring
        env_dict = payload.env.model_dump()
        ua = request.headers.get("user-agent", "")
        env_score, env_reasons, hard_fail = score_gate_environment(env_dict, request_user_agent=ua)

        # 3. Hard fail: redirect to decoy hellhole immediately (silent poisoning)
        if hard_fail:
            session["gate_failures"] = int(session.get("gate_failures", 0)) + 1
            session["score"] = min(float(session.get("score", 0.0)), cfg.decoy_threshold - 10.0)
            session.setdefault("reasons", []).extend(env_reasons)
            _record_decision(session, "decoy", env_reasons)
            store.store.save_session(session)
            
            # Redirect to decoy hellhole for silent data poisoning
            # Use node_id based on session hash for consistency
            node_id = hash(session_id) % cfg.decoy_max_nodes
            response = RedirectResponse(
                url=f"/bw/decoy/{node_id}?sid={session_id}&caught=1", 
                status_code=302
            )
            response.headers["x-botwall-decision"] = "decoy"
            response.headers["x-botwall-reasons"] = ",".join(env_reasons[-6:])
            _attach_cookie(response, cfg, session_id)
            return response
        
        # 3b. Elevated suspicion: also block with elevated challenge
        if env_score <= -50:
            session["gate_failures"] = int(session.get("gate_failures", 0)) + 1
            store.store.save_session(session)
            elevated = issue_pow_challenge(
                secret=cfg.secret_key,
                session_id=session_id,
                ip_hash=ip_hash,
                difficulty=cfg.pow_elevated_difficulty,
                ttl_seconds=cfg.pow_max_solve_seconds + 5,
            )
            blocked_page = render_gate_blocked_page(
                session_id=session_id,
                challenge_token=elevated.challenge_token,
                challenge=elevated.challenge,
                difficulty=cfg.pow_elevated_difficulty,
                return_to=payload.return_to,
                reasons=env_reasons,
            )
            return HTMLResponse(content=blocked_page, status_code=403)

        # 4. Issue gate token
        gate_token = issue_gate_token(
            secret=cfg.secret_key,
            session_id=session_id,
            ip_hash=ip_hash,
            solved_difficulty=pow_result.difficulty,
            env_score=env_score,
            ttl_seconds=cfg.gate_ttl_seconds,
        )
        session["gate_passed_at"]  = now
        session["gate_env_score"]  = env_score
        session["gate_difficulty"] = pow_result.difficulty
        session["gate_failures"]   = 0
        store.store.save_session(session)

        resp_data = GateVerifyResponse(
            session_id=session_id,
            decision="allow",
            env_score=env_score,
            next_path=payload.return_to or "/",
            gate_expires_at=now + cfg.gate_ttl_seconds,
            reasons=env_reasons,
        )
        response = JSONResponse(resp_data.model_dump(mode="json"))
        response.set_cookie(key=cfg.gate_cookie, value=gate_token, httponly=True,
                            samesite="lax", max_age=cfg.gate_ttl_seconds, path="/")
        response.set_cookie(key=cfg.session_cookie, value=session_id, httponly=True,
                            samesite="lax", path="/")
        return response

    @app.get("/bw/gate/check")
    async def bw_gate_check(request: Request) -> JSONResponse:
        """
        Integration helper for reverse-proxies:
        validates the current gate cookie against client IP binding.
        """
        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        ok, payload = _check_gate_cookie(request, cfg, ip_hash)
        if not ok:
            return JSONResponse({"ok": False, "reason": "missing_or_invalid_gate"}, status_code=401)
        return JSONResponse(
            {
                "ok": True,
                "session_id": payload.get("sid") if payload else None,
                "expires_at": payload.get("exp") if payload else None,
                "difficulty": payload.get("diff") if payload else None,
                "env_score": payload.get("env") if payload else None,
            }
        )

    # ── Stage 2: check + scoring routes ───────────────────────────────────────

    @app.get("/bw/sdk.js")
    def bw_sdk_js() -> Response:
        return Response(content=sdk_script(), media_type="application/javascript")

    @app.get("/bw/check", response_model=CheckResponse)
    async def bw_check(request: Request) -> JSONResponse:
        fallback = request.query_params.get("path", "/")
        target_path = _canonical_target_path(request, fallback)
        pre_gate_reasons = _explicit_scraper_reasons(request)
        if pre_gate_reasons:
            session_id = _get_session_id(request, cfg)
            client_ip = _client_ip(request)
            ip_hash = hash_client_ip(client_ip, cfg.secret_key)
            session = store.store.load_session(session_id, ip_hash)
            session["score"] = min(float(session.get("score", 0.0)), cfg.decoy_threshold - 5.0)
            session.setdefault("reasons", []).extend(pre_gate_reasons)
            _record_decision(session, "decoy", pre_gate_reasons)
            store.store.save_session(session)
            payload = CheckResponse(
                session_id=session_id,
                decision="decoy",
                score=float(session.get("score", 0.0)),
                reasons=pre_gate_reasons,
            )
            response = JSONResponse(payload.model_dump(mode="json"))
            response.headers["x-botwall-decision"] = "decoy"
            response.headers["x-botwall-score"] = f"{float(session.get('score', 0.0)):.2f}"
            response.headers["x-botwall-reasons"] = ",".join(pre_gate_reasons[-6:])
            _attach_cookie(response, cfg, session_id)
            return response
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
        response = HTMLResponse(page)
        response.headers["x-botwall-decision"] = "challenge"
        _attach_cookie(response, cfg, session_id)
        return response

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
        node = build_node(
            session_id,
            node_id % cfg.decoy_max_nodes,
            max_nodes=cfg.decoy_max_nodes,
            min_links=cfg.decoy_min_links,
            max_links=cfg.decoy_max_links,
        )
        response = HTMLResponse(render_decoy_page(node=node, session_id=session_id))
        response.headers["x-botwall-decision"] = "decoy"
        response.headers["x-robots-tag"] = "noindex, noarchive, nofollow"
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/bw/bot-caught")
    async def bw_bot_caught(request: Request) -> HTMLResponse:
        """Bot/scraper detection page - shows 'YOU LOWDE BOT' message."""
        session_id = request.query_params.get("sid") or _get_session_id(request, cfg)
        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        session = store.store.load_session(session_id, ip_hash)

        # Get the reasons why this was flagged as a bot
        reasons = session.get("reasons", [])
        user_agent = session.get("last_user_agent", request.headers.get("user-agent", ""))

        response = HTMLResponse(render_bot_caught_page(
            session_id=session_id,
            user_agent=user_agent,
            reasons=reasons[-6:] if reasons else None
        ))
        response.headers["x-botwall-decision"] = "bot_caught"
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
            instruction="Complete the mini-game on /bw/recovery; score and timing will be submitted automatically.",
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
        if payload.duration_ms < 2500 or payload.duration_ms > 60000:
            raise HTTPException(status_code=400, detail="invalid game duration")
        if payload.hits < 8:
            raise HTTPException(status_code=400, detail="insufficient game hits")
        if payload.game_score < 35:
            raise HTTPException(status_code=400, detail="insufficient game score")
        attempts = max(1, payload.hits + payload.misses)
        accuracy = payload.hits / attempts
        if accuracy < 0.5:
            raise HTTPException(status_code=400, detail="insufficient game accuracy")

        jti = str(parsed.get("jti"))
        if not store.store.mark_once("recovery_jti", jti, 300):
            raise HTTPException(status_code=409, detail="recovery token replay detected")

        session["allow_until"] = now + cfg.recovery_allow_seconds
        session["score"] = float(session.get("score", 0.0) + 25.0)
        session.setdefault("reasons", []).append("recovery:completed")
        session["recovery_game"] = {
            "score": payload.game_score,
            "hits": payload.hits,
            "misses": payload.misses,
            "duration_ms": payload.duration_ms,
            "accuracy": round(accuracy, 3),
        }
        store.store.save_session(session)

        result = RecoveryCompleteResponse(decision="allow", allow_until=int(session["allow_until"]))
        response = JSONResponse(result.model_dump(mode="json"), status_code=202)
        gate_token = issue_gate_token(
            secret=cfg.secret_key,
            session_id=session_id,
            ip_hash=ip_hash,
            solved_difficulty=int(session.get("gate_difficulty", cfg.pow_default_difficulty)),
            env_score=int(session.get("gate_env_score", 0)),
            ttl_seconds=cfg.gate_ttl_seconds,
        )
        response.set_cookie(
            key=cfg.gate_cookie,
            value=gate_token,
            httponly=True,
            samesite="lax",
            max_age=cfg.gate_ttl_seconds,
            path="/",
        )
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
        body = _build_operator_telemetry_snapshot(store)
        return HTMLResponse(render_dashboard(body))

    @app.get("/bw/telemetry")
    async def bw_telemetry_console() -> HTMLResponse:
        body = _build_operator_telemetry_snapshot(store)
        return HTMLResponse(render_telemetry_page(body))

    @app.get("/bw/telemetry.json")
    async def bw_telemetry_json() -> JSONResponse:
        return JSONResponse(_build_operator_telemetry_snapshot(store))

    @app.get("/__dashboard")
    async def bw_dashboard_json() -> JSONResponse:
        return JSONResponse(_build_operator_telemetry_snapshot(store))

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
        pre_gate = _redirect_explicit_scraper_to_decoy(request=request, settings=cfg, store=store, node_id=0)
        if pre_gate is not None:
            return pre_gate

        client_ip = _client_ip(request)
        ip_hash   = hash_client_ip(client_ip, cfg.secret_key)
        gate_ok, _ = _check_gate_cookie(request, cfg, ip_hash)
        if not gate_ok:
            return RedirectResponse(url="/bw/gate/challenge?path=/", status_code=302)

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
        pre_gate = _redirect_explicit_scraper_to_decoy(request=request, settings=cfg, store=store, node_id=page_id)
        if pre_gate is not None:
            return pre_gate

        client_ip   = _client_ip(request)
        ip_hash_pre = hash_client_ip(client_ip, cfg.secret_key)
        gate_ok, _  = _check_gate_cookie(request, cfg, ip_hash_pre)
        if not gate_ok:
            encoded = urllib.parse.quote(target_path, safe="/")
            return RedirectResponse(url=f"/bw/gate/challenge?path={encoded}", status_code=302)

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

    # ── Test Suite & Development Routes ────────────────────────────────────────

    @app.get("/bw/test-suite")
    async def bw_test_suite(request: Request) -> HTMLResponse:
        """Test suite dashboard for running bot/human simulations."""
        session_id = _get_session_id(request, cfg)
        suite = create_demo_test_suite()
        website = suite.websites[0] if suite.websites else None
        scenarios = suite.generate_default_scenarios()
        response = HTMLResponse(render_test_suite_page(
            session_id=session_id,
            website=website,
            scenarios=scenarios,
        ))
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/bw/test-suite/config")
    async def bw_test_suite_config() -> JSONResponse:
        """Get default test suite configuration."""
        config = TestWebsiteConfig(
            name="Demo Test Site",
            pages=7,
            has_forms=True,
            has_search=True,
            protection_level="maximum",
            include_honeypots=True,
            include_timing_traps=True,
        )
        return JSONResponse(config.__dict__)

    @app.post("/bw/test-suite/build")
    async def bw_test_suite_build(request: Request) -> JSONResponse:
        """Build a test website with specified configuration."""
        body = await request.body()
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            data = {}

        config = TestWebsiteConfig(
            name=data.get("name", "Test Site"),
            pages=data.get("pages", 5),
            has_forms=data.get("has_forms", True),
            has_search=data.get("has_search", True),
            protection_level=data.get("protection_level", "standard"),
            include_honeypots=data.get("include_honeypots", True),
            include_timing_traps=data.get("include_timing_traps", True),
        )

        builder = TestWebsiteBuilder(config)
        website = builder.build()

        return JSONResponse({
            "ok": True,
            "website": website,
        })

    @app.post("/bw/test-suite/simulate")
    async def bw_test_suite_simulate(request: Request) -> JSONResponse:
        """Run a behavior simulation and return results."""
        body = await request.body()
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            data = {}

        behavior_type = data.get("behavior_type", "human")
        simulator = BehaviorSimulator()

        # Generate simulated data based on behavior type
        results = {
            "behavior_type": behavior_type,
            "mouse_path": [],
            "keystrokes": [],
            "scroll_events": [],
            "dwell_ms": 0,
        }

        if behavior_type == "human":
            # Human-like mouse path
            start = (100.0, 100.0)
            end = (500.0, 400.0)
            results["mouse_path"] = [
                {"x": p["x"], "y": p["y"], "t": p["t"]}
                for p in simulator.simulate_human_mouse_path(start, end)
            ]
            # Human-like keystrokes
            text = "Hello, this is a test message."
            results["keystrokes"] = [
                {"char": k["char"], "press_time": k["press_time"], "release_time": k["release_time"], "dwell": k["dwell"]}
                for k in simulator.simulate_human_keystrokes(text)
            ]
            # Human-like scroll
            results["scroll_events"] = [
                {"y": s["y"], "t": s["t"], "delta": s["delta"]}
                for s in simulator.simulate_human_scroll()
            ]
            results["dwell_ms"] = random.randint(3000, 8000)

        elif behavior_type == "bot_basic":
            # Bot-like mouse path
            start = (100.0, 100.0)
            end = (500.0, 400.0)
            results["mouse_path"] = [
                {"x": p["x"], "y": p["y"], "t": p["t"]}
                for p in simulator.simulate_bot_mouse_path(start, end)
            ]
            # Bot-like keystrokes
            text = "Hello bot message here."
            results["keystrokes"] = [
                {"char": k["char"], "press_time": k["press_time"], "release_time": k["release_time"], "dwell": k["dwell"]}
                for k in simulator.simulate_bot_keystrokes(text)
            ]
            # Bot-like scroll (instant)
            results["scroll_events"] = [
                {"y": s["y"], "t": s["t"], "delta": s["delta"]}
                for s in simulator.simulate_bot_scroll()
            ]
            results["dwell_ms"] = random.randint(200, 500)

        return JSONResponse({
            "ok": True,
            "simulation": results,
        })

    @app.get("/bw/test-suite/behavior-types")
    async def bw_test_suite_behavior_types() -> JSONResponse:
        """List available behavior simulation types."""
        return JSONResponse({
            "types": [
                {
                    "id": "human",
                    "name": "Human User",
                    "description": "Natural mouse curves, variable keystroke timing, realistic scroll patterns",
                },
                {
                    "id": "bot_basic",
                    "name": "Basic Bot",
                    "description": "Straight mouse lines, instant keystrokes, instant scroll jumps",
                },
                {
                    "id": "bot_advanced",
                    "name": "Advanced Bot",
                    "description": "Simulated mouse movement with constant velocity",
                },
            ]
        })

    # ── Enhanced Telemetry Routes ────────────────────────────────────────────

    @app.get("/bw/telemetry/v2")
    async def bw_telemetry_v2(request: Request) -> HTMLResponse:
        """Enhanced telemetry console with Phase 2 behavioral data."""
        session_id = _get_session_id(request, cfg)
        snapshot = _build_enhanced_telemetry_snapshot(store)
        response = HTMLResponse(render_enhanced_telemetry_page(snapshot))
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/bw/telemetry/sessions/{session_id}/behavioral")
    async def bw_session_behavioral(session_id: str) -> JSONResponse:
        """Get detailed behavioral analysis for a specific session."""
        sessions = store.store.list_sessions(limit=500)
        session = next((s for s in sessions if s.get("session_id") == session_id), None)

        if not session:
            raise HTTPException(status_code=404, detail="session not found")

        # Extract Phase 2 data from events
        phase2_analysis = {
            "mouse_patterns": [],
            "keystroke_dynamics": [],
            "scroll_patterns": [],
            "engagement_metrics": [],
            "trap_interactions": [],
            "risk_flags": [],
        }

        events = session.get("events", [])
        for event in events:
            phase2_data = event.get("phase2_data")
            if phase2_data:
                if phase2_data.get("mouse_teleport_count", 0) > 0:
                    phase2_analysis["risk_flags"].append("MOUSE_TELEPORT")
                if phase2_data.get("instant_scroll_detected"):
                    phase2_analysis["risk_flags"].append("INSTANT_SCROLL")
                if phase2_data.get("likely_copy_paste"):
                    phase2_analysis["risk_flags"].append("COPY_PASTE")

        return JSONResponse({
            "session_id": session_id,
            "score": session.get("score", 0.0),
            "events_count": len(events),
            "phase2_analysis": phase2_analysis,
        })

    @app.get("/bw/telemetry/attack-patterns")
    async def bw_attack_patterns() -> JSONResponse:
        """Detect and report attack patterns across sessions."""
        sessions = store.store.list_sessions(limit=500)
        telemetry = store.store.list_telemetry(limit=200)

        patterns = {
            "mouse_teleport_bots": 0,
            "instant_scrollers": 0,
            "honeypot_hits": 0,
            "timing_trap_triggers": 0,
            "robotic_typing": 0,
            "suspicious_fingerprints": 0,
        }

        for s in sessions:
            events = s.get("events", [])
            for e in events:
                p2 = e.get("phase2_data", {})
                if p2.get("mouse_teleport_count", 0) > 0:
                    patterns["mouse_teleport_bots"] += 1
                if p2.get("instant_scroll_detected"):
                    patterns["instant_scrollers"] += 1
                if p2.get("honeypot_hits"):
                    patterns["honeypot_hits"] += len(p2["honeypot_hits"])

        for t in telemetry:
            if t.get("suspicion", 0) > 20:
                patterns["suspicious_fingerprints"] += 1

        return JSONResponse({
            "patterns": patterns,
            "total_sessions_analyzed": len(sessions),
            "high_risk_sessions": sum(1 for s in sessions if s.get("score", 0) < -50),
        })

    @app.get("/bw/stage2")
    async def bw_stage2_dashboard(request: Request) -> HTMLResponse:
        """Comprehensive Stage 2 behavioral analysis dashboard."""
        session_id = _get_session_id(request, cfg)
        snapshot = _build_enhanced_telemetry_snapshot(store)
        # Add phase2_analysis for the dashboard
        snapshot["phase2_analysis"] = {}
        response = HTMLResponse(render_enhanced_telemetry_page(snapshot))
        _attach_cookie(response, cfg, session_id)
        return response

    return app


app = create_app()
