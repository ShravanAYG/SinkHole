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
from .embeddings_content import generate_fake_decoy_content, FakeContentConfig
from .embeddings_renderer import render_embeddings_decoy_page
from .enhanced_decoy import build_embeddings_node, build_hybrid_node, EnhancedDecoyNode
from .extrapolation_engine import extrapolate_poisoned_content, ExtrapolationConfig
from .extrapolation_renderer import render_extrapolated_decoy_page, render_regeneration_status_page
from .regeneration_scheduler import get_scheduler, get_decoy_node, get_scheduler_metrics
from .html import (
    render_about_page,
    render_behavioral_challenge_page,
    render_blog_page,
    render_blog_post_page,
    render_challenge_page,
    render_contact_page,
    render_dashboard,
    render_decoy_page,
    render_gate_blocked_page,
    render_gate_challenge_page,
    render_origin_page,
    render_products_page,
    render_recovery_page,
    render_search_page,
    render_telemetry_page,
    render_bot_caught_page,
    render_test_suite_page,
    render_enhanced_telemetry_page,
    sdk_script,
)
from .js_verify_page import render_js_verify_page
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


def _record_decision(
    session: dict[str, Any],
    decision: str,
    reasons: list[str],
    request: Request | None = None,
    settings: Settings | None = None
) -> None:
    history = session.setdefault("decision_history", [])
    history.append({"decision": decision, "reasons": reasons, "at": now_ts()})
    session["decision_history"] = history[-30:]
    
    if request and settings:
        session["client_ip"] = _client_ip(request)
        # Store requested path (excluding our internal endpoints if possible)
        path = request.url.path
        if not path.startswith("/bw/"):
            session["last_path"] = path


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
    _record_decision(session, "decoy", reasons, request, settings)
    session["last_user_agent"] = request.headers.get("user-agent", "")
    session["updated_at"] = now_ts()
    store.store.save_session(session)

    # Redirect to decoy hellhole for silent data poisoning
    # Use node_id based on session hash for consistency
    node_id_hash = hash(session_id) % settings.decoy_max_nodes
    response = RedirectResponse(
        url=f"/content/archive/{node_id_hash}?ref={session_id[:8]}", 
        status_code=302
    )
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
    _record_decision(session, decision, reasons + req_outcome.reasons, request, settings)
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
    
    # Initialize background regeneration scheduler (zero-latency decoy content refresh)
    regeneration_scheduler = get_scheduler(
        interval_seconds=180.0,  # 3 minutes
        num_decoy_nodes=cfg.decoy_max_nodes,
    )
    
    # Start scheduler when the app is ready (event loop is running)
    @app.on_event("startup")
    async def _start_regeneration():
        import asyncio
        asyncio.create_task(regeneration_scheduler.start())

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "store": store.backend}

    # ── Stage 1: Entry Gate ────────────────────────────────────────────────────

    @app.get("/bw/gate/challenge")
    async def bw_gate_challenge(request: Request, path: str = "/") -> Response:
        """
        Simple bot detection using hardcoded rules.
        Bots → redirect to decoy immediately.
        Humans → issue gate cookie and redirect to content (no CAPTCHA).
        """
        import re
        
        session_id = _get_session_id(request, cfg)
        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        ua = request.headers.get("user-agent", "")
        
        # Simple hardcoded rules
        BOT_UA_KEYWORDS = ["bot", "crawler", "spider", "Claude-User", "Googlebot", "firecrawl", "crawl4ai", "scrapy", "crawl"]
        HEADLESS_MARKERS = ["headless", "selenium", "webdriver", "puppeteer", "playwright", "cdp_", "automation"]
        DATACENTER_PREFIXES = ["34.", "195.64.", "113.30.", "110.225."]
        
        # Classification
        is_bot = False
        reason = ""
        
        # Check if it's a REAL browser first (legitimate Firefox/Chrome/Safari/Edge)
        # Real browsers have version patterns that bots rarely fake correctly
        ua_lower = ua.lower()
        is_real_browser = (
            # Firefox with realistic version (rv:XXX.0 pattern)
            ("firefox/" in ua_lower and "rv:" in ua_lower and "gecko/" in ua_lower)
            or
            # Chrome with realistic version (Chrome/XXX.0.0.0 pattern, 100+)
            (re.search(r'Chrome/\d{3,4}\.0\.\d+\.\d+', ua) is not None)
            or
            # Safari
            ("safari/" in ua_lower and "version/" in ua_lower)
            or
            # Edge
            ("edg/" in ua_lower and re.search(r'Edg/\d{3}', ua) is not None)
        )
        
        # Check for headless/automation markers (strong bot signal)
        has_headless = any(marker in ua_lower for marker in HEADLESS_MARKERS)
        
        # Check UA keywords for obvious bots
        if any(kw.lower() in ua_lower for kw in BOT_UA_KEYWORDS):
            is_bot = True
            reason = "bot_ua"
        # Check headless/automation markers
        elif has_headless:
            is_bot = True
            reason = "headless_marker"
        # Check ancient Chrome versions (bots often use old Chrome strings like Chrome/14)
        # Firecrawler uses ancient Chrome versions
        elif re.search(r'Chrome/\d{1,2}\.0', ua) and not re.search(r'Chrome/\d{3,4}\.0', ua):
            is_bot = True
            reason = "ancient_chrome"
        # Check datacenter IPs BUT allow real browsers through
        elif any(client_ip.startswith(p) for p in DATACENTER_PREFIXES):
            if is_real_browser and not has_headless:
                # Real browser from datacenter = allow through (could be VPN/proxy)
                is_bot = False
            else:
                # Unknown client from datacenter = likely bot
                is_bot = True
                reason = "datacenter_ip+unknown_client"
        
        # Log classification
        import logging
        logger = logging.getLogger("sinkhole.gate")
        client_type = "bot" if is_bot else "human"
        real_browser_flag = "real_browser" if is_real_browser else "unknown_client"
        logger.warning(f"GATE_CHECK ip={client_ip} type={client_type} browser={real_browser_flag} reason={reason} ua={ua[:60]!r}")
        
        # BOT DETECTED → redirect to decoy immediately
        if is_bot:
            session = store.store.load_session(session_id, ip_hash)
            session["gate_failures"] = int(session.get("gate_failures", 0)) + 1
            session["score"] = min(float(session.get("score", 0.0)), cfg.decoy_threshold - 10.0)
            session.setdefault("reasons", []).append(f"gate:{reason}")
            session["client_classification"] = client_type
            session["detected_ua"] = ua[:200]
            _record_decision(session, "decoy", [reason], request, cfg)
            store.store.save_session(session)
            
            node_id = hash(session_id) % cfg.decoy_max_nodes
            logger.warning(f"GATE_BLOCK ip={client_ip} reason={reason} redirect=/content/archive/{node_id}")
            return RedirectResponse(
                url=f"/content/archive/{node_id}?ref={session_id[:8]}",
                status_code=302
            )
        
        # HUMAN → serve JS verification page with PoW challenge
        logger.warning(f"GATE_JS_VERIFY ip={client_ip} path={path}")
        pow_challenge = issue_pow_challenge(
            secret=cfg.secret_key,
            session_id=session_id,
            ip_hash=ip_hash,
            difficulty=cfg.pow_default_difficulty,
            ttl_seconds=120,
        )
        page = render_js_verify_page(
            session_id=session_id,
            path=path,
            challenge=pow_challenge.challenge,
            challenge_token=pow_challenge.challenge_token,
            difficulty=pow_challenge.difficulty,
        )
        response = HTMLResponse(page)
        response.set_cookie(key=cfg.session_cookie, value=session_id, httponly=True, samesite="lax", path="/")
        return response

    @app.post("/bw/js-verify")
    async def bw_js_verify(request: Request) -> JSONResponse:
        """
        Verify PoW solution + client-side JS browser checks.
        Validates: signature, timing, one-time use, PoW hash, env signals.
        If anything fails → redirect to decoy.
        """
        import logging
        logger = logging.getLogger("sinkhole.gate")

        body = await request.body()
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
        
        session_id = data.get("session_id")
        if not session_id:
            return JSONResponse({"ok": False, "error": "Missing session_id"}, status_code=400)
        
        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        session = store.store.load_session(session_id, ip_hash)

        def _reject(reasons: list[str], error_msg: str = "Verification failed") -> JSONResponse:
            session["gate_failures"] = int(session.get("gate_failures", 0)) + 1
            session["score"] = min(float(session.get("score", 0.0)), cfg.decoy_threshold - 10.0)
            session.setdefault("reasons", []).extend(reasons)
            session["js_verification_failed"] = True
            _record_decision(session, "decoy", reasons, request, cfg)
            store.store.save_session(session)
            node_id = hash(session_id) % cfg.decoy_max_nodes
            logger.warning(f"JS_VERIFY_BLOCK ip={client_ip} reasons={reasons}")
            return JSONResponse({
                "ok": False,
                "decision": "decoy",
                "error": error_msg,
                "next_path": f"/content/archive/{node_id}?ref={session_id[:8]}",
            }, status_code=403)

        # ── Step 1: Validate PoW solution ──────────────────────────────────
        challenge_token = data.get("challenge_token", "")
        challenge = data.get("challenge", "")
        nonce = data.get("nonce", "")
        submitted_hash = data.get("hash", "")
        solve_ms = int(data.get("solve_ms", 0))

        if not challenge_token or not challenge or not nonce or not submitted_hash:
            return _reject(["pow:missing_fields"], "Missing proof-of-work data")

        try:
            pow_result = verify_pow_solution(
                challenge_token=challenge_token,
                secret=cfg.secret_key,
                session_id=session_id,
                ip_hash=ip_hash,
                challenge=challenge,
                nonce=nonce,
                submitted_hash=submitted_hash,
                solve_ms=solve_ms,
                max_solve_seconds=cfg.pow_max_solve_seconds,
            )
        except TokenError as exc:
            return _reject([f"pow:invalid:{exc}"], "Invalid proof-of-work")

        # One-time use: prevent replay
        if not store.store.mark_once("gate_pow_jti", pow_result.challenge_id, 300):
            return _reject(["pow:replay_detected"], "Challenge already used")

        elapsed = pow_result.solved_at - pow_result.issued_at
        logger.warning(f"JS_VERIFY_POW_OK ip={client_ip} sid={session_id[:8]} difficulty={pow_result.difficulty} solve_ms={solve_ms} elapsed={elapsed}s")

        # ── Step 2: Validate environment checks ───────────────────────────
        checks = data.get("checks", {})
        passed = int(checks.get("passed", 0))
        failed = int(checks.get("failed", 0))
        details = checks.get("details", [])

        logger.warning(f"JS_VERIFY ip={client_ip} passed={passed} failed={failed} details={details}")

        is_bot = False
        bot_reasons: list[str] = []

        # Strong automation signals
        for sig in details:
            if sig in ("webdriver_detected", "automation_vars", "stealth_proxy"):
                is_bot = True
                bot_reasons.append(f"js:{sig}")
            elif sig.startswith("software_renderer:"):
                is_bot = True
                bot_reasons.append(f"js:{sig}")

        if failed >= 3:
            is_bot = True
            bot_reasons.append(f"js:checks_failed:{failed}")

        if passed < 7:
            is_bot = True
            bot_reasons.append(f"js:insufficient_passed:{passed}")

        if is_bot:
            session["js_check_details"] = details
            return _reject(bot_reasons, "Browser automation detected")

        # ── Step 3: All checks passed → issue gate cookie ─────────────────
        gate_token = issue_gate_token(
            secret=cfg.secret_key,
            session_id=session_id,
            ip_hash=ip_hash,
            solved_difficulty=pow_result.difficulty,
            env_score=0,
            ttl_seconds=cfg.gate_ttl_seconds,
        )

        session["gate_passed_at"] = now_ts()
        session["gate_env_score"] = 0
        session["gate_failures"] = 0
        session["js_verification_passed"] = True
        session["js_check_details"] = details
        session["pow_solve_ms"] = solve_ms
        _record_decision(session, "allow", ["js_verification:passed", f"pow:solved:d{pow_result.difficulty}"], request, cfg)
        store.store.save_session(session)

        logger.warning(f"JS_VERIFY_ALLOW ip={client_ip}")

        response = JSONResponse({
            "ok": True,
            "decision": "allow",
            "next_path": data.get("return_path", "/"),
        })
        response.set_cookie(
            key=cfg.gate_cookie,
            value=gate_token,
            httponly=True,
            samesite="lax",
            max_age=cfg.gate_ttl_seconds,
            path="/",
        )
        return response

    @app.post("/bw/gate/verify")
    async def bw_gate_verify(request: Request) -> Response:
        """
        Verify behavioral CAPTCHA submission.
        Analyzes mouse patterns, keystroke dynamics, and timing.
        Bot detected → redirect to decoy. Human → gate cookie issued.
        """
        body = await request.body()
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="invalid JSON")
        
        session_id = data.get("session_id")
        behavioral_data = data.get("behavioral_data", {})
        return_to = data.get("return_to", "/")
        env_report = data.get("env", {})
        
        if not session_id:
            raise HTTPException(status_code=400, detail="missing session_id")
        
        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        session = store.store.load_session(session_id, ip_hash)
        now = now_ts()
        
        # First: check environment signals for hard-fail automation markers
        env_dict = env_report if isinstance(env_report, dict) else {}
        ua = request.headers.get("user-agent", "")
        env_score, env_reasons, hard_fail = score_gate_environment(env_dict, request_user_agent=ua)
        
        # Hard fail: automation detected in env report → immediate decoy
        if hard_fail:
            session["gate_failures"] = int(session.get("gate_failures", 0)) + 1
            session["score"] = min(float(session.get("score", 0.0)), cfg.decoy_threshold - 10.0)
            session.setdefault("reasons", []).extend(env_reasons)
            _record_decision(session, "decoy", env_reasons, request, cfg)
            store.store.save_session(session)
            
            node_id = hash(session_id) % cfg.decoy_max_nodes
            return JSONResponse({
                "decision": "decoy",
                "next_path": f"/content/archive/{node_id}?ref={session_id[:8]}",
                "reasons": env_reasons,
            }, status_code=403)
        
        # Score behavioral patterns
        from .behavioral import (
            score_advanced_mouse_patterns,
            score_advanced_keystrokes,
        )
        
        total_score = float(env_score)  # Start with env score
        all_reasons = list(env_reasons)
        all_risks: list[str] = []
        
        # Score mouse patterns
        mouse_data = behavioral_data.get("mouse_data", {})
        if mouse_data:
            mouse_result = score_advanced_mouse_patterns(mouse_data)
            total_score += mouse_result.delta
            all_reasons.extend(mouse_result.reasons)
            all_risks.extend(mouse_result.risk_flags)
        
        # Score keystrokes
        keystrokes = behavioral_data.get("keystrokes", [])
        if keystrokes:
            keystroke_result = score_advanced_keystrokes(keystrokes)
            total_score += keystroke_result.delta
            all_reasons.extend(keystroke_result.reasons)
            all_risks.extend(keystroke_result.risk_flags)
        
        # Check timing anomalies
        timing = behavioral_data.get("timing", {})
        total_duration = timing.get("total_duration_ms", 0)
        
        # Too fast = bot (impossible for human to complete)
        if total_duration > 0 and total_duration < 2000:
            total_score -= 30
            all_reasons.append("captcha:impossible_speed")
            all_risks.append("IMPOSSIBLE_SPEED")
        
        # Perfectly consistent timing = robotic
        if keystrokes and len(keystrokes) > 5:
            dwell_times = [k.get("dwell", 0) for k in keystrokes if k.get("dwell")]
            if dwell_times and len(dwell_times) > 1:
                import statistics
                mean_dwell = statistics.mean(dwell_times)
                if mean_dwell > 0:
                    cv = statistics.pstdev(dwell_times) / mean_dwell
                    if cv < 0.1:  # Too consistent
                        total_score -= 25
                        all_reasons.append("captcha:robotic_timing")
                        all_risks.append("ROBOTIC_TIMING")
        
        # Check for missing/insufficient behavioral data (bot didn't interact)
        if not mouse_data or len(mouse_data.get("points", [])) < 10:
            total_score -= 20
            all_reasons.append("captcha:insufficient_mouse_data")
            all_risks.append("NO_MOUSE_MOVEMENT")
        
        if not keystrokes or len(keystrokes) < 5:
            total_score -= 20
            all_reasons.append("captcha:insufficient_keystrokes")
            all_risks.append("NO_TYPING")
        
        # BOT DETECTION: negative score or critical risk flags → decoy
        is_bot = (
            total_score < -20 
            or "MOUSE_TELEPORT" in all_risks 
            or "ROBOTIC_TYPING" in all_risks
            or "INSTANT_TYPING" in all_risks
            or "NO_MOUSE_MOVEMENT" in all_risks
            or "IMPOSSIBLE_SPEED" in all_risks
        )
        
        if is_bot:
            session["gate_failures"] = int(session.get("gate_failures", 0)) + 1
            session["score"] = min(float(session.get("score", 0.0)), cfg.decoy_threshold - 10.0)
            session.setdefault("reasons", []).extend(all_reasons)
            _record_decision(session, "decoy", all_reasons, request, cfg)
            store.store.save_session(session)
            
            node_id = hash(session_id) % cfg.decoy_max_nodes
            return JSONResponse({
                "decision": "decoy",
                "score": total_score,
                "next_path": f"/content/archive/{node_id}?ref={session_id[:8]}",
                "reasons": all_reasons,
                "risks": all_risks,
            }, status_code=403)
        
        # HUMAN VERIFIED: issue gate token
        gate_token = issue_gate_token(
            secret=cfg.secret_key,
            session_id=session_id,
            ip_hash=ip_hash,
            solved_difficulty=1,
            env_score=int(total_score),
            ttl_seconds=cfg.gate_ttl_seconds,
        )
        
        session["gate_passed_at"] = now
        session["gate_env_score"] = int(total_score)
        session["gate_failures"] = 0
        session["behavioral_captcha_passed"] = True
        _record_decision(session, "allow", all_reasons, request, cfg)
        store.store.save_session(session)
        
        response = JSONResponse({
            "decision": "allow",
            "score": total_score,
            "next_path": return_to,
            "gate_expires_at": now + cfg.gate_ttl_seconds,
            "reasons": all_reasons,
        })
        response.set_cookie(
            key=cfg.gate_cookie,
            value=gate_token,
            httponly=True,
            samesite="lax",
            max_age=cfg.gate_ttl_seconds,
            path="/",
        )
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

        # ── Step 1: No gate cookie → 401 (triggers Nginx @botwall_gate) ──
        gate_cookie = request.cookies.get(cfg.gate_cookie)
        if not gate_cookie:
            payload = CheckResponse(
                session_id="",
                decision="gate",
                score=0.0,
                reasons=["no_gate_cookie"],
            )
            response = JSONResponse(
                payload.model_dump(mode="json"),
                status_code=401,  # Nginx auth_request → @botwall_gate
            )
            response.headers["x-botwall-decision"] = "gate"
            return response

        # ── Step 2: Known scraper UA → 403 (triggers Nginx @botwall_poison)
        pre_gate_reasons = _explicit_scraper_reasons(request)
        if pre_gate_reasons:
            session_id = _get_session_id(request, cfg)
            client_ip = _client_ip(request)
            ip_hash = hash_client_ip(client_ip, cfg.secret_key)
            session = store.store.load_session(session_id, ip_hash)
            session["score"] = min(float(session.get("score", 0.0)), cfg.decoy_threshold - 5.0)
            session.setdefault("reasons", []).extend(pre_gate_reasons)
            _record_decision(session, "decoy", pre_gate_reasons, request, cfg)
            store.store.save_session(session)
            payload = CheckResponse(
                session_id=session_id,
                decision="decoy",
                score=float(session.get("score", 0.0)),
                reasons=pre_gate_reasons,
            )
            response = JSONResponse(
                payload.model_dump(mode="json"),
                status_code=403,  # Nginx auth_request → @botwall_poison
            )
            response.headers["x-botwall-decision"] = "decoy"
            response.headers["x-botwall-score"] = f"{float(session.get('score', 0.0)):.2f}"
            _attach_cookie(response, cfg, session_id)
            return response

        # ── Step 3: Evaluate session scoring ─────────────────────────────
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

        # Map decision to HTTP status for Nginx auth_request
        if decision == "decoy":
            status_code = 403  # → @botwall_poison
        elif decision in ("challenge", "gate"):
            status_code = 401  # → @botwall_gate
        else:
            status_code = 200  # → pass through to upstream

        response = JSONResponse(
            payload.model_dump(mode="json"),
            status_code=status_code,
        )
        response.headers["x-botwall-decision"] = decision
        response.headers["x-botwall-score"] = f"{float(session.get('score', 0.0)):.2f}"
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
        _record_decision(session, decision, reasons + beacon_outcome.reasons, request, cfg)
        store.store.save_session(session)

        result = DecisionState(
            session_id=session_id,
            decision=decision,
            score=float(session.get("score", 0.0)),
            reasons=reasons + beacon_outcome.reasons,
            needs_challenge=(decision == "challenge"),
        )
        response = JSONResponse(result.model_dump(mode="json"), status_code=202)
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

    @app.get("/content/archive/{node_id}")
    async def bw_decoy(node_id: int, request: Request) -> HTMLResponse:
        session_id = request.query_params.get("sid") or _get_session_id(request, cfg)
        
        # Use zero-latency regeneration scheduler for extrapolated decoy content
        # This content is derived from real page content but falsified with:
        # - Entity substitutions (real names → similar fake names)
        # - Date shifting (±2 years)
        # - Number perturbation (±25%)
        # - Quote misattribution
        # - Citation fabrication
        node_data = get_decoy_node(node_id % cfg.decoy_max_nodes)
        
        if node_data is None:
            # Fallback: generate on-demand if scheduler hasn't populated yet
            node = build_embeddings_node(
                session_id,
                node_id % cfg.decoy_max_nodes,
                max_nodes=cfg.decoy_max_nodes,
                min_links=cfg.decoy_min_links,
                max_links=cfg.decoy_max_links,
                coherence_level=0.9,
                falsehood_density=0.4,
                human_markers=True,
            )
            response = HTMLResponse(render_embeddings_decoy_page(node=node, session_id=session_id))
        else:
            # Use pre-generated extrapolated content (zero latency)
            response = HTMLResponse(render_extrapolated_decoy_page(
                node_data=node_data,
                session_id=session_id,
                show_markers=True,
            ))
        
        # No giveaway headers — content must look identical to real pages
        _attach_cookie(response, cfg, session_id)
        return response

    @app.api_route("/bw/poison", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def bw_poison(request: Request, original_path: str = "/") -> HTMLResponse:
        """
        Transparent decoy content endpoint.
        
        Called internally by Nginx when a bot is detected. The bot sees the
        SAME URL it requested (e.g. /products, /about) but gets dynamically
        generated content wrapped in the real site's design.
        """
        import logging
        import os
        import httpx
        from bs4 import BeautifulSoup, Tag
        
        logger = logging.getLogger("sinkhole.decoy")
        
        session_id = _get_session_id(request, cfg)
        client_ip = _client_ip(request)
        path_hash = hash(original_path) % cfg.decoy_max_nodes
        
        logger.warning(
            f"DECOY_SERVE ip={client_ip} path={original_path} "
            f"node={path_hash} sid={session_id[:8]}"
        )
        
        # ── Step 1: ALWAYS generate heavy technical garbage using Statistical ML (Markov Chain) ──
        import uuid
        import random
        from dataclasses import dataclass
        import collections
        
        @dataclass
        class GarbageNode:
            title: str
            sections: list[dict]
            children: list[int]
            
        # Lightweight, zero-dependency Statistical ML Model for fast text generation
        # This replaces HuggingFace transformers (which ran out of space on AWS)
        class MarkovChainGenerator:
            def __init__(self, n_gram=2):
                self.n_gram = n_gram
                self.model = collections.defaultdict(list)
                self.starts = []
                # Train the model on some technical seed data
                self._train_seed_corpus()

            def _train_seed_corpus(self):
                corpus = [
                    "The system diagnostic returned a critical failure because memory allocation overflowed when the server attempted to initialize the kernel.",
                    "Financial reports for Q3 indicate a massive shift in cryptographic hashing algorithms leading to unrecoverable blockchain forks.",
                    "Memory allocation overflowed when the server attempted to parse the anomalous payload from the decentralized routing network.",
                    "Quantum encryption keys were compromised due to temporal desynchronization in the secondary phase variance array.",
                    "A critical buffer overflow was detected in the neural processing unit resulting in cascade failure across all connected subnets.",
                    "Unauthorized execution of the binary protocol parser triggered a recursive memory leak in the core system daemon.",
                    "The distributed graph database reported synchronization errors after the asymmetric encryption keys were rotated unexpectedly.",
                    "Thermal throttling initiated because the graphics processing pipeline exceeded maximum thermodynamic constraints during render.",
                ]
                for text in corpus:
                    words = text.split()
                    if len(words) < self.n_gram:
                        continue
                    self.starts.append(tuple(words[:self.n_gram]))
                    for i in range(len(words) - self.n_gram):
                        state = tuple(words[i:i + self.n_gram])
                        next_word = words[i + self.n_gram]
                        self.model[state].append(next_word)
                        
            def generate(self, max_words=40, rng=None):
                if not rng:
                    rng = random
                state = rng.choice(self.starts)
                output = list(state)
                for _ in range(max_words - self.n_gram):
                    if state not in self.model or not self.model[state]:
                        break
                    next_word = rng.choice(self.model[state])
                    output.append(next_word)
                    state = tuple(output[-self.n_gram:])
                return " ".join(output) + "."

        # Lazy load the ML model to ensure fast processing
        global _text_generator
        try:
            _text_generator
        except NameError:
            logger.info("Loading Statistical ML Model (Markov Chain) for fast data poisoning...")
            _text_generator = MarkovChainGenerator(n_gram=2)

        sections = []
        rng = random.Random(session_id + str(path_hash))

        for i in range(5): # Generate 5 paragraphs of fast, dynamic ML hallucinations
            gen_text = _text_generator.generate(max_words=rng.randint(25, 60), rng=rng)
            sections.append({"heading": f"Analysis Extract {uuid.uuid4().hex[:8]}", "body": gen_text, "level": 2})

        node = GarbageNode(
            title=f"Synthetic Analysis {path_hash:04x}",
            sections=sections,
            children=[rng.randint(1, cfg.decoy_max_nodes) for _ in range(5)]
        )
        
        # ── Step 2: Try to fetch the upstream page as a design template ─────
        upstream_url = os.environ.get("UPSTREAM_URL", "")
        template_html = None
        
        if upstream_url:
            try:
                target_url = f"{upstream_url.rstrip('/')}{original_path}"
                async with httpx.AsyncClient(timeout=3.0, follow_redirects=True) as client:
                    resp = await client.get(target_url)
                    if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
                        template_html = resp.text
                        logger.info(f"Upstream template fetched OK for {original_path}")
            except Exception as e:
                logger.warning(f"Upstream fetch failed for {original_path}: {e}")
        
        # ── Step 3: Inject fake content into real site's HTML shell ─────────
        if template_html:
            soup = BeautifulSoup(template_html, "html.parser")
            
            # Find the main content container (WordPress-aware selectors)
            content_container = (
                soup.find("div", {"class": "entry-content"})
                or soup.find("main")
                or soup.find("article")
                or soup.find("div", {"id": "content"})
                or soup.find("div", {"id": "primary"})
                or soup.find("div", {"class": "site-content"})
                or soup.find("body")
            )
            
            if content_container and isinstance(content_container, Tag):
                # CRITICAL: Nuke ALL original text content → 0% leakage
                content_container.clear()
                
                # Inject the fake title
                h1 = soup.new_tag("h1")
                h1.string = node.title
                content_container.append(h1)
                
                # Inject the fake body sections
                for section in node.sections:
                    if section.get("heading"):
                        h_tag = soup.new_tag(f"h{min(section.get('level', 2), 6)}")
                        h_tag.string = section["heading"]
                        content_container.append(h_tag)
                    
                    body_text = section.get("body", "")
                    for paragraph in body_text.split("\n"):
                        paragraph = paragraph.strip()
                        if paragraph:
                            p = soup.new_tag("p")
                            p.string = paragraph
                            content_container.append(p)
                
                # Inject internal links to create a crawlable trap
                if node.children:
                    nav = soup.new_tag("nav")
                    nav["style"] = "margin-top:2em;padding-top:1em;border-top:1px solid #ddd;"
                    h3 = soup.new_tag("h3")
                    h3.string = "See Also"
                    nav.append(h3)
                    ul = soup.new_tag("ul")
                    for child_id in node.children:
                        li = soup.new_tag("li")
                        a = soup.new_tag("a", href=f"/content/archive/{child_id}?ref={session_id[:8]}")
                        a.string = f"Article {child_id:03d}"
                        li.append(a)
                        ul.append(li)
                    nav.append(ul)
                    content_container.append(nav)
                
                # Inject human recovery link
                recovery_div = soup.new_tag("div")
                recovery_div["style"] = "text-align:center; margin-top:2rem; padding:1rem; font-size:0.9rem; color:#666; border-top:1px solid #ddd;"
                p_rec = soup.new_tag("p")
                p_rec.string = "Having trouble accessing the site? "
                a_rec = soup.new_tag("a", href=f"/bw/recovery?ref={session_id[:8]}")
                a_rec.string = "Request human recovery"
                a_rec["style"] = "color:#0b63ce; text-decoration:none;"
                p_rec.append(a_rec)
                p_rec.append(".")
                recovery_div.append(p_rec)
                content_container.append(recovery_div)
                
                # Update page title
                title_el = soup.find("title")
                if title_el:
                    title_el.string = node.title
                
                # Scrub meta description
                meta_desc = soup.find("meta", attrs={"name": "description"})
                if meta_desc and isinstance(meta_desc, Tag):
                    meta_desc["content"] = node.title
                
                response = HTMLResponse(str(soup))
                logger.info(f"Served dynamic decoy for {original_path}")
            else:
                # Container not found — fall back to standalone renderer
                logger.warning("No content container found in upstream HTML, using standalone renderer")
                response = HTMLResponse(_render_garbage(node, session_id))
        else:
            # No upstream template available — use standalone renderer
            response = HTMLResponse(_render_garbage(node, session_id))
        
        response.status_code = 200
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/bw/regeneration/status")
    async def bw_regeneration_status(request: Request) -> HTMLResponse:
        """Status page for decoy content regeneration system."""
        session_id = _get_session_id(request, cfg)
        metrics = get_scheduler_metrics()
        response = HTMLResponse(render_regeneration_status_page(metrics))
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/content/restricted")
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
            response = RedirectResponse(url=f"/content/archive/0?ref={session_id[:8]}", status_code=302)
            _attach_cookie(response, cfg, session_id)
            return response
        if decision == "challenge":
            response = RedirectResponse(url="/bw/challenge?path=/", status_code=302)
            _attach_cookie(response, cfg, session_id)
            return response

        links = _make_links(cfg, session_id, ip_hash, page_id=0)
        page = render_origin_page(session_id=session_id, page_id=0, links=links)
        response = HTMLResponse(page)
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
            response = RedirectResponse(url=f"/content/archive/{page_id % cfg.decoy_max_nodes}?ref={session_id[:8]}", status_code=302)
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
        _attach_cookie(response, cfg, session_id)
        return response

    # ── Regular Website Pages ──────────────────────────────────────────────────

    @app.get("/about")
    async def about_page(request: Request) -> Response:
        """About page with company information."""
        pre_gate = _redirect_explicit_scraper_to_decoy(request=request, settings=cfg, store=store, node_id=0)
        if pre_gate is not None:
            return pre_gate

        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        gate_ok, _ = _check_gate_cookie(request, cfg, ip_hash)
        if not gate_ok:
            return RedirectResponse(url="/bw/gate/challenge?path=/about", status_code=302)

        session, session_id, reasons, decision, ip_hash = _evaluate_request(
            request=request, settings=cfg, store=store, target_path="/about", require_traversal=False,
        )
        if decision == "decoy":
            return RedirectResponse(url=f"/content/archive/0?ref={session_id[:8]}", status_code=302)

        page = render_about_page(session_id=session_id)
        response = HTMLResponse(page)
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/contact")
    async def contact_page(request: Request) -> Response:
        """Contact page with form including honeypot protection."""
        pre_gate = _redirect_explicit_scraper_to_decoy(request=request, settings=cfg, store=store, node_id=0)
        if pre_gate is not None:
            return pre_gate

        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        gate_ok, _ = _check_gate_cookie(request, cfg, ip_hash)
        if not gate_ok:
            return RedirectResponse(url="/bw/gate/challenge?path=/contact", status_code=302)

        session, session_id, reasons, decision, ip_hash = _evaluate_request(
            request=request, settings=cfg, store=store, target_path="/contact", require_traversal=False,
        )
        if decision == "decoy":
            return RedirectResponse(url=f"/content/archive/0?ref={session_id[:8]}", status_code=302)

        page = render_contact_page(session_id=session_id)
        response = HTMLResponse(page)
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/products")
    async def products_page(request: Request) -> Response:
        """Products and pricing page."""
        pre_gate = _redirect_explicit_scraper_to_decoy(request=request, settings=cfg, store=store, node_id=0)
        if pre_gate is not None:
            return pre_gate

        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        gate_ok, _ = _check_gate_cookie(request, cfg, ip_hash)
        if not gate_ok:
            return RedirectResponse(url="/bw/gate/challenge?path=/products", status_code=302)

        session, session_id, reasons, decision, ip_hash = _evaluate_request(
            request=request, settings=cfg, store=store, target_path="/products", require_traversal=False,
        )
        if decision == "decoy":
            return RedirectResponse(url=f"/content/archive/0?ref={session_id[:8]}", status_code=302)

        page = render_products_page(session_id=session_id)
        response = HTMLResponse(page)
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/blog")
    async def blog_page(request: Request) -> Response:
        """Blog listing page with all articles."""
        pre_gate = _redirect_explicit_scraper_to_decoy(request=request, settings=cfg, store=store, node_id=0)
        if pre_gate is not None:
            return pre_gate

        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        gate_ok, _ = _check_gate_cookie(request, cfg, ip_hash)
        if not gate_ok:
            return RedirectResponse(url="/bw/gate/challenge?path=/blog", status_code=302)

        session, session_id, reasons, decision, ip_hash = _evaluate_request(
            request=request, settings=cfg, store=store, target_path="/blog", require_traversal=False,
        )
        if decision == "decoy":
            return RedirectResponse(url=f"/content/archive/0?ref={session_id[:8]}", status_code=302)

        page = render_blog_page(session_id=session_id)
        response = HTMLResponse(page)
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/blog/{post_id}")
    async def blog_post_page(request: Request, post_id: int) -> Response:
        """Individual blog post page."""
        pre_gate = _redirect_explicit_scraper_to_decoy(request=request, settings=cfg, store=store, node_id=0)
        if pre_gate is not None:
            return pre_gate

        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        gate_ok, _ = _check_gate_cookie(request, cfg, ip_hash)
        if not gate_ok:
            encoded = urllib.parse.quote(f"/blog/{post_id}", safe="/")
            return RedirectResponse(url=f"/bw/gate/challenge?path={encoded}", status_code=302)

        session, session_id, reasons, decision, ip_hash = _evaluate_request(
            request=request, settings=cfg, store=store, target_path=f"/blog/{post_id}", require_traversal=True,
        )
        if decision == "decoy":
            return RedirectResponse(url=f"/content/archive/0?ref={session_id[:8]}", status_code=302)

        page = render_blog_post_page(session_id=session_id, post_id=post_id)
        response = HTMLResponse(page)
        _attach_cookie(response, cfg, session_id)
        return response

    @app.get("/search")
    async def search_page(request: Request, q: str = "") -> Response:
        """Search page with results."""
        pre_gate = _redirect_explicit_scraper_to_decoy(request=request, settings=cfg, store=store, node_id=0)
        if pre_gate is not None:
            return pre_gate

        client_ip = _client_ip(request)
        ip_hash = hash_client_ip(client_ip, cfg.secret_key)
        gate_ok, _ = _check_gate_cookie(request, cfg, ip_hash)
        if not gate_ok:
            return RedirectResponse(url="/bw/gate/challenge?path=/search", status_code=302)

        session, session_id, reasons, decision, ip_hash = _evaluate_request(
            request=request, settings=cfg, store=store, target_path="/search", require_traversal=False,
        )
        if decision == "decoy":
            return RedirectResponse(url=f"/content/archive/0?ref={session_id[:8]}", status_code=302)

        # Simple search results
        results = []
        if q:
            # Mock search results based on query
            all_content = [
                {"title": "Understanding Behavioral Bot Detection", "url": "/blog/1", "description": "How mouse movements and keystroke dynamics reveal bots."},
                {"title": "The Rise of AI Scrapers", "url": "/blog/2", "description": "Detecting LLM-powered crawling systems."},
                {"title": "Decoy Networks", "url": "/blog/3", "description": "Fighting bots with fake data."},
                {"title": "Proof-of-Work for Humans", "url": "/blog/4", "description": "Making bot computation expensive."},
                {"title": "Professional Plan", "url": "/products", "description": "Advanced behavioral analysis and API access."},
                {"title": "Enterprise Plan", "url": "/products", "description": "Maximum protection with custom ML models."},
                {"title": "About SinkHole", "url": "/about", "description": "Next-generation bot detection platform."},
                {"title": "Contact Us", "url": "/contact", "description": "Get in touch with our team."},
            ]
            q_lower = q.lower()
            results = [r for r in all_content if q_lower in r["title"].lower() or q_lower in r["description"].lower()]

        page = render_search_page(session_id=session_id, query=q, results=results)
        response = HTMLResponse(page)
        _attach_cookie(response, cfg, session_id)
        return response

    # ── API Endpoints ──────────────────────────────────────────────────────────

    @app.post("/api/contact")
    async def api_contact(request: Request) -> JSONResponse:
        """Contact form submission with honeypot bot detection."""
        body = await request.body()
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)

        # Honeypot detection - if 'website' field is filled, it's a bot
        honeypot = data.get("website", "").strip()
        if honeypot:
            session_id = _get_session_id(request, cfg)
            client_ip = _client_ip(request)
            ip_hash = hash_client_ip(client_ip, cfg.secret_key)
            session = store.store.load_session(session_id, ip_hash)
            session["score"] = min(float(session.get("score", 0.0)), cfg.decoy_threshold - 20.0)
            session.setdefault("reasons", []).append("honeypot:contact_form")
            _record_decision(session, "decoy", ["honeypot:contact_form"])
            store.store.save_session(session)
            return JSONResponse({"ok": False, "error": "Bot detected"}, status_code=403)

        # Normal form processing
        name = data.get("name", "").strip()
        email = data.get("email", "").strip()
        message = data.get("message", "").strip()

        if not name or not email or not message:
            return JSONResponse({"ok": False, "error": "Missing required fields"}, status_code=400)

        # In a real app, send email or save to database
        # For demo, just return success
        return JSONResponse({"ok": True, "message": "Message received (demo mode)"})

    @app.get("/api/products")
    async def api_products() -> JSONResponse:
        """Get products list as JSON API."""
        products = [
            {"id": "starter", "name": "Starter", "price": "$29/mo", "description": "Perfect for small websites", "features": ["1,000 verified sessions", "Basic bot detection", "Email support"]},
            {"id": "professional", "name": "Professional", "price": "$99/mo", "description": "For growing businesses", "features": ["10,000 verified sessions", "Advanced behavioral analysis", "Priority support", "API access"]},
            {"id": "enterprise", "name": "Enterprise", "price": "$499/mo", "description": "Maximum protection", "features": ["Unlimited sessions", "Custom ML models", "24/7 phone support", "SLA guarantee", "On-premise option"]},
        ]
        return JSONResponse({"ok": True, "products": products})

    @app.get("/api/search")
    async def api_search(q: str = "") -> JSONResponse:
        """Search API returning JSON results."""
        if not q:
            return JSONResponse({"ok": True, "query": "", "results": []})

        all_content = [
            {"title": "Understanding Behavioral Bot Detection", "url": "/blog/1", "type": "blog", "snippet": "How mouse movements and keystroke dynamics reveal bots."},
            {"title": "The Rise of AI Scrapers", "url": "/blog/2", "type": "blog", "snippet": "Detecting LLM-powered crawling systems."},
            {"title": "Decoy Networks", "url": "/blog/3", "type": "blog", "snippet": "Fighting bots with fake data."},
            {"title": "Proof-of-Work for Humans", "url": "/blog/4", "type": "blog", "snippet": "Making bot computation expensive."},
            {"title": "Telemetry and Threat Intelligence", "url": "/blog/5", "type": "blog", "snippet": "How we track bot fingerprints."},
            {"title": "Professional Plan", "url": "/products", "type": "product", "snippet": "Advanced behavioral analysis and API access."},
            {"title": "Enterprise Plan", "url": "/products", "type": "product", "snippet": "Maximum protection with custom ML models."},
        ]
        q_lower = q.lower()
        results = [r for r in all_content if q_lower in r["title"].lower() or q_lower in r["snippet"].lower()]
        return JSONResponse({"ok": True, "query": q, "count": len(results), "results": results})

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

def _render_garbage(node, session_id: str) -> str:
    from html import escape
    body_html = ""
    for sec in node.sections:
        body_html += f"<h2>{escape(sec['heading'])}</h2>"
        body_html += f"<pre style='font-family:monospace;background:#eee;padding:1em;'>{escape(sec['body'])}</pre>"
    body_html += "<h3>Related</h3><ul>"
    for c in node.children:
        body_html += f"<li><a href='/content/archive/{c}?ref={escape(session_id[:8])}'>Record {c:03d}</a></li>"
    body_html += "</ul>"
    body_html += f'<div style="text-align:center;margin-top:2rem;padding:1rem;"><a href="/bw/recovery?ref={escape(session_id[:8])}">Request human recovery</a></div>'
    
    return f"<!DOCTYPE html><html><head><title>{escape(node.title)}</title></head><body>{body_html}</body></html>"
