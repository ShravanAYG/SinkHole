from __future__ import annotations

import uuid
from typing import Any

from .crypto import TokenError, now_ts, sign_json, verify_json


def issue_proof_token(
    *,
    secret: str,
    session_id: str,
    ip_hash: str,
    page_path: str,
    ttl_seconds: int,
) -> tuple[str, str]:
    now = now_ts()
    nonce = uuid.uuid4().hex
    payload = {
        "t": "proof",
        "sid": session_id,
        "iph": ip_hash,
        "path": page_path,
        "nonce": nonce,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return sign_json(payload, secret), nonce


def verify_proof_token(
    *,
    token: str,
    secret: str,
    session_id: str,
    ip_hash: str,
    page_path: str,
    nonce: str,
    now: int | None = None,
) -> dict[str, str | int]:
    if now is None:
        now = now_ts()

    payload = verify_json(token, secret)
    if payload.get("t") != "proof":
        raise TokenError("wrong token type")
    if payload.get("sid") != session_id:
        raise TokenError("session mismatch")
    if payload.get("iph") != ip_hash:
        raise TokenError("ip hash mismatch")
    if payload.get("path") != page_path:
        raise TokenError("path mismatch")
    if payload.get("nonce") != nonce:
        raise TokenError("nonce mismatch")
    if int(payload.get("exp", 0)) < now:
        raise TokenError("proof token expired")

    return payload


def issue_gate_token(
    *,
    secret: str,
    session_id: str,
    ip_hash: str,
    difficulty: int,
    env_score: float,
    ttl_seconds: int,
) -> tuple[str, str]:
    now = now_ts()
    jti = uuid.uuid4().hex
    payload = {
        "t": "gate",
        "sid": session_id,
        "iph": ip_hash,
        "diff": difficulty,
        "env": env_score,
        "jti": jti,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return sign_json(payload, secret), jti


def verify_gate_token(
    *,
    token: str,
    secret: str,
    current_ip_hash: str,
    now: int | None = None,
) -> dict[str, Any]:
    if now is None:
        now = now_ts()

    payload = verify_json(token, secret)
    if payload.get("t") != "gate":
        raise TokenError("wrong token type")
    if payload.get("iph") != current_ip_hash:
        raise TokenError("ip changed since gate was passed")
    if int(payload.get("exp", 0)) < now:
        raise TokenError("gate token expired")

    return payload
