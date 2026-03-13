from __future__ import annotations

from .crypto import TokenError, now_ts, sign_json, verify_json


def issue_traversal_token(
    *,
    secret: str,
    session_id: str,
    ip_hash: str,
    page_path: str,
    ttl_seconds: int,
) -> str:
    now = now_ts()
    payload = {
        "t": "traversal",
        "sid": session_id,
        "iph": ip_hash,
        "path": page_path,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return sign_json(payload, secret)


def verify_traversal_token(
    *,
    token: str,
    secret: str,
    session_id: str,
    ip_hash: str,
    page_path: str,
    now: int | None = None,
) -> bool:
    if now is None:
        now = now_ts()

    try:
        payload = verify_json(token, secret)
    except TokenError:
        return False

    if payload.get("t") != "traversal":
        return False
    if payload.get("sid") != session_id:
        return False
    if payload.get("iph") != ip_hash:
        return False
    if payload.get("path") != page_path:
        return False
    if int(payload.get("exp", 0)) < now:
        return False
    return True
