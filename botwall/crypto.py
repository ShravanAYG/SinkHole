from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from typing import Any


class TokenError(ValueError):
    """Raised when token validation fails."""


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def sign_json(payload: dict[str, Any], secret: str) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    return f"{_b64encode(body)}.{_b64encode(mac)}"


def verify_json(token: str, secret: str) -> dict[str, Any]:
    try:
        body_b64, mac_b64 = token.split(".", 1)
    except ValueError as exc:
        raise TokenError("malformed token") from exc

    try:
        body = _b64decode(body_b64)
        received_mac = _b64decode(mac_b64)
    except (binascii.Error, ValueError) as exc:
        raise TokenError("malformed token") from exc
    expected_mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    if not hmac.compare_digest(received_mac, expected_mac):
        raise TokenError("invalid signature")

    try:
        return json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise TokenError("invalid payload") from exc


def now_ts() -> int:
    return int(time.time())


def hash_client_ip(ip: str, secret: str) -> str:
    value = f"{ip}|{secret}".encode("utf-8")
    return hashlib.sha256(value).hexdigest()[:24]


def stable_fingerprint(parts: list[str], secret: str) -> str:
    joined = "|".join(parts).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), joined, hashlib.sha256).hexdigest()
