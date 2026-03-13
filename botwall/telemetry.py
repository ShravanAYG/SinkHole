from __future__ import annotations

import hashlib
import json
from typing import Any

from .crypto import now_ts, sign_json, stable_fingerprint, verify_json
from .models import BeaconEvent, TelemetryExport, TelemetryFingerprint, TelemetryImport


def build_behavioral_fingerprint(
    *,
    secret: str,
    user_agent: str,
    ja3: str,
    pointer_entropy_bucket: str,
    dwell_bucket: str,
    trap_hits: int,
) -> str:
    return stable_fingerprint(
        [
            user_agent.lower()[:80],
            ja3,
            pointer_entropy_bucket,
            dwell_bucket,
            str(min(trap_hits, 9)),
        ],
        secret,
    )


def _bucket(value: float, size: float) -> str:
    return str(int(value // size))


def fingerprint_from_beacon(secret: str, beacon: BeaconEvent, ja3: str = "") -> str:
    pointer_bucket = _bucket(beacon.pointer_entropy, 0.5)
    dwell_bucket = _bucket(float(beacon.dwell_ms), 1000.0)
    ua = beacon.user_agent or "unknown"
    return build_behavioral_fingerprint(
        secret=secret,
        user_agent=ua,
        ja3=ja3,
        pointer_entropy_bucket=pointer_bucket,
        dwell_bucket=dwell_bucket,
        trap_hits=beacon.trap_hits,
    )


def signature_for_feed(source: str, exported_at: int, fingerprints: list[TelemetryFingerprint], secret: str) -> str:
    payload = {
        "source": source,
        "exported_at": exported_at,
        "fingerprints": [fp.model_dump(mode="json") for fp in fingerprints],
    }
    token = sign_json(payload, secret)
    # Return stable signature of token body so signatures are short and printable.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def export_feed(*, source: str, fingerprints: list[dict[str, Any]], secret: str) -> TelemetryExport:
    exported_at = now_ts()
    items = [TelemetryFingerprint(**item) for item in fingerprints]
    signature = signature_for_feed(source, exported_at, items, secret)
    return TelemetryExport(source=source, exported_at=exported_at, fingerprints=items, signature=signature)


def verify_import(payload: TelemetryImport, secret: str) -> bool:
    expected = signature_for_feed(payload.source, payload.exported_at, payload.fingerprints, secret)
    return expected == payload.signature


def parse_peer_secrets(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(k): str(v) for k, v in parsed.items()}
