from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Any

try:
    import redis as redis_lib
except Exception:  # pragma: no cover - optional import guard
    redis_lib = None


def default_session(session_id: str, ip_hash: str, ts: int) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "ip_hash": ip_hash,
        "created_at": ts,
        "updated_at": ts,
        "score": 0.0,
        "reasons": [],
        "request_times": [],
        "events": [],
        "proof_valid": 0,
        "challenge_issued": 0,
        "decision_history": [],
        "allow_until": 0,
        "traversal_valid": 0,
        "traversal_invalid": 0,
        "telemetry_hits": 0,
        "sdk_missing_count": 0,
        "last_user_agent": "",
        "recovery_started": 0,
    }


class BaseStore:
    def load_session(self, session_id: str, ip_hash: str) -> dict[str, Any]:
        raise NotImplementedError

    def save_session(self, session: dict[str, Any]) -> None:
        raise NotImplementedError

    def mark_once(self, kind: str, value: str, ttl_seconds: int) -> bool:
        raise NotImplementedError

    def add_telemetry(self, item: dict[str, Any]) -> None:
        raise NotImplementedError

    def list_telemetry(self, limit: int = 200) -> list[dict[str, Any]]:
        raise NotImplementedError

    def list_sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        raise NotImplementedError


class InMemoryStore(BaseStore):
    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}
        self._once: dict[str, int] = {}
        self._telemetry: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def _prune_once(self, now: int) -> None:
        expired = [k for k, exp in self._once.items() if exp <= now]
        for key in expired:
            self._once.pop(key, None)

    def load_session(self, session_id: str, ip_hash: str) -> dict[str, Any]:
        now = int(time.time())
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                session = default_session(session_id, ip_hash, now)
                self._sessions[session_id] = session
            if not session.get("ip_hash"):
                session["ip_hash"] = ip_hash
            return json.loads(json.dumps(session))

    def save_session(self, session: dict[str, Any]) -> None:
        with self._lock:
            self._sessions[session["session_id"]] = json.loads(json.dumps(session))

    def mark_once(self, kind: str, value: str, ttl_seconds: int) -> bool:
        now = int(time.time())
        key = f"{kind}:{value}"
        with self._lock:
            self._prune_once(now)
            if key in self._once:
                return False
            self._once[key] = now + ttl_seconds
            return True

    def add_telemetry(self, item: dict[str, Any]) -> None:
        with self._lock:
            self._telemetry.append(json.loads(json.dumps(item)))
            self._telemetry = self._telemetry[-500:]

    def list_telemetry(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            return json.loads(json.dumps(self._telemetry[-limit:]))

    def list_sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            values = list(self._sessions.values())[-limit:]
            return json.loads(json.dumps(values))


class RedisStore(BaseStore):
    def __init__(self, url: str) -> None:
        if redis_lib is None:
            raise RuntimeError("redis package missing")
        self._redis = redis_lib.Redis.from_url(url, decode_responses=True)

    def _session_key(self, session_id: str) -> str:
        return f"bw:s:{session_id}"

    def load_session(self, session_id: str, ip_hash: str) -> dict[str, Any]:
        now = int(time.time())
        key = self._session_key(session_id)
        raw = self._redis.get(key)
        if raw is None:
            session = default_session(session_id, ip_hash, now)
            self._redis.setex(key, 86400, json.dumps(session, separators=(",", ":")))
            return session

        session = json.loads(raw)
        if not session.get("ip_hash"):
            session["ip_hash"] = ip_hash
        return session

    def save_session(self, session: dict[str, Any]) -> None:
        key = self._session_key(session["session_id"])
        self._redis.setex(key, 86400, json.dumps(session, separators=(",", ":")))

    def mark_once(self, kind: str, value: str, ttl_seconds: int) -> bool:
        key = f"bw:once:{kind}:{value}"
        created = self._redis.set(key, "1", nx=True, ex=ttl_seconds)
        return bool(created)

    def add_telemetry(self, item: dict[str, Any]) -> None:
        self._redis.rpush("bw:telemetry", json.dumps(item, separators=(",", ":")))
        self._redis.ltrim("bw:telemetry", -500, -1)

    def list_telemetry(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self._redis.lrange("bw:telemetry", -limit, -1)
        return [json.loads(row) for row in rows]

    def list_sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        keys = self._redis.keys("bw:s:*")
        keys = keys[-limit:]
        if not keys:
            return []
        rows = self._redis.mget(keys)
        sessions = []
        for row in rows:
            if not row:
                continue
            sessions.append(json.loads(row))
        return sessions


@dataclass(slots=True)
class StoreManager:
    store: BaseStore
    backend: str


def init_store(redis_enabled: bool, redis_url: str) -> StoreManager:
    if not redis_enabled:
        return StoreManager(store=InMemoryStore(), backend="memory")

    try:
        redis_store = RedisStore(redis_url)
        redis_store._redis.ping()
        return StoreManager(store=redis_store, backend="redis")
    except Exception:
        return StoreManager(store=InMemoryStore(), backend="memory")
