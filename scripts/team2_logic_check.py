#!/usr/bin/env python3
from __future__ import annotations

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from botwall.crypto import hash_client_ip
from botwall.decoy import build_node
from botwall.models import BeaconEvent
from botwall.proof import (
    compute_pow_hash,
    issue_gate_token,
    issue_pow_challenge,
    issue_proof_token,
    verify_gate_token,
    verify_pow_solution,
    verify_proof_token,
)
from botwall.scoring import apply_score, decide, score_beacon, score_request
from botwall.traversal import build_traversal_url, issue_traversal_token, verify_traversal_token


def assert_true(cond: bool, message: str) -> None:
    if not cond:
        raise RuntimeError(message)


def run() -> None:
    secret = "logic-check-secret"
    sid = "logic-check-session"
    ip_hash = hash_client_ip("127.0.0.1", secret)

    challenge = issue_pow_challenge(secret=secret, session_id=sid, ip_hash=ip_hash, difficulty=2, ttl_seconds=30)
    nonce = "0"
    digest = compute_pow_hash(challenge.challenge, nonce)
    while not digest.startswith("00"):
        nonce = hex(int(nonce, 16) + 1)[2:]
        digest = compute_pow_hash(challenge.challenge, nonce)

    verify_pow_solution(
        challenge_token=challenge.challenge_token,
        secret=secret,
        session_id=sid,
        ip_hash=ip_hash,
        challenge=challenge.challenge,
        nonce=nonce,
        submitted_hash=digest,
        solve_ms=250,
        max_solve_seconds=30,
    )

    gate = issue_gate_token(secret=secret, session_id=sid, ip_hash=ip_hash, solved_difficulty=2, env_score=-5, ttl_seconds=120)
    gate_payload = verify_gate_token(token=gate, secret=secret, current_ip_hash=ip_hash)
    assert_true(gate_payload["t"] == "gate", "Gate token verification failed")

    proof_token, proof_nonce = issue_proof_token(secret=secret, session_id=sid, ip_hash=ip_hash, page_path="/content/1", ttl_seconds=60)
    verify_proof_token(
        token=proof_token,
        secret=secret,
        session_id=sid,
        ip_hash=ip_hash,
        page_path="/content/1",
        nonce=proof_nonce,
    )

    traversal = issue_traversal_token(secret=secret, session_id=sid, ip_hash=ip_hash, page_path="/content/2", ttl_seconds=300)
    assert_true(
        verify_traversal_token(token=traversal, secret=secret, session_id=sid, ip_hash=ip_hash, page_path="/content/2"),
        "Traversal token verification failed",
    )
    traversal_url = build_traversal_url("/content/2", traversal)
    assert_true("bw_trace=" in traversal_url, "Traversal URL helper failed")

    session = {
        "session_id": sid,
        "score": 0.0,
        "request_times": [],
        "reasons": [],
        "events": [],
        "proof_valid": 0,
        "challenge_issued": 0,
        "allow_until": 0,
    }

    req = score_request(
        {
            "user_agent": "Mozilla/5.0 Chrome/120.0",
            "accept_language": "en-US,en;q=0.9",
            "ip_reputation": "good",
            "ja3": "browser-ja3",
        },
        session,
        now=100,
    )
    apply_score(session, req, now=100)

    beacon = BeaconEvent(
        session_id=sid,
        pointer_moves=30,
        scroll_events=9,
        max_scroll_depth=300,
        visibility_changes=1,
        focus_events=2,
        dwell_ms=2200,
        pointer_entropy=1.4,
        canvas_frame_ms=[1.1, 1.4, 1.2, 1.3],
        webgl_frame_ms=[0.9, 1.0, 1.1, 1.0],
        user_agent="Mozilla/5.0 Chrome/120.0",
        platform="Linux",
    )
    b = score_beacon(beacon, request_ua="Mozilla/5.0 Chrome/120.0")
    apply_score(session, b, now=101)
    session["events"].append(beacon.model_dump(mode="json"))
    session["proof_valid"] = 1
    session["request_times"].append(101)

    decision, _ = decide(session, sequence_window=16, now=102)
    assert_true(decision in {"allow", "observe"}, "Decision engine did not produce expected post-proof state")

    node = build_node(session_id=sid, node_id=7, max_nodes=80, min_links=4, max_links=6)
    assert_true(4 <= len(node.links) <= 6, "Decoy link density out of configured range")
    assert_true("brother" in " ".join(node.body).lower(), "Decoy relational inconsistency missing")

    print("[OK] Team-2 logic check passed")


if __name__ == "__main__":
    run()
