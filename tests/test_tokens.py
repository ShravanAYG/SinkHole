from __future__ import annotations

import hashlib

from botwall.crypto import TokenError, hash_client_ip
from botwall.proof import (
    issue_gate_token,
    issue_pow_challenge,
    issue_proof_token,
    score_gate_environment,
    verify_gate_token,
    verify_pow_solution,
    verify_proof_token,
)
from botwall.traversal import issue_traversal_token, verify_traversal_token


def test_proof_token_binds_session_ip_path_and_nonce() -> None:
    secret = "s3cr3t"
    session_id = "sid123"
    ip_hash = hash_client_ip("127.0.0.1", secret)
    token, nonce = issue_proof_token(
        secret=secret,
        session_id=session_id,
        ip_hash=ip_hash,
        page_path="/content/1",
        ttl_seconds=60,
    )

    payload = verify_proof_token(
        token=token,
        secret=secret,
        session_id=session_id,
        ip_hash=ip_hash,
        page_path="/content/1",
        nonce=nonce,
    )
    assert payload["sid"] == session_id


def test_proof_token_expiry_and_path_mismatch() -> None:
    secret = "s3cr3t"
    session_id = "sid123"
    ip_hash = hash_client_ip("127.0.0.1", secret)
    token, nonce = issue_proof_token(
        secret=secret,
        session_id=session_id,
        ip_hash=ip_hash,
        page_path="/content/1",
        ttl_seconds=1,
    )

    # Path mismatch must fail.
    try:
        verify_proof_token(
            token=token,
            secret=secret,
            session_id=session_id,
            ip_hash=ip_hash,
            page_path="/content/2",
            nonce=nonce,
        )
        assert False, "expected TokenError"
    except TokenError:
        pass

    # Expiry must fail.
    try:
        verify_proof_token(
            token=token,
            secret=secret,
            session_id=session_id,
            ip_hash=ip_hash,
            page_path="/content/1",
            nonce=nonce,
            now=10**10,
        )
        assert False, "expected TokenError"
    except TokenError:
        pass


def test_traversal_token_validation_and_tamper() -> None:
    secret = "s3cr3t"
    session_id = "sid123"
    ip_hash = hash_client_ip("127.0.0.1", secret)
    token = issue_traversal_token(
        secret=secret,
        session_id=session_id,
        ip_hash=ip_hash,
        page_path="/content/4",
        ttl_seconds=300,
    )

    assert verify_traversal_token(
        token=token,
        secret=secret,
        session_id=session_id,
        ip_hash=ip_hash,
        page_path="/content/4",
    )

    assert not verify_traversal_token(
        token=token,
        secret=secret,
        session_id=session_id,
        ip_hash=ip_hash,
        page_path="/content/5",
    )


def test_pow_challenge_solution_and_replay_bindings() -> None:
    secret = "s3cr3t"
    session_id = "sid123"
    ip_hash = hash_client_ip("127.0.0.1", secret)

    challenge = issue_pow_challenge(
        secret=secret,
        session_id=session_id,
        ip_hash=ip_hash,
        difficulty=2,
        ttl_seconds=30,
    )

    target = "0" * challenge.difficulty
    nonce = 0
    solved_nonce = ""
    solved_hash = ""
    while True:
        candidate = format(nonce, "x")
        digest = hashlib.sha256((challenge.challenge + candidate).encode("utf-8")).hexdigest()
        if digest.startswith(target):
            solved_nonce = candidate
            solved_hash = digest
            break
        nonce += 1

    result = verify_pow_solution(
        challenge_token=challenge.challenge_token,
        secret=secret,
        session_id=session_id,
        ip_hash=ip_hash,
        challenge=challenge.challenge,
        nonce=solved_nonce,
        submitted_hash=solved_hash,
        solve_ms=60,
        max_solve_seconds=30,
    )
    assert result.difficulty == 2
    assert result.challenge_id

    try:
        verify_pow_solution(
            challenge_token=challenge.challenge_token,
            secret=secret,
            session_id=session_id,
            ip_hash=ip_hash,
            challenge=challenge.challenge,
            nonce=solved_nonce,
            submitted_hash="0" * 64,
            solve_ms=60,
            max_solve_seconds=30,
        )
        assert False, "expected TokenError"
    except TokenError:
        pass


def test_pow_accepts_fast_solve_time_when_hash_is_valid() -> None:
    secret = "s3cr3t"
    session_id = "sid-fast"
    ip_hash = hash_client_ip("127.0.0.1", secret)

    challenge = issue_pow_challenge(
        secret=secret,
        session_id=session_id,
        ip_hash=ip_hash,
        difficulty=2,
        ttl_seconds=30,
    )

    target = "0" * challenge.difficulty
    nonce = 0
    solved_nonce = ""
    solved_hash = ""
    while True:
        candidate = format(nonce, "x")
        digest = hashlib.sha256((challenge.challenge + candidate).encode("utf-8")).hexdigest()
        if digest.startswith(target):
            solved_nonce = candidate
            solved_hash = digest
            break
        nonce += 1

    result = verify_pow_solution(
        challenge_token=challenge.challenge_token,
        secret=secret,
        session_id=session_id,
        ip_hash=ip_hash,
        challenge=challenge.challenge,
        nonce=solved_nonce,
        submitted_hash=solved_hash,
        solve_ms=1,
        max_solve_seconds=30,
    )
    assert result.difficulty == 2


def test_gate_token_ip_binding_and_env_scoring() -> None:
    secret = "s3cr3t"
    sid = "sid-1"
    good_ip_hash = hash_client_ip("10.0.0.1", secret)
    bad_ip_hash = hash_client_ip("10.0.0.2", secret)

    token = issue_gate_token(
        secret=secret,
        session_id=sid,
        ip_hash=good_ip_hash,
        solved_difficulty=3,
        env_score=-10,
        ttl_seconds=120,
    )
    payload = verify_gate_token(token=token, secret=secret, current_ip_hash=good_ip_hash)
    assert payload["sid"] == sid

    try:
        verify_gate_token(token=token, secret=secret, current_ip_hash=bad_ip_hash)
        assert False, "expected TokenError"
    except TokenError:
        pass

    score, reasons, hard_fail = score_gate_environment(
        {
            "webdriver": True,
            "chrome_obj": True,
            "plugins_count": 3,
            "languages": ["en-US", "en"],
            "viewport": [1366, 768],
            "notification_api": True,
            "perf_memory": True,
            "renderer": "ANGLE (NVIDIA)",
        },
        request_user_agent="Mozilla/5.0 Chrome/120.0",
    )
    assert hard_fail is True
    assert "env:webdriver_true" in reasons
    assert score <= 0
