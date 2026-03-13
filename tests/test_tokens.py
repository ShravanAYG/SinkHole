from __future__ import annotations

from botwall.crypto import TokenError, hash_client_ip
from botwall.proof import issue_proof_token, verify_proof_token
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
