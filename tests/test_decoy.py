from __future__ import annotations

from botwall.decoy import build_node


def test_decoy_deterministic_per_session_and_node() -> None:
    a = build_node("session-a", 7)
    b = build_node("session-a", 7)
    assert a.title == b.title
    assert a.body == b.body
    assert a.links == b.links


def test_decoy_contains_relational_inconsistency_pattern() -> None:
    node = build_node("session-z", 11)
    text = " ".join(node.body).lower()
    assert "brother" in text
    assert len(node.links) >= 2
