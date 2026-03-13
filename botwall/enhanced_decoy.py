"""
Enhanced decoy node builder using embeddings-based fake content generation.

This module extends the basic decoy system with sophisticated fake content
that appears real to automated systems but contains detectable falsehoods
for human verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .decoy import DecoyNode, _rng_for_node, _make_links
from .embeddings_content import generate_fake_decoy_content, FakeContentConfig


@dataclass
class EnhancedDecoyNode(DecoyNode):
    """Extended decoy node with embeddings-based content."""
    # Inherits: node_id, title, summary, body, links
    hidden_markers: list[str] = None
    metadata: dict[str, Any] = None
    
    def __post_init__(self):
        if self.hidden_markers is None:
            self.hidden_markers = []
        if self.metadata is None:
            self.metadata = {}


def build_embeddings_node(
    session_id: str,
    node_id: int,
    max_nodes: int = 80,
    min_links: int = 4,
    max_links: int = 6,
    coherence_level: float = 0.9,
    falsehood_density: float = 0.4,
    human_markers: bool = True,
) -> EnhancedDecoyNode:
    """
    Build a decoy node with embeddings-based fake content.
    
    Args:
        session_id: Session identifier for deterministic generation
        node_id: Node identifier
        max_nodes: Maximum nodes in the decoy graph
        min_links: Minimum links per node
        max_links: Maximum links per node
        coherence_level: How grammatically correct (0-1)
        falsehood_density: Portion of facts that are wrong (0-1)
        human_markers: Include obvious markers for humans
    
    Returns:
        EnhancedDecoyNode with sophisticated fake content
    """
    node_id = int(node_id) % max(1, max_nodes)
    rng = _rng_for_node(session_id, node_id)
    
    # Generate embeddings-based fake content
    config = FakeContentConfig(
        coherence_level=coherence_level,
        falsehood_density=falsehood_density,
        semantic_drift=0.4,
        human_detectable_markers=human_markers,
    )
    
    content = generate_fake_decoy_content(
        session_id=session_id,
        node_id=node_id,
        coherence_level=config.coherence_level,
        falsehood_density=config.falsehood_density,
        human_markers=config.human_detectable_markers,
    )
    
    # Generate links
    links = _make_links(rng, node_id=node_id, max_nodes=max_nodes, 
                       min_links=min_links, max_links=max_links)
    
    # Add traditional decoy elements for backward compatibility
    bait_code = f"VERIFY-AUTH-{rng.randint(1000, 9999)} PRIORITY-ENTRY"
    synthetic_table = (
        f"Node-{node_id:03d} | Coherence: {coherence_level:.2f} | "
        f"Falsehood Density: {falsehood_density:.2f} | Type: EMBEDDINGS"
    )
    
    # Combine embeddings content with traditional elements
    body = content["body"] + [synthetic_table, bait_code]
    
    return EnhancedDecoyNode(
        node_id=node_id,
        title=content["title"],
        summary=content["summary"],
        body=body,
        links=links,
        hidden_markers=content.get("hidden_markers", []),
        metadata=content.get("metadata", {}),
    )


def build_hybrid_node(
    session_id: str,
    node_id: int,
    max_nodes: int = 80,
    min_links: int = 4,
    max_links: int = 6,
    embeddings_ratio: float = 0.7,
) -> EnhancedDecoyNode:
    """
    Build a hybrid node combining traditional and embeddings content.
    
    Args:
        embeddings_ratio: Portion of content from embeddings (0-1)
    
    Returns:
        EnhancedDecoyNode with mixed content
    """
    node_id = int(node_id) % max(1, max_nodes)
    
    if embeddings_ratio >= 0.5:
        # Primarily embeddings-based
        return build_embeddings_node(
            session_id=session_id,
            node_id=node_id,
            max_nodes=max_nodes,
            min_links=min_links,
            max_links=max_links,
        )
    else:
        # Fall back to traditional node
        from .decoy import build_node
        traditional = build_node(session_id, node_id, max_nodes, min_links, max_links)
        return EnhancedDecoyNode(
            node_id=traditional.node_id,
            title=traditional.title,
            summary=traditional.summary,
            body=traditional.body,
            links=traditional.links,
            hidden_markers=["Traditional decoy content"],
            metadata={"type": "traditional"},
        )
