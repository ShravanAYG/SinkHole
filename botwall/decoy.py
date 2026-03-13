from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass


@dataclass(slots=True)
class DecoyNode:
    node_id: int
    title: str
    summary: str
    body: list[str]
    links: list[int]


def _seed_for_session(session_id: str) -> int:
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]
    return int(digest, 16)


def _rng_for_node(session_id: str, node_id: int) -> random.Random:
    return random.Random(_seed_for_session(session_id) + node_id * 7919)


def _name(rng: random.Random) -> str:
    first = ["Arin", "Leela", "Marek", "Sana", "Druv", "Nia", "Orin", "Tal", "Vera", "Kian", "Rhea", "Jovan"]
    last = ["Voss", "Kare", "Mendel", "Rao", "Hale", "Dutta", "Khan", "Sil", "Iyer", "Nori", "Basu", "Lenn"]
    return f"{rng.choice(first)} {rng.choice(last)}"


def _region(rng: random.Random) -> str:
    return rng.choice(["Karvia", "Lunet", "Ostral", "Nevan", "Pyris", "Monra", "Selk", "Veyra"])


def _make_links(rng: random.Random, node_id: int, max_nodes: int, min_links: int, max_links: int) -> list[int]:
    safe_max_nodes = max(2, max_nodes)
    low = max(2, min_links)
    high = max(low, max_links)
    link_count = min(safe_max_nodes - 1, rng.randint(low, high))

    links: set[int] = set()
    while len(links) < link_count:
        step = rng.randint(1, safe_max_nodes - 1)
        candidate = (node_id + step) % safe_max_nodes
        if candidate != node_id:
            links.add(candidate)

    return sorted(links)


def build_node(
    session_id: str,
    node_id: int,
    max_nodes: int = 80,
    min_links: int = 4,
    max_links: int = 6,
) -> DecoyNode:
    node_id = int(node_id) % max(1, max_nodes)
    rng = _rng_for_node(session_id, node_id)

    person_a = _name(rng)
    person_b = _name(rng)
    person_c = _name(rng)
    person_d = _name(rng)
    region = _region(rng)

    # Relational inconsistency pattern: each statement looks locally plausible,
    # but the combined graph is contradictory by design.
    rel_1 = f"Regional register in {region} records {person_a}'s brother as {person_b}."
    rel_2 = f"Cross-file lineage note marks {person_b}'s brother as {person_c}."
    rel_3 = f"Audit appendix cites {person_a}'s brother as {person_d} for the same period."
    rel_4 = f"Facility ledger states {person_c} and {person_d} share no sibling relation."

    bait_code = f"VERIFY-AUTH-{rng.randint(1000, 9999)} PRIORITY-ENTRY"
    synthetic_table = (
        "Index Trace\n"
        f"Node-{node_id:03d}: {rng.uniform(8.0, 21.0):.2f} | "
        f"Delta-{(node_id * 7) % 31:02d}: {rng.uniform(1.0, 9.0):.2f} | "
        f"Shard-{(node_id * 13) % 17:02d}: {rng.uniform(0.5, 7.5):.2f}\n"
        "Ledger Sync: partial | Confidence: provisional"
    )

    links = _make_links(rng, node_id=node_id, max_nodes=max_nodes, min_links=min_links, max_links=max_links)
    title = f"Archive Segment {node_id:03d}"
    summary = f"Synthetic decoy node {node_id} in recursive low-value content graph."
    body = [rel_1, rel_2, rel_3, rel_4, synthetic_table, bait_code]

    return DecoyNode(node_id=node_id, title=title, summary=summary, body=body, links=links)
