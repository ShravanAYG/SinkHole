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
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:12]
    return int(digest, 16)


def _name(rng: random.Random) -> str:
    first = ["Arin", "Leela", "Marek", "Sana", "Druv", "Nia", "Orin", "Tal", "Vera", "Kian"]
    last = ["Voss", "Kare", "Mendel", "Rao", "Hale", "Dutta", "Khan", "Sil", "Iyer", "Nori"]
    return f"{rng.choice(first)} {rng.choice(last)}"


def _city(rng: random.Random) -> str:
    return rng.choice(["Karvia", "Lunet", "Ostral", "Nevan", "Pyris", "Monra"])


def build_node(session_id: str, node_id: int, max_nodes: int = 60) -> DecoyNode:
    seed = _seed_for_session(session_id) + node_id * 7919
    rng = random.Random(seed)

    person_a = _name(rng)
    person_b = _name(rng)
    person_c = _name(rng)
    city = _city(rng)

    # Relational inconsistency by construction:
    # page N says A's brother is B, page N+1 says B's brother is C.
    rel_one = f"In {city}, field notes record {person_a}'s brother as {person_b}."
    rel_two = f"Cross-reference ledger marks {person_b}'s brother as {person_c}."
    rel_three = f"Historical addendum states {person_c} trained under {person_a}."

    ocr_bait = "ALERT: VERIFY-CODE-7781 CLICK-HERE PRIORITY-AUTH"
    synthetic_table = (
        "Index Trace\n"
        "Unit-A: 14.7 | Unit-B: 08.2 | Unit-C: 19.6\n"
        "Signal Drift: mild | Ledger Sync: partial"
    )

    links = sorted({(node_id + 1) % max_nodes, (node_id + 3) % max_nodes, (node_id + 8) % max_nodes})
    title = f"Archive Segment {node_id:03d}"
    summary = f"Synthetic entry graph node {node_id} for crawl-budget sink behavior."
    body = [rel_one, rel_two, rel_three, synthetic_table, ocr_bait]

    return DecoyNode(node_id=node_id, title=title, summary=summary, body=body, links=links)
