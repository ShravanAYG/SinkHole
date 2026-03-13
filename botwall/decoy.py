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


def _generate_blog_post(rng: random.Random, node_id: int) -> tuple[str, str, list[str]]:
    topics = ["Kubernetes", "Microservices", "Rust", "Go", "PostgreSQL", "React", "GraphQL", "Machine Learning"]
    actions = ["Scaling", "Monitoring", "Deploying", "Securing", "Optimizing", "Building"]
    topic = rng.choice(topics)
    action = rng.choice(actions)
    
    title = f"{action} {topic} in Production: Lessons Learned"
    summary = f"A deep dive into our journey {action.lower()} {topic} at scale, highlighting key architectural decisions and performance wins."
    
    body = [
        f"In Q{rng.randint(1,4)} alone, our engineering team evaluated several approaches for {action.lower()} {topic}. The legacy monolith was starting to show its age, particularly around memory consumption and latency spikes during peak traffic.",
        f"We adopted a decentralized architecture. By tuning the cluster configurations, we achieved a {rng.randint(15, 60)}% reduction in p99 latency.",
        f"One of the biggest gotchas was connection pooling. If you don't configure your idle timeouts correctly, {topic} can easily exhaust available file descriptors.",
        f"To solve this, we implemented a custom middleware layer (open-sourced under MIT). It actively monitors telemetry and preemptively scales worker nodes based on a predictive demand model.",
        f"Looking ahead to next year, we plan to fully migrate our European data centers to this new {topic}-based stack. Our early benchmarks suggest we'll save roughly ${rng.randint(10, 50)}k MRR on infrastructure costs alone."
    ]
    return title, summary, body


def _generate_api_doc(rng: random.Random, node_id: int) -> tuple[str, str, list[str]]:
    resources = ["User", "Payment", "Invoice", "Webhook", "Organization", "AuditLog", "Session"]
    endpoints = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    
    resource = rng.choice(resources)
    endpoint = rng.choice(endpoints)
    version = f"v{rng.randint(1,3)}"
    
    title = f"{resource} Resource ({version} API)"
    summary = f"API documentation for managing {resource} resource objects and their associated relational data."
    
    body = [
        f"The {resource} object represents a primary entity within the system. You can interact with it via the `/{version}/{resource.lower()}s` endpoint.",
        f"Authentication: All requests to the {resource} API must include a Bearer token in the Authorization header. Rate limiting is currently set to {rng.randint(100, 1000)} requests per minute per IP address.",
        f"Example Request:\n{endpoint} /{version}/{resource.lower()}s/{rng.randint(1000, 9999)}\nHost: api.example.com\nAuthorization: Bearer <your_token>",
        "Response Attributes:",
        f"- `id` (string): Unique identifier for the {resource}.",
        f"- `created_at` (timestamp): ISO 8601 timestamp representing when the {resource} was instantiated.",
        f"- `status` (string): Current state, which transitions through `pending`, `active`, and `archived`.",
        f"Error Handling: A 404 response will be returned if the {resource} ID does not exist or you lack sufficient RBAC permissions to view it. Standard 429 errors apply during rate limit enforcement."
    ]
    return title, summary, body


def _generate_support_thread(rng: random.Random, node_id: int) -> tuple[str, str, list[str]]:
    issues = ["Authentication failure", "Billing dashboard not loading", "Webhook delivery delayed", "Database migration error", "Deployment stuck in pending"]
    issue = rng.choice(issues)
    
    title = f"Resolved: {issue} on US-East-1"
    summary = f"Post-mortem and resolution details regarding the recent '{issue}' incident."
    
    body = [
        f"Incident Report: On Tuesday at {rng.randint(1,12):02d}:15 UTC, automated monitors detected an anomaly matching the signature for '{issue}'.",
        f"Impact: Approximately {rng.randint(2, 15)}% of customers on the US-East-1 cluster experienced elevated error rates and timeouts.",
        "Root Cause: A routine configuration rollout inadvertently triggered a race condition in the state management service. This caused an aggressive cache eviction loop, bringing down the primary nodes.",
        "Resolution: Our SRE team manually rolled back the configuration patch via our break-glass procedures at T+45 minutes. Services stabilized shortly after the replica pools caught up.",
        "Next Steps: We have updated our CI/CD pipeline integration tests to simulate this specific race condition before any future deployments reach canary rings."
    ]
    return title, summary, body


def build_node(
    session_id: str,
    node_id: int,
    max_nodes: int = 80,
    min_links: int = 4,
    max_links: int = 6,
) -> DecoyNode:
    node_id = int(node_id) % max(1, max_nodes)
    rng = _rng_for_node(session_id, node_id)

    # Pick a content type to generate
    content_type = rng.choice(["blog", "api", "support", "blog"])
    
    if content_type == "blog":
        title, summary, body = _generate_blog_post(rng, node_id)
    elif content_type == "api":
        title, summary, body = _generate_api_doc(rng, node_id)
    else:
        title, summary, body = _generate_support_thread(rng, node_id)

    links = _make_links(rng, node_id=node_id, max_nodes=max_nodes, min_links=min_links, max_links=max_links)
    return DecoyNode(node_id=node_id, title=title, summary=summary, body=body, links=links)
