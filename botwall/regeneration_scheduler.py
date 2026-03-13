"""
Background Regeneration System - Zero-latency decoy content refresh.

Runs as a background async task that:
1. Harvests real content every N minutes
2. Regenerates falsified decoy content atomically
3. Swaps decoy nodes without blocking requests
4. Monitors performance and adjusts frequency
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .content_harvester import ContentHarvester, SemanticCache
from .extrapolation_engine import ExtrapolationConfig, SemanticExtrapolator, FalsifiedContent


@dataclass
class RegenerationMetrics:
    """Performance metrics for the regeneration system."""
    total_runs: int = 0
    successful_runs: int = 0
    failed_runs: int = 0
    total_generation_time_ms: float = 0.0
    avg_generation_time_ms: float = 0.0
    last_run_timestamp: float = 0.0
    last_success_timestamp: float = 0.0
    cache_hit_rate: float = 0.0
    decoy_nodes_active: int = 0


@dataclass
class AtomicDecoyStore:
    """
    Thread-safe atomic store for decoy content.
    
    Uses immutable swap pattern for zero-latency updates.
    Readers always see a consistent snapshot.
    """
    nodes: dict[int, dict[str, Any]] = field(default_factory=dict)
    version: int = 0
    created_at: float = field(default_factory=time.time)
    source_cache_version: int = 0


class RegenerationScheduler:
    """
    Background scheduler for decoy content regeneration.
    
    Designed for zero impact on request serving:
    - Runs in separate asyncio task
    - Pre-builds content before swapping
    - Atomic pointer swap (no locks during read)
    - Adaptive frequency based on load
    """
    
    _instance: RegenerationScheduler | None = None
    
    def __new__(cls) -> RegenerationScheduler:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(
        self,
        interval_seconds: float = 180.0,  # 3 minutes default
        num_decoy_nodes: int = 80,
    ):
        if self._initialized:
            return
        self._initialized = True
        
        self.interval = interval_seconds
        self.num_nodes = num_decoy_nodes
        
        # Harvester and extrapolator
        self.harvester = ContentHarvester()
        self.extrapolator: SemanticExtrapolator | None = None
        
        # Atomic stores
        self._current_store: AtomicDecoyStore = AtomicDecoyStore()
        self._next_store: AtomicDecoyStore | None = None
        
        # Metrics
        self.metrics = RegenerationMetrics()
        
        # Control
        self._running = False
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()
        
        # Adaptive controls
        self._backoff_counter = 0
        self._max_backoff = 5
    
    async def start(self) -> None:
        """Start the background regeneration loop."""
        if self._running:
            return
        
        self._running = True
        self._stop_event.clear()
        
        # Initial population
        await self._regenerate_once()
        
        # Start background task
        self._task = asyncio.create_task(self._regeneration_loop())
    
    async def stop(self) -> None:
        """Stop the background regeneration loop."""
        if not self._running:
            return
        
        self._running = False
        self._stop_event.set()
        
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
    
    async def _regeneration_loop(self) -> None:
        """Main regeneration loop."""
        while self._running:
            try:
                # Wait for interval (with early exit support)
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self._get_interval(),
                )
                if not self._running:
                    break
            except asyncio.TimeoutError:
                pass  # Normal interval elapsed
            
            if not self._running:
                break
            
            # Run regeneration
            try:
                await self._regenerate_once()
            except Exception as e:
                # Log but don't crash - we'll retry next cycle
                self.metrics.failed_runs += 1
                self._backoff_counter = min(self._backoff_counter + 1, self._max_backoff)
    
    async def _regenerate_once(self) -> None:
        """Execute one regeneration cycle."""
        start_time = time.perf_counter()
        self.metrics.last_run_timestamp = time.time()
        self.metrics.total_runs += 1
        
        try:
            # Step 1: Harvest real content (async, non-blocking)
            cache = await self.harvester.harvest_all()
            
            # Step 2: Skip if cache hasn't changed
            if cache.version == self._current_store.source_cache_version:
                # No changes, skip regeneration
                self.metrics.cache_hit_rate = (
                    (self.metrics.cache_hit_rate * 9 + 1.0) / 10
                )
                return
            
            self.metrics.cache_hit_rate = (
                (self.metrics.cache_hit_rate * 9 + 0.0) / 10
            )
            
            # Step 3: Initialize extrapolator with new cache
            self.extrapolator = SemanticExtrapolator(cache)
            
            # Step 4: Generate all decoy nodes in background
            new_nodes = await self._generate_all_nodes(cache)
            
            # Step 5: Build next store
            next_store = AtomicDecoyStore(
                nodes=new_nodes,
                version=self._current_store.version + 1,
                created_at=time.time(),
                source_cache_version=cache.version,
            )
            
            # Step 6: Atomic swap
            self._current_store = next_store
            
            # Update metrics
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            self.metrics.successful_runs += 1
            self.metrics.last_success_timestamp = time.time()
            self.metrics.total_generation_time_ms += elapsed_ms
            self.metrics.avg_generation_time_ms = (
                self.metrics.total_generation_time_ms / self.metrics.successful_runs
            )
            self.metrics.decoy_nodes_active = len(new_nodes)
            
            # Reset backoff on success
            self._backoff_counter = 0
            
        except Exception as e:
            self.metrics.failed_runs += 1
            self._backoff_counter = min(self._backoff_counter + 1, self._max_backoff)
            raise
    
    async def _generate_all_nodes(self, cache: SemanticCache) -> dict[int, dict[str, Any]]:
        """Generate all decoy nodes from cached content."""
        nodes: dict[int, dict[str, Any]] = {}
        
        # Get all content nodes as potential seeds
        cache_nodes = list(cache.nodes.values())
        
        # Generate each decoy node
        for node_id in range(self.num_nodes):
            # Pick seed node (deterministic based on node_id)
            if cache_nodes:
                seed_index = node_id % len(cache_nodes)
                seed_node = cache_nodes[seed_index]
            else:
                seed_node = None
            
            # Generate falsified content
            falsified = self.extrapolator.extrapolate_content(
                seed_node=seed_node,
                config=ExtrapolationConfig(
                    entity_swap_ratio=0.5,
                    date_drift_range=(-730, 730),  # ±2 years
                    number_perturbation=0.3,
                    quote_misattribution=0.4,
                    citation_fabrication=True,
                    event_inversion=0.25,
                ),
            )
            
            # Build links (deterministic)
            links = self._generate_links(node_id)
            
            # Store node data
            nodes[node_id] = {
                "node_id": node_id,
                "title": falsified.title,
                "summary": falsified.summary,
                "sections": [
                    {"heading": s.heading, "body": s.body, "level": s.level}
                    for s in falsified.sections
                ],
                "links": links,
                "source_nodes": falsified.source_nodes,
                "confidence_score": falsified.confidence_score,
                "falsification_map": falsified.falsification_map,
                "generated_at": time.time(),
            }
        
        return nodes
    
    def _generate_links(self, node_id: int) -> list[int]:
        """Generate deterministic links for a node."""
        rng = random.Random(
            hashlib.sha256(f"links:{node_id}:v{self._current_store.version}".encode()).hexdigest()[:8],
            16,
        )
        
        num_links = rng.randint(3, 6)
        links = []
        
        while len(links) < num_links:
            target = rng.randint(0, self.num_nodes - 1)
            if target != node_id and target not in links:
                links.append(target)
        
        return sorted(links)
    
    def _get_interval(self) -> float:
        """Get current interval with backoff applied."""
        backoff_multiplier = 2 ** self._backoff_counter
        return self.interval * backoff_multiplier
    
    def get_node(self, node_id: int) -> dict[str, Any] | None:
        """
        Get a decoy node (zero-latency, atomic read).
        
        This is called from request handlers and must be extremely fast.
        """
        return self._current_store.nodes.get(node_id)
    
    def get_all_nodes(self) -> dict[int, dict[str, Any]]:
        """Get all current decoy nodes."""
        return self._current_store.nodes.copy()
    
    def get_metrics(self) -> RegenerationMetrics:
        """Get current metrics snapshot."""
        return RegenerationMetrics(
            total_runs=self.metrics.total_runs,
            successful_runs=self.metrics.successful_runs,
            failed_runs=self.metrics.failed_runs,
            total_generation_time_ms=self.metrics.total_generation_time_ms,
            avg_generation_time_ms=self.metrics.avg_generation_time_ms,
            last_run_timestamp=self.metrics.last_run_timestamp,
            last_success_timestamp=self.metrics.last_success_timestamp,
            cache_hit_rate=self.metrics.cache_hit_rate,
            decoy_nodes_active=self.metrics.decoy_nodes_active,
        )


# Singleton accessor
def get_scheduler(
    interval_seconds: float = 180.0,
    num_decoy_nodes: int = 80,
) -> RegenerationScheduler:
    """Get the regeneration scheduler singleton."""
    scheduler = RegenerationScheduler()
    if not scheduler._initialized:
        scheduler.__init__(interval_seconds, num_decoy_nodes)
    return scheduler


# Convenience functions for app integration
def get_decoy_node(node_id: int) -> dict[str, Any] | None:
    """Get a decoy node (for use in request handlers)."""
    scheduler = get_scheduler()
    return scheduler.get_node(node_id)


def get_scheduler_metrics() -> RegenerationMetrics:
    """Get scheduler metrics."""
    scheduler = get_scheduler()
    return scheduler.get_metrics()
