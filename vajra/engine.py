"""ScanEngine — runs all discoverers concurrently, returns populated graph.

Uses asyncio.TaskGroup to run all 7 cloud providers in parallel.
Sequential scanning is too slow for production — an attacker could
modify infrastructure mid-scan if we take 5 minutes per provider.

Concurrent scanning = all providers at once = scan completes faster
than any single provider could change.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

from vajra.core.graph_engine import VajraGraph
from vajra.core.models import CloudAsset, GraphEdge

logger = logging.getLogger(__name__)

# All supported providers
_PROVIDERS: tuple[str, ...] = (
    "aws",
    "azure",
    "gcp",
    "alibaba",
    "tencent",
    "huawei",
    "k8s",
)


class ScanEngine:
    """Orchestrates concurrent multi-cloud discovery.

    Runs all discoverers in parallel using asyncio.TaskGroup,
    streams results into a single VajraGraph.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path
        self._graph = VajraGraph()
        self._scan_time: float = 0.0
        self._assets_discovered: int = 0

    async def scan_all(
        self,
        providers: tuple[str, ...] = _PROVIDERS,
    ) -> VajraGraph:
        """Run all providers concurrently, return populated graph.

        Uses asyncio.TaskGroup for structured concurrency.
        All providers run in parallel — if one fails, others continue.
        """
        start = time.perf_counter()
        results: list[tuple[list[CloudAsset], list[GraphEdge]]] = []

        async with asyncio.TaskGroup() as tg:
            tasks = []
            for provider in providers:
                task = tg.create_task(
                    self._discover_provider(provider),
                )
                tasks.append(task)

        # Collect results from all tasks
        for task in tasks:
            assets, edges = task.result()
            results.append((assets, edges))

        # Stream into graph (sequential — graph is not thread-safe)
        for assets, edges in results:
            for asset in assets:
                self._graph.add_asset(asset)
                self._assets_discovered += 1
            for edge in edges:
                self._graph.add_edge(edge)

        self._scan_time = time.perf_counter() - start
        logger.info(
            "scan complete: %d assets, %.2fs across %d providers",
            self._assets_discovered,
            self._scan_time,
            len(providers),
        )
        return self._graph

    async def _discover_provider(
        self,
        provider: str,
    ) -> tuple[list[CloudAsset], list[GraphEdge]]:
        """Discover assets for a single provider.

        Runs in a separate task — failures don't block other providers.
        Returns empty lists on error (graceful degradation).
        """
        try:
            # In production: instantiate provider-specific discoverer
            # For now: return empty (discoverers need real DB)
            logger.debug("discovering %s...", provider)
            # Simulate async work (real discoverers would do I/O)
            await asyncio.sleep(0)
            return [], []
        except Exception as e:
            logger.warning(
                "provider %s failed: %s (continuing with others)",
                provider,
                e,
            )
            return [], []

    def scan_sync(
        self,
        providers: tuple[str, ...] = _PROVIDERS,
    ) -> VajraGraph:
        """Synchronous wrapper for scan_all().

        For CLI usage where asyncio event loop isn't running.
        """
        return asyncio.run(self.scan_all(providers))

    @property
    def graph(self) -> VajraGraph:
        """Return the populated graph."""
        return self._graph

    @property
    def stats(self) -> dict[str, Any]:
        """Scan statistics."""
        return {
            "assets_discovered": self._assets_discovered,
            "scan_time_seconds": round(self._scan_time, 3),
            "graph_integrity": self._graph.verify_integrity(),
        }
