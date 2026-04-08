"""ScanEngine — runs all discoverers concurrently, returns populated graph.

Uses asyncio.TaskGroup to run all 7 cloud providers in parallel.
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

_DEFAULT_DB = Path("vajra_scan.duckdb")

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
    """Orchestrates concurrent multi-cloud discovery."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or _DEFAULT_DB
        self._graph = VajraGraph()
        self._scan_time: float = 0.0
        self._assets_discovered: int = 0

    async def scan_all(
        self,
        providers: tuple[str, ...] = _PROVIDERS,
    ) -> VajraGraph:
        """Run all providers concurrently, return populated graph."""
        start = time.perf_counter()
        results: list[tuple[list[CloudAsset], list[GraphEdge]]] = []

        async with asyncio.TaskGroup() as tg:
            tasks = []
            for provider in providers:
                task = tg.create_task(
                    self._discover_provider(provider),
                )
                tasks.append(task)

        for task in tasks:
            assets, edges = task.result()
            results.append((assets, edges))

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

        Dynamically imports and instantiates the provider's discoverer.
        Falls back gracefully if DuckDB file doesn't exist or
        provider has no discoverer registered.
        """
        try:
            if not self._db_path.exists():
                logger.warning(
                    "DuckDB file not found: %s — run 'cloudquery sync' first",
                    self._db_path,
                )
                return [], []

            # Dynamic import triggers __init_subclass__ auto-registration
            try:
                __import__(f"vajra.discovery.{provider}.discoverer")
            except ImportError:
                logger.debug(
                    "no discoverer module for %s",
                    provider,
                )
                return [], []

            from vajra.discovery.mapper import BaseDiscoverer

            discoverer_cls = BaseDiscoverer.get_discoverer(provider)
            if discoverer_cls is None:
                logger.debug(
                    "no discoverer registered for %s",
                    provider,
                )
                return [], []

            logger.info("discovering %s...", provider)
            discoverer = discoverer_cls(self._db_path)
            assets = discoverer.discover()
            logger.info(
                "%s: discovered %d assets",
                provider,
                len(assets),
            )

            # Yield control for concurrency
            await asyncio.sleep(0)
            return assets, []

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
        """Synchronous wrapper for scan_all()."""
        return asyncio.run(self.scan_all(providers))

    @property
    def graph(self) -> VajraGraph:
        return self._graph

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "assets_discovered": self._assets_discovered,
            "scan_time_seconds": round(self._scan_time, 3),
            "graph_integrity": self._graph.verify_integrity(),
        }
