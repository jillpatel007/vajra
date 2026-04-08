"""Scanner Framework — @vajra_scanner decorator + auto-registration.

Every analysis plugin registers itself with @vajra_scanner.
ScanEngine.run_all() discovers and runs all registered scanners.
Adding a new scanner = one decorated class. Zero wiring.
"""

from __future__ import annotations

import logging
from typing import Any

from vajra.core.graph_engine import VajraGraph

logger = logging.getLogger(__name__)

# Global scanner registry
_SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {}


def vajra_scanner(cls: type[BaseScanner]) -> type[BaseScanner]:
    """Decorator that auto-registers a scanner plugin."""
    name = getattr(cls, "name", cls.__name__)
    _SCANNER_REGISTRY[name] = cls
    logger.debug("registered scanner: %s", name)
    return cls


class BaseScanner:
    """Base class for all analysis plugins."""

    name: str = ""

    def run(self, graph: VajraGraph) -> dict[str, Any]:
        """Run analysis on the graph. Override in subclass."""
        raise NotImplementedError


def get_registry() -> dict[str, type[BaseScanner]]:
    """Return all registered scanners."""
    return dict(_SCANNER_REGISTRY)


def run_all(graph: VajraGraph) -> list[dict[str, Any]]:
    """Run all registered scanners against the graph."""
    results: list[dict[str, Any]] = []
    for name, scanner_cls in _SCANNER_REGISTRY.items():
        try:
            scanner = scanner_cls()
            result = scanner.run(graph)
            result["scanner"] = name
            results.append(result)
            logger.info("scanner %s completed", name)
        except Exception as e:
            logger.warning("scanner %s failed: %s", name, e)
            results.append({"scanner": name, "error": str(e)})
    return results
