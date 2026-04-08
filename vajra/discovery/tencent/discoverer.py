"""Tencent Cloud Discoverer — CAM roles, COS buckets.

Tencent uses CAM (Cloud Access Management).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from vajra.core.models import (
    CloudAsset,
    EdgeValidity,
    GraphEdge,
    RelationType,
)
from vajra.discovery.mapper import BaseDiscoverer

logger = logging.getLogger(__name__)

_PRIVILEGED_ACTIONS: frozenset[str] = frozenset(
    {
        "cam:AssumeRole",
        "cos:PutObject",
        "cos:GetObject",
        "cos:*",
    }
)

_ASSUME_ACTIONS: frozenset[str] = frozenset(
    {
        "cam:AssumeRole",
    }
)


class TencentDiscoverer(BaseDiscoverer):
    """Discovers Tencent Cloud assets and builds edges."""

    provider = "tencent"

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._assets: dict[str, CloudAsset] = {}

    def discover(self) -> list[CloudAsset]:
        """Discover Tencent Cloud assets."""
        from vajra.data.cloudquery_adapter import CloudQueryAdapter

        adapter = CloudQueryAdapter(self._db_path)
        raw_assets = adapter.load_assets()

        classified: list[CloudAsset] = []
        for asset in raw_assets:
            if asset.provider != "tencent":
                continue
            self._assets[asset.id] = asset
            classified.append(asset)

        logger.info(
            "Tencent discovery: %d assets",
            len(classified),
        )
        return classified

    def build_edges(
        self,
        policies: list[dict[str, Any]],
    ) -> list[GraphEdge]:
        """Build edges from Tencent CAM policies."""
        edges: list[GraphEdge] = []
        for policy in policies:
            edge = self._policy_to_edge(policy)
            if edge is not None:
                edges.append(edge)
        return edges

    def _policy_to_edge(
        self,
        policy: dict[str, Any],
    ) -> GraphEdge | None:
        """Convert Tencent CAM policy to edge. Default-DENY."""
        effect = policy.get("effect", "")
        principal = policy.get("principal", "")
        actions = policy.get("action", [])
        resource = policy.get("resource", "")

        if effect.strip().upper() != "ALLOW":
            return None
        if principal not in self._assets:
            return None
        if resource not in self._assets:
            return None

        relation = None
        risk = 0.5
        for action in actions:
            if action in _ASSUME_ACTIONS:
                relation = RelationType.CAN_ASSUME
                risk = 0.9
                break
            if action in _PRIVILEGED_ACTIONS:
                relation = RelationType.HAS_ACCESS
                risk = 0.8
                break

        if relation is None:
            return None

        return GraphEdge(
            source=principal,
            target=resource,
            relation=relation,
            risk_weight=risk,
            iam_validity=EdgeValidity.ASSUMED_VALID,
        )
