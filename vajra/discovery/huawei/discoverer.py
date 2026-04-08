"""Huawei Cloud Discoverer — IAM agencies, OBS buckets.

Huawei uses IAM agencies for cross-account delegation.
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
        "iam:agencies:assume",
        "obs:object:PutObject",
        "obs:object:GetObject",
        "obs:*",
    }
)

_ASSUME_ACTIONS: frozenset[str] = frozenset(
    {
        "iam:agencies:assume",
    }
)


class HuaweiDiscoverer(BaseDiscoverer):
    """Discovers Huawei Cloud assets and builds edges."""

    provider = "huawei"

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._assets: dict[str, CloudAsset] = {}

    def discover(self) -> list[CloudAsset]:
        """Discover Huawei Cloud assets."""
        from vajra.data.cloudquery_adapter import CloudQueryAdapter

        adapter = CloudQueryAdapter(self._db_path)
        raw_assets = adapter.load_assets()

        classified: list[CloudAsset] = []
        for asset in raw_assets:
            if asset.provider != "huawei":
                continue
            self._assets[asset.id] = asset
            classified.append(asset)

        logger.info(
            "Huawei discovery: %d assets",
            len(classified),
        )
        return classified

    def build_edges(
        self,
        policies: list[dict[str, Any]],
    ) -> list[GraphEdge]:
        """Build edges from Huawei IAM policies."""
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
        """Convert Huawei IAM policy to edge. Default-DENY."""
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
