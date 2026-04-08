"""Alibaba Cloud Discoverer — RAM roles, OSS buckets, KMS, ECS.

Alibaba uses RAM (Resource Access Management) instead of IAM.
MLPS 2.0 Level 3 compliance requires strict access control.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from vajra.core.models import (
    AssetType,
    CloudAsset,
    EdgeValidity,
    GraphEdge,
    RelationType,
)
from vajra.discovery.mapper import BaseDiscoverer

logger = logging.getLogger(__name__)

_PRIVILEGED_ACTIONS: frozenset[str] = frozenset(
    {
        "ram:AssumeRole",
        "oss:PutObject",
        "oss:GetObject",
        "oss:*",
        "ecs:*",
        "kms:Decrypt",
    }
)

_ASSUME_ACTIONS: frozenset[str] = frozenset(
    {
        "ram:AssumeRole",
        "sts:AssumeRole",
    }
)


class AlibabaDiscoverer(BaseDiscoverer):
    """Discovers Alibaba Cloud assets and builds edges."""

    provider = "alibaba"

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._assets: dict[str, CloudAsset] = {}

    def discover(self) -> list[CloudAsset]:
        """Discover Alibaba Cloud assets from CloudQuery."""
        from vajra.data.cloudquery_adapter import CloudQueryAdapter

        adapter = CloudQueryAdapter(self._db_path)
        raw_assets = adapter.load_assets()

        classified: list[CloudAsset] = []
        for asset in raw_assets:
            if asset.provider != "alibaba":
                continue
            classified_asset = self._classify(asset)
            self._assets[classified_asset.id] = classified_asset
            classified.append(classified_asset)

        logger.info(
            "Alibaba discovery: %d assets",
            len(classified),
        )
        return classified

    def _classify(self, asset: CloudAsset) -> CloudAsset:
        """Classify Alibaba asset."""
        is_entry = asset.asset_type == AssetType.RAM_ROLE
        is_jewel = asset.asset_type == AssetType.OSS_BUCKET

        if not is_entry and not is_jewel:
            return asset

        return CloudAsset(
            id=asset.id,
            name=asset.name,
            asset_type=asset.asset_type,
            provider=asset.provider,
            region=asset.region,
            metadata=asset.metadata,
            is_entry_point=is_entry,
            is_crown_jewel=is_jewel,
        )

    def build_edges(
        self,
        policies: list[dict[str, Any]],
    ) -> list[GraphEdge]:
        """Build edges from Alibaba RAM policies."""
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
        """Convert Alibaba RAM policy to edge.

        Same default-DENY pattern as AWS/Azure/GCP.
        """
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
