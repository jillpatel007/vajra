"""AWS Discoverer — pulls assets from CloudQuery DuckDB and builds edges.

Pipeline:
    CloudQuery scans AWS → DuckDB → this discoverer reads it
    → creates CloudAsset nodes + GraphEdge relationships
    → feeds into VajraGraph for attack path analysis

Security controls (from Forge 1 threat model):
    1. All data flows through CloudQueryAdapter (sanitised + integrity-checked)
    2. Edge conditions go through Cedar evaluator (default-DENY)
    3. Entry points and crown jewels are classified by heuristics, not trusted data
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

# ---------------------------------------------------------------------------
# Heuristics for classification
# ---------------------------------------------------------------------------
# Why heuristics? We can't trust cloud metadata to tell us what's critical.
# An attacker could rename a bucket "not-important-ignore-me".
# Instead, we look at structural signals: type + patterns.

_ENTRY_POINT_TYPES: frozenset[AssetType] = frozenset(
    {
        AssetType.EC2_INSTANCE,
        AssetType.LAMBDA_FUNCTION,
    }
)

_CROWN_JEWEL_TYPES: frozenset[AssetType] = frozenset(
    {
        AssetType.S3_BUCKET,
        AssetType.RDS_DATABASE,
        AssetType.SECRET,
    }
)

# IAM patterns that signal dangerous relationships
_ASSUME_ROLE_ACTIONS: frozenset[str] = frozenset(
    {
        "sts:AssumeRole",
        "sts:AssumeRoleWithSAML",
        "sts:AssumeRoleWithWebIdentity",
    }
)

_DATA_ACCESS_ACTIONS: frozenset[str] = frozenset(
    {
        "s3:GetObject",
        "s3:PutObject",
        "s3:*",
        "rds:*",
        "rds-db:connect",
        "secretsmanager:GetSecretValue",
    }
)


class AWSDiscoverer(BaseDiscoverer):
    """Discovers AWS assets and builds edges from IAM relationships.

    Auto-registered via __init_subclass__ when this module is imported.
    """

    provider = "aws"

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._assets: dict[str, CloudAsset] = {}

    def discover(self) -> list[CloudAsset]:
        """Discover all AWS assets from CloudQuery scan results.

        Uses CloudQueryAdapter for safe data loading,
        then classifies each asset as entry_point or crown_jewel.
        """
        from vajra.data.cloudquery_adapter import CloudQueryAdapter

        adapter = CloudQueryAdapter(self._db_path)
        raw_assets = adapter.load_assets()

        # Filter to AWS only and classify
        classified: list[CloudAsset] = []
        for asset in raw_assets:
            if asset.provider != "aws":
                continue
            classified_asset = self._classify_asset(asset)
            self._assets[classified_asset.id] = classified_asset
            classified.append(classified_asset)

        logger.info("AWS discovery: %d assets classified", len(classified))
        return classified

    def _classify_asset(self, asset: CloudAsset) -> CloudAsset:
        """Classify asset as entry_point or crown_jewel based on type.

        Why we rebuild the asset instead of mutating:
            CloudAsset is frozen (Pydantic ConfigDict(frozen=True)).
            We create a new instance with the classification flags set.
            Immutability = integrity guarantee.
        """
        is_entry = asset.asset_type in _ENTRY_POINT_TYPES
        is_jewel = asset.asset_type in _CROWN_JEWEL_TYPES

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
        iam_policies: list[dict[str, Any]],
    ) -> list[GraphEdge]:
        """Build graph edges from IAM policy statements.

        This is where YOUR security logic goes, Jill.
        The function below needs the critical 5-10 lines that decide:
            - WHICH IAM statements create edges
            - WHAT relation type each edge gets
            - HOW risk weight is calculated

        Args:
            iam_policies: List of IAM policy documents from CloudQuery.
                Each has: principal, action, resource, effect, conditions.

        Returns:
            List of GraphEdge objects ready for VajraGraph.
        """
        edges: list[GraphEdge] = []
        for policy in iam_policies:
            edge = self._policy_to_edge(policy)
            if edge is not None:
                edges.append(edge)
        logger.info(
            "AWS edge building: %d edges from %d policies",
            len(edges),
            len(iam_policies),
        )
        return edges

    def _policy_to_edge(
        self,
        policy: dict[str, Any],
    ) -> GraphEdge | None:
        """Convert a single IAM policy statement to a GraphEdge.

        ┌─────────────────────────────────────────────────────────┐
        │  STUDENT WRITES THIS METHOD — the security decision     │
        │                                                         │
        │  Rules:                                                 │
        │  1. Only "Allow" effect creates edges (Deny = no path)  │
        │  2. AssumeRole actions → CAN_ASSUME relation            │
        │  3. Data access actions → HAS_ACCESS relation           │
        │  4. Risk weight = 0.9 for assume, 0.8 for access        │
        │  5. Extract conditions for Cedar evaluation later        │
        │  6. If principal or resource not in our assets → None    │
        └─────────────────────────────────────────────────────────┘
        """
        effect = policy.get("effect", "")
        principal = policy.get("principal", "")
        actions = policy.get("action", [])
        resource = policy.get("resource", "")
        raw_conditions = policy.get("conditions", {})

        # Canonicalize effect — prevents case-trick bypass (Jill's fix)
        if effect.strip().upper() != "ALLOW":
            return None

        # Both ends must exist in our discovered assets
        if principal not in self._assets or resource not in self._assets:
            return None

        # Determine relation type from action
        relation = None
        risk = 0.5
        for action in actions:
            if action in _ASSUME_ROLE_ACTIONS:
                relation = RelationType.CAN_ASSUME
                risk = 0.9
                break
            if action in _DATA_ACCESS_ACTIONS:
                relation = RelationType.HAS_ACCESS
                risk = 0.8
                break

        if relation is None:
            return None

        # Extract conditions as tuple for Cedar evaluation
        conds = tuple(
            f"{op}:{k}:{v}"
            for op, kvs in raw_conditions.items()
            for k, v in kvs.items()
        )

        return GraphEdge(
            source=principal,
            target=resource,
            relation=relation,
            risk_weight=risk,
            conditions=conds,
            iam_validity=EdgeValidity.ASSUMED_VALID,
        )
