"""Azure Discoverer — pulls assets from CloudQuery and builds edges.

Azure IAM model differs from AWS:
    AWS:   Principal → Policy → Action → Resource
    Azure: Service Principal → Role Assignment → Permissions → Scope

SCOPE HIERARCHY (privilege escalation risk):
    Subscription (highest) > Resource Group > Resource (lowest)

    A role at subscription scope grants access to EVERYTHING in that
    subscription. Vajra must treat subscription-scope assignments as
    higher risk than resource-scope assignments.

Security controls (from Forge 1 threat model):
    1. Scope depth validated (subscription vs resource group vs resource)
    2. Cross-cloud edges built for federated identity
    3. All data through CloudQueryAdapter (sanitised + integrity-checked)
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

# Azure scope depth → risk multiplier
# Subscription scope = highest privilege = highest risk
_SCOPE_RISK: dict[str, float] = {
    "subscription": 0.95,
    "resource_group": 0.75,
    "resource": 0.6,
}

# Azure roles that signal dangerous access
_PRIVILEGED_ROLES: frozenset[str] = frozenset(
    {
        "Owner",
        "Contributor",
        "User Access Administrator",
        "Key Vault Administrator",
        "Storage Blob Data Owner",
    }
)

_READER_ROLES: frozenset[str] = frozenset(
    {
        "Reader",
        "Key Vault Reader",
        "Storage Blob Data Reader",
    }
)

_CROWN_JEWEL_TYPES: frozenset[AssetType] = frozenset(
    {
        AssetType.KEY_VAULT,
        AssetType.BLOB_CONTAINER,
    }
)


class AzureDiscoverer(BaseDiscoverer):
    """Discovers Azure assets and builds edges from role assignments.

    Auto-registered via __init_subclass__.
    """

    provider = "azure"

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._assets: dict[str, CloudAsset] = {}

    def discover(self) -> list[CloudAsset]:
        """Discover all Azure assets from CloudQuery scan results."""
        from vajra.data.cloudquery_adapter import CloudQueryAdapter

        adapter = CloudQueryAdapter(self._db_path)
        raw_assets = adapter.load_assets()

        classified: list[CloudAsset] = []
        for asset in raw_assets:
            if asset.provider != "azure":
                continue
            classified_asset = self._classify_asset(asset)
            self._assets[classified_asset.id] = classified_asset
            classified.append(classified_asset)

        logger.info("Azure discovery: %d assets classified", len(classified))
        return classified

    def _classify_asset(self, asset: CloudAsset) -> CloudAsset:
        """Classify Azure asset as entry_point or crown_jewel."""
        is_entry = asset.asset_type == AssetType.SERVICE_PRINCIPAL
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

    @staticmethod
    def _parse_scope_depth(scope: str) -> str:
        """Determine scope level from Azure scope string.

        Azure scopes look like:
            /subscriptions/{id}                          → subscription
            /subscriptions/{id}/resourceGroups/{name}    → resource_group
            /subscriptions/{id}/resourceGroups/{name}/providers/... → resource

        Higher scope = more privilege = more risk.
        """
        scope_clean = scope.strip().strip("/").lower()
        parts = scope_clean.split("/")

        if len(parts) <= 2:
            return "subscription"
        if len(parts) <= 4:
            return "resource_group"
        return "resource"

    def build_edges(
        self,
        role_assignments: list[dict[str, Any]],
    ) -> list[GraphEdge]:
        """Build graph edges from Azure role assignments.

        Args:
            role_assignments: List of role assignment dicts from CloudQuery.
                Each has: principal_id, role_name, scope, resource_id.

        Returns:
            List of GraphEdge objects ready for VajraGraph.
        """
        edges: list[GraphEdge] = []
        for assignment in role_assignments:
            edge = self._assignment_to_edge(assignment)
            if edge is not None:
                edges.append(edge)
        logger.info(
            "Azure edge building: %d edges from %d assignments",
            len(edges),
            len(role_assignments),
        )
        return edges

    def _assignment_to_edge(
        self,
        assignment: dict[str, Any],
    ) -> GraphEdge | None:
        """Convert a single Azure role assignment to a GraphEdge.

        ┌─────────────────────────────────────────────────────────┐
        │  STUDENT WRITES THIS METHOD — the security decision     │
        │                                                         │
        │  Rules:                                                 │
        │  1. Both principal and resource must be in our assets    │
        │  2. Privileged roles → HAS_ACCESS, risk from scope      │
        │  3. Reader roles → READS_FROM, lower risk               │
        │  4. Unknown roles → skip (don't assume safe)            │
        │  5. Scope depth determines risk weight                  │
        │  6. Subscription scope = highest risk (0.95)            │
        └─────────────────────────────────────────────────────────┘
        """
        principal_id = assignment.get("principal_id", "")
        role_name = assignment.get("role_name", "")
        scope = assignment.get("scope", "")
        resource_id = assignment.get("resource_id", "")

        # Both ends must exist in discovered assets
        if principal_id not in self._assets:
            return None
        if resource_id not in self._assets:
            return None

        # Determine relation and risk from role type + scope
        scope_depth = self._parse_scope_depth(scope)
        base_risk = _SCOPE_RISK.get(scope_depth, 0.5)

        if role_name in _PRIVILEGED_ROLES:
            relation = RelationType.HAS_ACCESS
            risk = base_risk
        elif role_name in _READER_ROLES:
            relation = RelationType.READS_FROM
            risk = base_risk * 0.5
        else:
            # Unknown role — don't create edge (default-DENY)
            return None

        return GraphEdge(
            source=principal_id,
            target=resource_id,
            relation=relation,
            risk_weight=risk,
            conditions=(f"scope:{scope_depth}",),
            iam_validity=EdgeValidity.ASSUMED_VALID,
        )
