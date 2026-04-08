"""GCP Discoverer — pulls assets from CloudQuery and builds edges.

GCP IAM model differs from AWS and Azure:
    AWS:   Principal → Policy → Action → Resource
    Azure: Service Principal → Role Assignment → Scope
    GCP:   Member → IAM Binding → Role → Resource

KEY GCP CONCEPT — IAM BINDING EXPANSION:
    A binding at project level grants access to EVERY resource in the project.
    Example: roles/owner on project = owns ALL buckets, ALL VMs, ALL service accounts.

    Vajra MUST expand project-level bindings into edges to each resource.
    Missing this = missing the biggest attack paths in GCP.

Security controls (from Forge 1 threat model):
    1. Project-level bindings expanded to all child resources
    2. Cross-cloud edges built for workload identity federation
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

# GCP roles that signal dangerous access
_PRIVILEGED_ROLES: frozenset[str] = frozenset(
    {
        "roles/owner",
        "roles/editor",
        "roles/iam.serviceAccountAdmin",
        "roles/iam.serviceAccountTokenCreator",
        "roles/storage.admin",
        "roles/compute.admin",
    }
)

_IMPERSONATION_ROLES: frozenset[str] = frozenset(
    {
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.serviceAccountUser",
    }
)

_READER_ROLES: frozenset[str] = frozenset(
    {
        "roles/viewer",
        "roles/storage.objectViewer",
        "roles/iam.serviceAccountViewer",
    }
)

_CROWN_JEWEL_TYPES: frozenset[AssetType] = frozenset(
    {
        AssetType.GCS_BUCKET,
    }
)


class GCPDiscoverer(BaseDiscoverer):
    """Discovers GCP assets and builds edges from IAM bindings.

    Auto-registered via __init_subclass__.
    """

    provider = "gcp"

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._assets: dict[str, CloudAsset] = {}

    def discover(self) -> list[CloudAsset]:
        """Discover all GCP assets from CloudQuery scan results."""
        from vajra.data.cloudquery_adapter import CloudQueryAdapter

        adapter = CloudQueryAdapter(self._db_path)
        raw_assets = adapter.load_assets()

        classified: list[CloudAsset] = []
        for asset in raw_assets:
            if asset.provider != "gcp":
                continue
            classified_asset = self._classify_asset(asset)
            self._assets[classified_asset.id] = classified_asset
            classified.append(classified_asset)

        logger.info("GCP discovery: %d assets classified", len(classified))
        return classified

    def _classify_asset(self, asset: CloudAsset) -> CloudAsset:
        """Classify GCP asset as entry_point or crown_jewel."""
        is_entry = asset.asset_type == AssetType.SERVICE_ACCOUNT
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
        iam_bindings: list[dict[str, Any]],
    ) -> list[GraphEdge]:
        """Build graph edges from GCP IAM bindings.

        CRITICAL: project-level bindings are expanded to all
        resources in the project. This is the GCP-specific logic
        that catches the biggest attack paths.

        Args:
            iam_bindings: List of IAM binding dicts from CloudQuery.
                Each has: member, role, resource, scope_level.

        Returns:
            List of GraphEdge objects ready for VajraGraph.
        """
        edges: list[GraphEdge] = []
        for binding in iam_bindings:
            new_edges = self._binding_to_edges(binding)
            edges.extend(new_edges)
        logger.info(
            "GCP edge building: %d edges from %d bindings",
            len(edges),
            len(iam_bindings),
        )
        return edges

    def _binding_to_edges(
        self,
        binding: dict[str, Any],
    ) -> list[GraphEdge]:
        """Convert a single GCP IAM binding to GraphEdge(s).

        ┌─────────────────────────────────────────────────────────┐
        │  STUDENT WRITES THIS METHOD — the expansion logic       │
        │                                                         │
        │  Rules:                                                 │
        │  1. Member must exist in our discovered assets           │
        │  2. Impersonation roles → CAN_ASSUME (priv esc!)       │
        │  3. Privileged roles → HAS_ACCESS, risk 0.9            │
        │  4. Reader roles → READS_FROM, risk 0.4                │
        │  5. Unknown roles → skip (default-DENY)                │
        │  6. If scope_level == "project" → create edge to EVERY │
        │     resource in self._assets from that project          │
        │     This is the GCP binding explosion defense           │
        └─────────────────────────────────────────────────────────┘
        """
        member = binding.get("member", "")
        role = binding.get("role", "")
        resource = binding.get("resource", "")
        scope_level = binding.get("scope_level", "resource")

        if member not in self._assets:
            return []

        # Determine relation and risk from role
        if role in _IMPERSONATION_ROLES:
            relation = RelationType.CAN_ASSUME
            risk = 0.95
        elif role in _PRIVILEGED_ROLES:
            relation = RelationType.HAS_ACCESS
            risk = 0.9
        elif role in _READER_ROLES:
            relation = RelationType.READS_FROM
            risk = 0.4
        else:
            return []  # Unknown role — default-DENY

        # PROJECT-LEVEL BINDING EXPANSION
        # A project binding grants access to ALL resources in that project
        if scope_level == "project":
            return self._expand_project_binding(
                member,
                relation,
                risk,
                role,
            )

        # Resource-level binding — single edge
        if resource not in self._assets:
            return []

        return [
            GraphEdge(
                source=member,
                target=resource,
                relation=relation,
                risk_weight=risk,
                conditions=(f"gcp_role:{role}",),
                iam_validity=EdgeValidity.ASSUMED_VALID,
            ),
        ]

    def _expand_project_binding(
        self,
        member: str,
        relation: RelationType,
        risk: float,
        role: str,
    ) -> list[GraphEdge]:
        """Expand a project-level binding to edges to ALL resources.

        This is the GCP-specific attack: one binding at project level
        gives access to everything. Vajra must model this as individual
        edges to each resource so the graph engine can find all paths.
        """
        edges: list[GraphEdge] = []
        for asset_id, asset in self._assets.items():
            # Don't create self-loops
            if asset_id == member:
                continue
            # Don't create edges to other service accounts
            # (those need explicit impersonation bindings)
            if asset.asset_type == AssetType.SERVICE_ACCOUNT:
                continue
            edges.append(
                GraphEdge(
                    source=member,
                    target=asset_id,
                    relation=relation,
                    risk_weight=min(risk * 1.1, 1.0),  # project = higher risk
                    conditions=(f"gcp_role:{role}", "scope:project"),
                    iam_validity=EdgeValidity.ASSUMED_VALID,
                ),
            )
        if edges:
            logger.info(
                "GCP binding explosion: %s → %d resources via %s",
                member,
                len(edges),
                role,
            )
        return edges
