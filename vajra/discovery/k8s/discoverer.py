"""Kubernetes Discoverer — RBAC bindings, ServiceAccounts, secrets.

K8s RBAC attack paths:
    ServiceAccount → ClusterRoleBinding → ClusterRole(cluster-admin)
    = total cluster compromise from a single pod.

    Pod with mounted SA token + secret env vars = entry point.
    ClusterRoleBinding to cluster-admin = CRITICAL edge.

Security controls:
    1. ClusterRoleBindings to cluster-admin → risk 0.99
    2. ServiceAccounts with mounted secrets → entry points
    3. Secrets in env vars flagged as credential exposure
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

_CRITICAL_ROLES: frozenset[str] = frozenset(
    {
        "cluster-admin",
        "admin",
        "edit",
    }
)

_SECRET_ENV_PATTERNS: frozenset[str] = frozenset(
    {
        "API_KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "CREDENTIALS",
        "PRIVATE_KEY",
    }
)


class K8sDiscoverer(BaseDiscoverer):
    """Discovers Kubernetes RBAC paths and secret exposure."""

    provider = "k8s"

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._assets: dict[str, CloudAsset] = {}

    def discover(self) -> list[CloudAsset]:
        """Discover K8s assets from CloudQuery scan."""
        from vajra.data.cloudquery_adapter import CloudQueryAdapter

        adapter = CloudQueryAdapter(self._db_path)
        raw_assets = adapter.load_assets()

        classified: list[CloudAsset] = []
        for asset in raw_assets:
            if asset.provider not in ("k8s", "kubernetes"):
                continue
            self._assets[asset.id] = asset
            classified.append(asset)

        logger.info("K8s discovery: %d assets", len(classified))
        return classified

    def discover_from_rbac(
        self,
        service_accounts: list[dict[str, Any]],
        role_bindings: list[dict[str, Any]],
        secrets_in_env: list[dict[str, Any]],
    ) -> tuple[list[CloudAsset], list[GraphEdge]]:
        """Build K8s assets and edges from RBAC data.

        Args:
            service_accounts: K8s ServiceAccount objects.
            role_bindings: ClusterRoleBindings and RoleBindings.
            secrets_in_env: Pod env vars containing secret references.

        Returns:
            Tuple of (assets, edges) ready for VajraGraph.
        """
        assets: list[CloudAsset] = []
        edges: list[GraphEdge] = []

        # Build ServiceAccount assets
        for sa in service_accounts:
            sa_id = sa.get("uid", "")
            sa_name = sa.get("name", "")
            namespace = sa.get("namespace", "default")

            if not sa_id:
                continue

            asset = CloudAsset(
                id=sa_id,
                name=f"{namespace}/{sa_name}",
                asset_type=AssetType.K8S_SERVICE_ACCOUNT,
                provider="aws",  # K8s runs on a cloud provider
                region=namespace,
                is_entry_point=True,
            )
            assets.append(asset)
            self._assets[sa_id] = asset

        # Build ClusterRole assets and edges from bindings
        for binding in role_bindings:
            binding_edges = self._binding_to_edges(binding)
            edges.extend(binding_edges)

        # Flag secrets in env vars
        for secret in secrets_in_env:
            pod_sa = secret.get("service_account_uid", "")
            env_name = secret.get("env_name", "")
            if pod_sa in self._assets and self._has_secret_pattern(
                env_name,
            ):
                logger.warning(
                    "secret exposure: SA %s has %s in env",
                    pod_sa,
                    env_name,
                )

        logger.info(
            "K8s RBAC: %d assets, %d edges",
            len(assets),
            len(edges),
        )
        return assets, edges

    def _binding_to_edges(
        self,
        binding: dict[str, Any],
    ) -> list[GraphEdge]:
        """Convert a RoleBinding/ClusterRoleBinding to edges.

        ClusterRoleBinding to cluster-admin = CRITICAL (0.99).
        """
        subject_uid = binding.get("subject_uid", "")
        role_name = binding.get("role_name", "")
        target_uid = binding.get("target_uid", "")
        binding_type = binding.get("type", "RoleBinding")

        if subject_uid not in self._assets:
            return []

        # Determine risk from role
        if role_name in _CRITICAL_ROLES:
            risk = 0.99
            relation = RelationType.HAS_ACCESS
        elif role_name:
            risk = 0.6
            relation = RelationType.HAS_ACCESS
        else:
            return []  # No role = no edge (default-DENY)

        # ClusterRoleBinding = cluster-wide = higher risk
        if binding_type == "ClusterRoleBinding":
            risk = min(risk * 1.05, 1.0)

        # If target exists as asset, create direct edge
        if target_uid and target_uid in self._assets:
            return [
                GraphEdge(
                    source=subject_uid,
                    target=target_uid,
                    relation=relation,
                    risk_weight=risk,
                    conditions=(
                        f"k8s_role:{role_name}",
                        f"binding_type:{binding_type}",
                    ),
                    iam_validity=EdgeValidity.VALID,
                ),
            ]

        # ClusterRoleBinding without specific target =
        # access to everything (like GCP project-level)
        if binding_type == "ClusterRoleBinding":
            return self._expand_cluster_binding(
                subject_uid,
                role_name,
                risk,
            )

        return []

    def _expand_cluster_binding(
        self,
        subject_uid: str,
        role_name: str,
        risk: float,
    ) -> list[GraphEdge]:
        """Expand cluster-wide binding to all resources."""
        edges: list[GraphEdge] = []
        for asset_id, asset in self._assets.items():
            if asset_id == subject_uid:
                continue
            if asset.asset_type == AssetType.K8S_SERVICE_ACCOUNT:
                continue
            edges.append(
                GraphEdge(
                    source=subject_uid,
                    target=asset_id,
                    relation=RelationType.HAS_ACCESS,
                    risk_weight=risk,
                    conditions=(
                        f"k8s_role:{role_name}",
                        "binding_type:ClusterRoleBinding",
                        "scope:cluster",
                    ),
                    iam_validity=EdgeValidity.VALID,
                ),
            )
        return edges

    @staticmethod
    def _has_secret_pattern(env_name: str) -> bool:
        """Check if env var name matches secret patterns."""
        upper = env_name.upper()
        return any(p in upper for p in _SECRET_ENV_PATTERNS)
