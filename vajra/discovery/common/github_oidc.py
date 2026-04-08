"""GitHub OIDC Federation — detects cross-cloud trust from CI/CD.

GitHub Actions can assume AWS IAM roles via OIDC federation
WITHOUT storing secrets. The trust relationship is:

    GitHub Workflow → (OIDC token) → AWS IAM Role → cloud resources

This creates a cross-cloud attack path:
    GitHub (compromised repo/workflow) → AWS → Azure → GCP

Vajra detects these OIDC trust relationships and creates
CROSS_ACCOUNT edges in the attack graph.

The full cross-cloud path:
    GITHUB_WORKFLOW → AWS_IAM_ROLE → AZURE_SP → GCP_SA → crown jewel
"""

from __future__ import annotations

import logging
from typing import Any

from vajra.core.models import (
    AssetType,
    CloudAsset,
    EdgeValidity,
    GraphEdge,
    RelationType,
)

logger = logging.getLogger(__name__)

# OIDC providers that create cross-cloud trust
_OIDC_PROVIDERS: frozenset[str] = frozenset(
    {
        "token.actions.githubusercontent.com",
        "accounts.google.com",
        "login.microsoftonline.com",
        "sts.amazonaws.com",
    }
)


class GitHubOIDCDiscoverer:
    """Detects GitHub OIDC federation trust relationships.

    Scans IAM trust policies for OIDC provider URLs.
    Creates CROSS_ACCOUNT edges from CI/CD to cloud roles.
    """

    def __init__(self) -> None:
        self._workflows: dict[str, CloudAsset] = {}
        self._edges_created: int = 0

    def discover_oidc_trusts(
        self,
        iam_trust_policies: list[dict[str, Any]],
        existing_assets: dict[str, CloudAsset],
    ) -> tuple[list[CloudAsset], list[GraphEdge]]:
        """Find OIDC trust relationships and create cross-cloud edges.

        Args:
            iam_trust_policies: IAM role trust policy documents.
                Each has: role_id, trust_policy (with Principal/Federated).
            existing_assets: Already-discovered assets in the graph.

        Returns:
            Tuple of (new workflow assets, cross-cloud edges).
        """
        assets: list[CloudAsset] = []
        edges: list[GraphEdge] = []

        for policy in iam_trust_policies:
            role_id = policy.get("role_id", "")
            trust = policy.get("trust_policy", {})

            if role_id not in existing_assets:
                continue

            # Check for OIDC federation in trust policy
            federated = trust.get("Principal", {}).get(
                "Federated",
                "",
            )
            if not federated:
                continue

            # Is this a known OIDC provider?
            oidc_provider = self._extract_oidc_provider(federated)
            if not oidc_provider:
                continue

            # Create workflow asset as entry point
            condition = trust.get("Condition", {})
            repo = self._extract_repo(condition)
            workflow_id = f"oidc-{oidc_provider}-{repo or 'unknown'}"

            if workflow_id not in self._workflows:
                workflow = CloudAsset(
                    id=workflow_id,
                    name=f"OIDC: {repo or oidc_provider}",
                    asset_type=AssetType.CICD_PIPELINE,
                    provider="aws",
                    region="global",
                    is_entry_point=True,
                    metadata={
                        "oidc_provider": oidc_provider,
                        "repo": repo or "unknown",
                    },
                )
                assets.append(workflow)
                self._workflows[workflow_id] = workflow

            # Create cross-cloud edge
            edges.append(
                GraphEdge(
                    source=workflow_id,
                    target=role_id,
                    relation=RelationType.CROSS_ACCOUNT,
                    risk_weight=0.9,
                    conditions=(
                        f"oidc:{oidc_provider}",
                        f"repo:{repo or 'any'}",
                    ),
                    iam_validity=EdgeValidity.VALID,
                ),
            )
            self._edges_created += 1

        logger.info(
            "OIDC: %d trust relationships, %d cross-cloud edges",
            len(assets),
            len(edges),
        )
        return assets, edges

    @staticmethod
    def _extract_oidc_provider(federated: str) -> str | None:
        """Extract OIDC provider from federated principal ARN."""
        for provider in _OIDC_PROVIDERS:
            if provider in federated:
                return provider
        return None

    @staticmethod
    def _extract_repo(condition: dict[str, Any]) -> str | None:
        """Extract GitHub repo from OIDC condition."""
        string_like = condition.get(
            "StringLike",
            condition.get("StringEquals", {}),
        )
        sub = str(
            string_like.get(
                "token.actions.githubusercontent.com:sub",
                "",
            )
        )
        if sub and ":" in sub:
            # Format: repo:org/name:ref:refs/heads/main
            parts = sub.split(":")
            if len(parts) >= 2:
                return str(parts[1])
        return None

    @property
    def stats(self) -> dict[str, int]:
        return {
            "workflows": len(self._workflows),
            "edges": self._edges_created,
        }
