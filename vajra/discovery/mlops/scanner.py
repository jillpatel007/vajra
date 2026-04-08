"""MLOps Security Scanner — discovers ML pipeline assets.

Attack chain: internet → training job → poisoned model → production

SageMaker jobs with internet access + no VPC = entry points.
Model registries with public write = crown jewels at risk.
Training data stores = crown jewels (poisoning target).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from vajra.core.models import (
    AssetType,
    CloudAsset,
    EdgeValidity,
    GraphEdge,
    RelationType,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MLPipelineAsset:
    """Metadata for an ML pipeline component."""

    asset_id: str
    asset_name: str
    component_type: str  # training_job, model_registry, endpoint, dataset
    internet_accessible: bool
    vpc_configured: bool
    iam_role: str
    provider: str = "aws"


class MLOpsSecurityScanner:
    """Discovers ML pipeline assets and flags security risks."""

    def __init__(self) -> None:
        self._assets: list[CloudAsset] = []
        self._edges: list[GraphEdge] = []

    def scan_training_jobs(
        self,
        jobs: list[dict[str, Any]],
    ) -> list[CloudAsset]:
        """Discover SageMaker/Vertex training jobs.

        Jobs with internet access and no VPC = entry points.
        """
        assets: list[CloudAsset] = []
        for job in jobs:
            internet = job.get("internet_accessible", False)
            vpc = job.get("vpc_configured", False)

            # Internet + no VPC = entry point (attacker reachable)
            is_entry = internet and not vpc

            asset = CloudAsset(
                id=job.get("id", ""),
                name=job.get("name", ""),
                asset_type=AssetType.ML_TRAINING_JOB,
                provider=job.get("provider", "aws"),
                region=job.get("region", "us-east-1"),
                is_entry_point=is_entry,
                metadata={
                    "internet_accessible": internet,
                    "vpc_configured": vpc,
                    "iam_role": job.get("iam_role", ""),
                },
            )
            assets.append(asset)
            self._assets.append(asset)

        logger.info("MLOps: %d training jobs scanned", len(assets))
        return assets

    def scan_model_registries(
        self,
        registries: list[dict[str, Any]],
    ) -> list[CloudAsset]:
        """Discover model registries (who can push models)."""
        assets: list[CloudAsset] = []
        for reg in registries:
            public_write = reg.get("public_write", False)

            asset = CloudAsset(
                id=reg.get("id", ""),
                name=reg.get("name", ""),
                asset_type=AssetType.ML_MODEL,
                provider=reg.get("provider", "aws"),
                region=reg.get("region", "us-east-1"),
                is_crown_jewel=True,  # Models are crown jewels
                metadata={"public_write": public_write},
            )
            assets.append(asset)
            self._assets.append(asset)

        return assets

    def scan_datasets(
        self,
        datasets: list[dict[str, Any]],
    ) -> list[CloudAsset]:
        """Discover training datasets (poisoning targets)."""
        assets: list[CloudAsset] = []
        for ds in datasets:
            asset = CloudAsset(
                id=ds.get("id", ""),
                name=ds.get("name", ""),
                asset_type=AssetType.DATASET,
                provider=ds.get("provider", "aws"),
                region=ds.get("region", "us-east-1"),
                is_crown_jewel=True,  # Training data = crown jewel
            )
            assets.append(asset)
            self._assets.append(asset)

        return assets

    def build_ml_edges(
        self,
        job_to_role: dict[str, str],
        job_to_dataset: dict[str, str],
        existing_assets: dict[str, CloudAsset],
    ) -> list[GraphEdge]:
        """Build edges for ML pipeline attack paths."""
        edges: list[GraphEdge] = []

        # Training job → IAM role (can_assume)
        for job_id, role_id in job_to_role.items():
            if job_id in existing_assets and role_id in existing_assets:
                edges.append(
                    GraphEdge(
                        source=job_id,
                        target=role_id,
                        relation=RelationType.CAN_ASSUME,
                        risk_weight=0.9,
                        iam_validity=EdgeValidity.VALID,
                    )
                )

        # Training job → dataset (trains_on)
        for job_id, dataset_id in job_to_dataset.items():
            if job_id in existing_assets and dataset_id in existing_assets:
                edges.append(
                    GraphEdge(
                        source=job_id,
                        target=dataset_id,
                        relation=RelationType.TRAINS_ON,
                        risk_weight=0.85,
                        iam_validity=EdgeValidity.VALID,
                    )
                )

        self._edges = edges
        return edges
