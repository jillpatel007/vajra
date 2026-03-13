"""Tests for vajra/core/models.py"""

import pytest

from vajra.core.models import (
    AssetType,
    CloudAsset,
    CrownJewelTier,
    EdgeValidity,
    GraphEdge,
    NetworkValidity,
    RelationType,
)


def test_cloud_asset_creates_correctly() -> None:
    """A CloudAsset can be created with required fields."""
    asset = CloudAsset(
        id="aws-iam-role-123",
        name="DataProcessingRole",
        asset_type=AssetType.IAM_ROLE,
        provider="aws",
        region="us-east-1",
    )
    assert asset.name == "DataPro   cessingRole"
    assert asset.provider == "aws"
    assert asset.is_entry_point is False
    assert asset.is_crown_jewel is False


def test_frozen_asset_cannot_be_modified() -> None:
    """frozen=True must raise an error on any modification attempt."""
    asset = CloudAsset(
        id="aws-iam-role-123",
        name="DataProcessingRole",
        asset_type=AssetType.IAM_ROLE,
        provider="aws",
        region="us-east-1",
    )
    with pytest.raises(ValueError):
        asset.name = "hacked"  # type: ignore[misc]


def test_integrity_hash_changes_when_field_changes() -> None:
    """Different field values must produce different hashes."""
    asset_original = CloudAsset(
        id="aws-iam-role-123",
        name="DataProcessingRole",
        asset_type=AssetType.IAM_ROLE,
        provider="aws",
        region="us-east-1",
        is_crown_jewel=True,
    )
    asset_tampered = CloudAsset(
        id="aws-iam-role-123",
        name="DataProcessingRole",
        asset_type=AssetType.IAM_ROLE,
        provider="aws",
        region="us-east-1",
        is_crown_jewel=False,
    )
    assert asset_original.integrity_hash() != asset_tampered.integrity_hash()


def test_integrity_hash_is_deterministic() -> None:
    """Same asset must always produce the same hash."""
    asset = CloudAsset(
        id="aws-iam-role-123",
        name="DataProcessingRole",
        asset_type=AssetType.IAM_ROLE,
        provider="aws",
        region="us-east-1",
    )
    hash1 = asset.integrity_hash()
    hash2 = asset.integrity_hash()
    assert hash1 == hash2


def test_graph_edge_exploitable_only_when_both_valid() -> None:
    """Edge is exploitable only when BOTH IAM and network allow it."""
    edge_exploitable = GraphEdge(
        source="ec2-123",
        target="iam-role-456",
        relation=RelationType.CAN_ASSUME,
        risk_weight=0.9,
        iam_validity=EdgeValidity.VALID,
        network_validity=NetworkValidity.REACHABLE,
    )
    assert edge_exploitable.is_exploitable is True

    edge_network_blocked = GraphEdge(
        source="ec2-123",
        target="iam-role-456",
        relation=RelationType.CAN_ASSUME,
        risk_weight=0.9,
        iam_validity=EdgeValidity.VALID,
        network_validity=NetworkValidity.BLOCKED,
    )
    assert edge_network_blocked.is_exploitable is False

    edge_iam_blocked = GraphEdge(
        source="ec2-123",
        target="iam-role-456",
        relation=RelationType.CAN_ASSUME,
        risk_weight=0.9,
        iam_validity=EdgeValidity.CONDITION_BLOCKED,
        network_validity=NetworkValidity.REACHABLE,
    )
    assert edge_iam_blocked.is_exploitable is False


def test_crown_jewel_tier_set_correctly() -> None:
    """Crown jewel tier must be stored and retrievable."""
    asset = CloudAsset(
        id="aws-rds-payments",
        name="PaymentsDatabase",
        asset_type=AssetType.RDS_DATABASE,
        provider="aws",
        region="us-east-1",
        is_crown_jewel=True,
        crown_jewel_tier=CrownJewelTier.CRITICAL,
    )
    assert asset.is_crown_jewel is True
    assert asset.crown_jewel_tier == CrownJewelTier.CRITICAL
