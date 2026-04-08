"""Tests for Network Reachability Checker.

PDF Day 8 requirements:
    - Verify network_validity=BLOCKED on edge to private-subnet resource
    - Verify is_exploitable=False when network blocks even if IAM allows
    - Network/IAM intersection correct
"""

from vajra.analysis.network_reachability import (
    NetworkReachabilityChecker,
)
from vajra.core.models import (
    AssetType,
    CloudAsset,
    EdgeValidity,
    GraphEdge,
    NetworkValidity,
    RelationType,
)


def _make_asset(
    asset_id: str,
    provider: str = "aws",
) -> CloudAsset:
    return CloudAsset(
        id=asset_id,
        name=asset_id,
        asset_type=AssetType.EC2_INSTANCE,
        provider=provider,
        region="us-east-1",
    )


def test_same_vpc_reachable() -> None:
    """Two assets in same VPC → REACHABLE."""
    checker = NetworkReachabilityChecker(
        network_config={
            "vpc_map": {"ec2-a": "vpc-1", "ec2-b": "vpc-1"},
        }
    )
    result = checker.check(_make_asset("ec2-a"), _make_asset("ec2-b"))
    assert result.validity == NetworkValidity.REACHABLE


def test_different_vpc_no_peering_blocked() -> None:
    """Different VPCs, no peering → BLOCKED.

    This is the key FP reduction test. IAM may allow access,
    but if packets can't reach, it's not exploitable.
    """
    checker = NetworkReachabilityChecker(
        network_config={
            "vpc_map": {"ec2-a": "vpc-1", "rds-b": "vpc-2"},
            "vpc_peerings": [],
        }
    )
    result = checker.check(_make_asset("ec2-a"), _make_asset("rds-b"))
    assert result.validity == NetworkValidity.BLOCKED


def test_peered_vpcs_reachable() -> None:
    """VPCs with active peering → REACHABLE."""
    checker = NetworkReachabilityChecker(
        network_config={
            "vpc_map": {"ec2-a": "vpc-1", "rds-b": "vpc-2"},
            "vpc_peerings": [{"vpc_a": "vpc-1", "vpc_b": "vpc-2"}],
        }
    )
    result = checker.check(_make_asset("ec2-a"), _make_asset("rds-b"))
    assert result.validity == NetworkValidity.REACHABLE


def test_no_vpc_data_unknown() -> None:
    """No VPC data → UNKNOWN (conservative, not REACHABLE)."""
    checker = NetworkReachabilityChecker(network_config={})
    result = checker.check(_make_asset("ec2-a"), _make_asset("rds-b"))
    assert result.validity == NetworkValidity.UNKNOWN


def test_security_group_blocks() -> None:
    """Same VPC but security group denies → BLOCKED."""
    checker = NetworkReachabilityChecker(
        network_config={
            "vpc_map": {"ec2-a": "vpc-1", "rds-b": "vpc-1"},
            "security_groups": {
                "rds-b": [{"action": "deny", "source": "*"}],
            },
        }
    )
    result = checker.check(_make_asset("ec2-a"), _make_asset("rds-b"))
    assert result.validity == NetworkValidity.BLOCKED


def test_iam_valid_network_blocked_not_exploitable() -> None:
    """IAM allows but network blocks → NOT exploitable.

    This is THE test that proves the Day 8 concept:
    permission existing ≠ being exploitable.
    """
    edge = GraphEdge(
        source="ec2-a",
        target="rds-b",
        relation=RelationType.HAS_ACCESS,
        risk_weight=0.9,
        iam_validity=EdgeValidity.VALID,
        network_validity=NetworkValidity.BLOCKED,
    )
    assert edge.is_exploitable is False


def test_both_valid_is_exploitable() -> None:
    """IAM valid AND network reachable → exploitable."""
    edge = GraphEdge(
        source="ec2-a",
        target="rds-b",
        relation=RelationType.HAS_ACCESS,
        risk_weight=0.9,
        iam_validity=EdgeValidity.VALID,
        network_validity=NetworkValidity.REACHABLE,
    )
    assert edge.is_exploitable is True


def test_alibaba_asset_reachability() -> None:
    """Verify Alibaba RAM role works with reachability checker."""
    checker = NetworkReachabilityChecker(
        network_config={
            "vpc_map": {"ram-role": "vpc-cn", "oss-bucket": "vpc-cn"},
        }
    )
    ram = CloudAsset(
        id="ram-role",
        name="admin-role",
        asset_type=AssetType.RAM_ROLE,
        provider="alibaba",
        region="cn-hangzhou",
    )
    oss = CloudAsset(
        id="oss-bucket",
        name="data-bucket",
        asset_type=AssetType.OSS_BUCKET,
        provider="alibaba",
        region="cn-hangzhou",
    )
    result = checker.check(ram, oss)
    assert result.validity == NetworkValidity.REACHABLE
