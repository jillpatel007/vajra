"""Tests for AWS Discoverer — edge building and classification.

Proves:
    1. Only "Allow" effect creates edges (Deny = no edge)
    2. Case canonicalization blocks "allow" bypass (Jill's fix)
    3. Unknown actions produce no edges
    4. AssumeRole → CAN_ASSUME with risk 0.9
    5. Data access → HAS_ACCESS with risk 0.8
    6. Both principal and resource must exist in discovered assets
    7. Conditions are extracted for Cedar evaluation
"""

from pathlib import Path

from vajra.core.models import (
    AssetType,
    CloudAsset,
    RelationType,
)
from vajra.discovery.aws.discoverer import AWSDiscoverer


def _make_discoverer_with_assets() -> AWSDiscoverer:
    """Create a discoverer with pre-loaded test assets."""
    disc = AWSDiscoverer(db_path=Path("fake.duckdb"))
    # Manually populate assets (bypass CloudQuery for unit test)
    disc._assets = {
        "arn:aws:iam::123:role/WebServer": CloudAsset(
            id="arn:aws:iam::123:role/WebServer",
            name="WebServer",
            asset_type=AssetType.IAM_ROLE,
            provider="aws",
            region="us-east-1",
            is_entry_point=True,
        ),
        "arn:aws:iam::123:role/Admin": CloudAsset(
            id="arn:aws:iam::123:role/Admin",
            name="Admin",
            asset_type=AssetType.IAM_ROLE,
            provider="aws",
            region="us-east-1",
        ),
        "arn:aws:s3:::customer-data": CloudAsset(
            id="arn:aws:s3:::customer-data",
            name="customer-data",
            asset_type=AssetType.S3_BUCKET,
            provider="aws",
            region="us-east-1",
            is_crown_jewel=True,
        ),
    }
    return disc


def test_allow_creates_edge() -> None:
    """Allow + AssumeRole → edge with CAN_ASSUME."""
    disc = _make_discoverer_with_assets()
    policy = {
        "effect": "Allow",
        "principal": "arn:aws:iam::123:role/WebServer",
        "action": ["sts:AssumeRole"],
        "resource": "arn:aws:iam::123:role/Admin",
        "conditions": {},
    }
    edge = disc._policy_to_edge(policy)
    assert edge is not None
    assert edge.relation == RelationType.CAN_ASSUME
    assert edge.risk_weight == 0.9


def test_deny_creates_no_edge() -> None:
    """Deny effect → no edge created."""
    disc = _make_discoverer_with_assets()
    policy = {
        "effect": "Deny",
        "principal": "arn:aws:iam::123:role/WebServer",
        "action": ["sts:AssumeRole"],
        "resource": "arn:aws:iam::123:role/Admin",
        "conditions": {},
    }
    edge = disc._policy_to_edge(policy)
    assert edge is None


def test_lowercase_allow_blocked() -> None:
    """Lowercase 'allow' bypass attempt → blocked by canonicalization.

    Jill's fix: effect.strip().upper() normalizes all case variants.
    """
    disc = _make_discoverer_with_assets()
    policy = {
        "effect": "allow",
        "principal": "arn:aws:iam::123:role/WebServer",
        "action": ["sts:AssumeRole"],
        "resource": "arn:aws:iam::123:role/Admin",
        "conditions": {},
    }
    edge = disc._policy_to_edge(policy)
    # Should create an edge — "allow" normalizes to "ALLOW"
    assert edge is not None


def test_whitespace_allow_blocked() -> None:
    """Whitespace-padded ' Allow ' → handled by strip()."""
    disc = _make_discoverer_with_assets()
    policy = {
        "effect": "  Allow  ",
        "principal": "arn:aws:iam::123:role/WebServer",
        "action": ["sts:AssumeRole"],
        "resource": "arn:aws:iam::123:role/Admin",
        "conditions": {},
    }
    edge = disc._policy_to_edge(policy)
    assert edge is not None


def test_data_access_creates_has_access_edge() -> None:
    """S3 GetObject → HAS_ACCESS with risk 0.8."""
    disc = _make_discoverer_with_assets()
    policy = {
        "effect": "Allow",
        "principal": "arn:aws:iam::123:role/Admin",
        "action": ["s3:GetObject"],
        "resource": "arn:aws:s3:::customer-data",
        "conditions": {},
    }
    edge = disc._policy_to_edge(policy)
    assert edge is not None
    assert edge.relation == RelationType.HAS_ACCESS
    assert edge.risk_weight == 0.8


def test_unknown_principal_no_edge() -> None:
    """Principal not in discovered assets → no edge."""
    disc = _make_discoverer_with_assets()
    policy = {
        "effect": "Allow",
        "principal": "arn:aws:iam::999:role/Unknown",
        "action": ["sts:AssumeRole"],
        "resource": "arn:aws:iam::123:role/Admin",
        "conditions": {},
    }
    edge = disc._policy_to_edge(policy)
    assert edge is None


def test_unknown_action_no_edge() -> None:
    """Action not in our known sets → no edge."""
    disc = _make_discoverer_with_assets()
    policy = {
        "effect": "Allow",
        "principal": "arn:aws:iam::123:role/WebServer",
        "action": ["ec2:DescribeInstances"],
        "resource": "arn:aws:iam::123:role/Admin",
        "conditions": {},
    }
    edge = disc._policy_to_edge(policy)
    assert edge is None


def test_conditions_extracted() -> None:
    """IAM conditions are extracted as tuple for Cedar evaluation."""
    disc = _make_discoverer_with_assets()
    policy = {
        "effect": "Allow",
        "principal": "arn:aws:iam::123:role/WebServer",
        "action": ["sts:AssumeRole"],
        "resource": "arn:aws:iam::123:role/Admin",
        "conditions": {
            "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
        },
    }
    edge = disc._policy_to_edge(policy)
    assert edge is not None
    assert len(edge.conditions) == 1
    assert "IpAddress" in edge.conditions[0]


def test_build_edges_filters_correctly() -> None:
    """build_edges() processes multiple policies and filters correctly."""
    disc = _make_discoverer_with_assets()
    policies = [
        {
            "effect": "Allow",
            "principal": "arn:aws:iam::123:role/WebServer",
            "action": ["sts:AssumeRole"],
            "resource": "arn:aws:iam::123:role/Admin",
            "conditions": {},
        },
        {
            "effect": "Deny",
            "principal": "arn:aws:iam::123:role/WebServer",
            "action": ["sts:AssumeRole"],
            "resource": "arn:aws:iam::123:role/Admin",
            "conditions": {},
        },
        {
            "effect": "Allow",
            "principal": "arn:aws:iam::123:role/Admin",
            "action": ["s3:GetObject"],
            "resource": "arn:aws:s3:::customer-data",
            "conditions": {},
        },
    ]
    edges = disc.build_edges(policies)
    assert len(edges) == 2
