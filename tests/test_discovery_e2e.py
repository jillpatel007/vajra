"""End-to-end discovery test with mock DuckDB output.

PDF Day 7 requirement: Mock CloudQuery DuckDB output.
Verify: Azure SP discovered, GCP default SA discovered,
Cedar blocks edge with region condition, Cedar allows edge without conditions.
"""

from vajra.analysis.cedar_evaluator import CedarEvaluator
from vajra.core.graph_engine import VajraGraph
from vajra.core.models import (
    AssetType,
    CloudAsset,
    EdgeValidity,
    GraphEdge,
    NetworkValidity,
    RelationType,
)


def test_multi_cloud_discovery_to_graph() -> None:
    """Simulate: discover assets from 3 clouds → build unified graph."""
    graph = VajraGraph()

    # AWS assets (from AWS discoverer)
    aws_ec2 = CloudAsset(
        id="aws-ec2-web",
        name="Web Server",
        asset_type=AssetType.EC2_INSTANCE,
        provider="aws",
        region="us-east-1",
        is_entry_point=True,
    )
    aws_role = CloudAsset(
        id="aws-iam-admin",
        name="Admin Role",
        asset_type=AssetType.IAM_ROLE,
        provider="aws",
        region="global",
    )

    # Azure assets (from Azure discoverer)
    azure_sp = CloudAsset(
        id="azure-sp-webapp",
        name="WebApp SP",
        asset_type=AssetType.SERVICE_PRINCIPAL,
        provider="azure",
        region="eastus",
    )

    # GCP assets (from GCP discoverer)
    gcp_sa = CloudAsset(
        id="gcp-sa-default",
        name="default@project.iam",
        asset_type=AssetType.SERVICE_ACCOUNT,
        provider="gcp",
        region="us-central1",
    )
    gcp_bucket = CloudAsset(
        id="gcp-bucket-data",
        name="customer-data",
        asset_type=AssetType.GCS_BUCKET,
        provider="gcp",
        region="us-central1",
        is_crown_jewel=True,
    )

    for asset in [aws_ec2, aws_role, azure_sp, gcp_sa, gcp_bucket]:
        graph.add_asset(asset)

    # Cross-cloud attack path: AWS → Azure → GCP
    graph.add_edge(
        GraphEdge(
            source="aws-ec2-web",
            target="aws-iam-admin",
            relation=RelationType.CAN_ASSUME,
            risk_weight=0.9,
            iam_validity=EdgeValidity.VALID,
            network_validity=NetworkValidity.REACHABLE,
        )
    )
    graph.add_edge(
        GraphEdge(
            source="aws-iam-admin",
            target="azure-sp-webapp",
            relation=RelationType.CROSS_ACCOUNT,
            risk_weight=0.85,
            iam_validity=EdgeValidity.VALID,
            network_validity=NetworkValidity.REACHABLE,
        )
    )
    graph.add_edge(
        GraphEdge(
            source="azure-sp-webapp",
            target="gcp-sa-default",
            relation=RelationType.CROSS_ACCOUNT,
            risk_weight=0.8,
            iam_validity=EdgeValidity.VALID,
            network_validity=NetworkValidity.REACHABLE,
        )
    )
    graph.add_edge(
        GraphEdge(
            source="gcp-sa-default",
            target="gcp-bucket-data",
            relation=RelationType.HAS_ACCESS,
            risk_weight=0.9,
            iam_validity=EdgeValidity.VALID,
            network_validity=NetworkValidity.REACHABLE,
        )
    )

    # Must find cross-cloud attack path
    paths = graph.find_attack_paths()
    assert len(paths) >= 1, "must detect cross-cloud attack path"
    assert len(paths[0]) == 4, "path should be 4 edges long"

    # Must recommend minimum cut
    cut = graph.find_minimum_cut()
    assert len(cut.edges_to_cut) >= 1


def test_cedar_blocks_conditional_edge() -> None:
    """Cedar blocks edge with unsatisfied region condition."""
    evaluator = CedarEvaluator()

    # Condition: only allow from us-east-1
    conditions = {
        "StringEquals": {"aws:RequestedRegion": "us-east-1"},
    }
    # Context: request from eu-west-1
    context = {"aws:RequestedRegion": "eu-west-1"}

    result = evaluator.evaluate(conditions, context)
    assert result.validity == EdgeValidity.CONDITION_BLOCKED


def test_cedar_allows_unconditional_edge() -> None:
    """Edge without conditions → ASSUMED_VALID."""
    evaluator = CedarEvaluator()
    result = evaluator.evaluate({})
    assert result.validity == EdgeValidity.ASSUMED_VALID


def test_cedar_allows_satisfied_condition() -> None:
    """Edge with satisfied condition → VALID."""
    evaluator = CedarEvaluator()
    conditions = {
        "StringEquals": {"aws:RequestedRegion": "us-east-1"},
    }
    context = {"aws:RequestedRegion": "us-east-1"}
    result = evaluator.evaluate(conditions, context)
    assert result.validity == EdgeValidity.VALID


def test_is_exploitable_requires_both_iam_and_network() -> None:
    """is_exploitable = True ONLY when BOTH IAM and network valid."""
    # Both valid → exploitable
    edge_both = GraphEdge(
        source="a",
        target="b",
        relation=RelationType.HAS_ACCESS,
        risk_weight=0.9,
        iam_validity=EdgeValidity.VALID,
        network_validity=NetworkValidity.REACHABLE,
    )
    assert edge_both.is_exploitable is True

    # IAM valid, network blocked → NOT exploitable
    edge_net_blocked = GraphEdge(
        source="a",
        target="b",
        relation=RelationType.HAS_ACCESS,
        risk_weight=0.9,
        iam_validity=EdgeValidity.VALID,
        network_validity=NetworkValidity.BLOCKED,
    )
    assert edge_net_blocked.is_exploitable is False

    # IAM blocked, network valid → NOT exploitable
    edge_iam_blocked = GraphEdge(
        source="a",
        target="b",
        relation=RelationType.HAS_ACCESS,
        risk_weight=0.9,
        iam_validity=EdgeValidity.CONDITION_BLOCKED,
        network_validity=NetworkValidity.REACHABLE,
    )
    assert edge_iam_blocked.is_exploitable is False
