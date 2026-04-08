"""Day 5 Integration Test: Full pipeline end-to-end.

Chains every core component together:
    CloudAsset -> VajraGraph -> add_edge -> find_attack_paths
    -> find_minimum_cut -> sign report -> verify passes
    -> tamper one byte -> verify fails

This is the single test that proves the entire foundation works.
"""

from typing import Any

from vajra.core.graph_engine import VajraGraph
from vajra.core.models import (
    AssetType,
    CloudAsset,
    EdgeValidity,
    GraphEdge,
    NetworkValidity,
    RelationType,
)
from vajra.core.report_signer import sign_report, verify_report

SECRET = "integration-test-secret-key-32b!"  # noqa: S105  # pragma: allowlist secret


def _build_test_graph() -> VajraGraph:
    """Build a small attack graph: internet -> ec2 -> iam_role -> s3_bucket."""
    graph = VajraGraph()

    internet = CloudAsset(
        id="internet-entry",
        name="Public Internet",
        asset_type=AssetType.EC2_INSTANCE,
        provider="aws",
        region="us-east-1",
        is_entry_point=True,
    )
    ec2 = CloudAsset(
        id="ec2-web-server",
        name="Web Server",
        asset_type=AssetType.EC2_INSTANCE,
        provider="aws",
        region="us-east-1",
    )
    iam_role = CloudAsset(
        id="iam-role-admin",
        name="Admin Role",
        asset_type=AssetType.IAM_ROLE,
        provider="aws",
        region="global",
    )
    s3_crown_jewel = CloudAsset(
        id="s3-customer-data",
        name="Customer PII Bucket",
        asset_type=AssetType.S3_BUCKET,
        provider="aws",
        region="us-east-1",
        is_crown_jewel=True,
    )

    for asset in [internet, ec2, iam_role, s3_crown_jewel]:
        graph.add_asset(asset)

    graph.add_edge(
        GraphEdge(
            source="internet-entry",
            target="ec2-web-server",
            relation=RelationType.HAS_ACCESS,
            risk_weight=0.9,
            iam_validity=EdgeValidity.VALID,
            network_validity=NetworkValidity.REACHABLE,
        )
    )
    graph.add_edge(
        GraphEdge(
            source="ec2-web-server",
            target="iam-role-admin",
            relation=RelationType.CAN_ASSUME,
            risk_weight=0.8,
            iam_validity=EdgeValidity.VALID,
            network_validity=NetworkValidity.REACHABLE,
        )
    )
    graph.add_edge(
        GraphEdge(
            source="iam-role-admin",
            target="s3-customer-data",
            relation=RelationType.HAS_ACCESS,
            risk_weight=0.95,
            iam_validity=EdgeValidity.VALID,
            network_validity=NetworkValidity.REACHABLE,
        )
    )
    return graph


def test_full_pipeline_integration() -> None:
    """Chain: build graph -> find paths -> min cut -> sign -> verify -> tamper."""
    # Step 1: Build graph
    graph = _build_test_graph()
    assert graph.verify_integrity()

    # Step 2: Find attack paths
    paths = graph.find_attack_paths()
    assert len(paths) >= 1, "should find at least one attack path"

    # Step 3: Find minimum cut
    min_cut = graph.find_minimum_cut()
    assert len(min_cut.edges_to_cut) >= 1, "should recommend at least one edge to cut"

    # Step 4: Build report payload from analysis
    report_payload: dict[str, Any] = {
        "scan_id": "integration-test-001",
        "attack_paths_found": len(paths),
        "minimum_cut_edges": len(min_cut.edges_to_cut),
        "findings": [
            {
                "path": [e.source + " -> " + e.target for e in path],
                "risk": sum(e.risk_weight for e in path),
            }
            for path in paths
        ],
    }

    # Step 5: Sign the report
    signed = sign_report(report_payload, SECRET)
    assert signed.signature, "signature should not be empty"

    # Step 6: Verify the untampered report
    assert verify_report(signed, SECRET) is True, "clean report should verify"

    # Step 7: Tamper with the report — change one finding
    signed.payload["attack_paths_found"] = 0

    # Step 8: Verify the tampered report FAILS
    assert verify_report(signed, SECRET) is False, "tampered report must fail verify"


def test_constrained_cut_excludes_business_critical() -> None:
    """Verify find_constrained_cut() never selects business_critical nodes."""
    graph = VajraGraph()

    entry = CloudAsset(
        id="entry-point",
        name="Entry",
        asset_type=AssetType.EC2_INSTANCE,
        provider="aws",
        region="us-east-1",
        is_entry_point=True,
    )
    critical_db = CloudAsset(
        id="critical-db",
        name="Production DB",
        asset_type=AssetType.RDS_DATABASE,
        provider="aws",
        region="us-east-1",
        is_business_critical=True,
    )
    crown_jewel = CloudAsset(
        id="crown-jewel",
        name="Secret Data",
        asset_type=AssetType.S3_BUCKET,
        provider="aws",
        region="us-east-1",
        is_crown_jewel=True,
    )

    for asset in [entry, critical_db, crown_jewel]:
        graph.add_asset(asset)

    graph.add_edge(
        GraphEdge(
            source="entry-point",
            target="critical-db",
            relation=RelationType.HAS_ACCESS,
            risk_weight=0.9,
        )
    )
    graph.add_edge(
        GraphEdge(
            source="critical-db",
            target="crown-jewel",
            relation=RelationType.HAS_ACCESS,
            risk_weight=0.9,
        )
    )

    constrained = graph.find_constrained_cut()
    # No edge touching business_critical should be in the cut
    for edge in constrained.edges_to_cut:
        assert (
            edge.source != "critical-db"
        ), "business_critical node should not be cut (source)"
        assert (
            edge.target != "critical-db"
        ), "business_critical node should not be cut (target)"
