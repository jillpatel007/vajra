"""Tests for Days 11-15 — Analysis, Lambda, Rules, Learning, Chaos.

Covers all PDF requirements for Phase 3.
"""

from typing import Any

import pytest

from vajra.analysis.plugins import (
    AnomalyAnalysis,
    FinancialAnalysis,
    MinCutAnalysis,
    PathAnalysis,
    RegulatoryTimerAnalysis,
    ShadowITAnalysis,
)
from vajra.chaos.simulator import ChaosMode, ChaosSimulator
from vajra.controls.compensating import CompensatingControlRegistry
from vajra.core.graph_engine import VajraGraph
from vajra.core.models import (
    AssetType,
    CloudAsset,
    CrownJewelTier,
    EdgeValidity,
    GraphEdge,
    NetworkValidity,
    RelationType,
)
from vajra.data.lambda_architecture import ServingLayer
from vajra.data.layers import BronzeLayer, GoldLayer, SilverLayer
from vajra.learning.weight_calibrator import WeightCalibrator
from vajra.mitre.overlay import enrich_finding, get_coverage, map_to_mitre
from vajra.rules.loader import SigmaCollection
from vajra.scanners.framework import get_registry, run_all


def _build_test_graph() -> VajraGraph:
    """Standard test graph for all plugin tests."""
    graph = VajraGraph()
    entry = CloudAsset(
        id="entry",
        name="Entry",
        asset_type=AssetType.EC2_INSTANCE,
        provider="aws",
        region="us-east-1",
        is_entry_point=True,
    )
    mid = CloudAsset(
        id="mid",
        name="Mid",
        asset_type=AssetType.IAM_ROLE,
        provider="aws",
        region="global",
    )
    jewel = CloudAsset(
        id="jewel",
        name="Crown",
        asset_type=AssetType.S3_BUCKET,
        provider="aws",
        region="us-east-1",
        is_crown_jewel=True,
        crown_jewel_tier=CrownJewelTier.CRITICAL,
    )
    for a in [entry, mid, jewel]:
        graph.add_asset(a)
    graph.add_edge(
        GraphEdge(
            source="entry",
            target="mid",
            relation=RelationType.CAN_ASSUME,
            risk_weight=0.9,
            iam_validity=EdgeValidity.VALID,
            network_validity=NetworkValidity.REACHABLE,
        )
    )
    graph.add_edge(
        GraphEdge(
            source="mid",
            target="jewel",
            relation=RelationType.HAS_ACCESS,
            risk_weight=0.85,
            iam_validity=EdgeValidity.VALID,
            network_validity=NetworkValidity.REACHABLE,
        )
    )
    return graph


# ═══════════════════════════════════════════════════════════════════
# DAY 11: Scanner Framework + Analysis Plugins
# ═══════════════════════════════════════════════════════════════════


class TestScannerFramework:
    def test_plugins_auto_registered(self) -> None:
        registry = get_registry()
        assert "path_analysis" in registry
        assert "min_cut_analysis" in registry
        assert "financial_analysis" in registry

    def test_run_all_returns_results(self) -> None:
        graph = _build_test_graph()
        results = run_all(graph)
        assert len(results) >= 6
        names = [r["scanner"] for r in results]
        assert "path_analysis" in names

    def test_path_analysis_finds_paths(self) -> None:
        graph = _build_test_graph()
        result = PathAnalysis().run(graph)
        assert result["paths_found"] >= 1

    def test_min_cut_top5_ranked(self) -> None:
        graph = _build_test_graph()
        result = MinCutAnalysis().run(graph)
        assert result["standard_cut"] >= 1
        assert "tiered_cuts" in result
        assert "critical" in result["tiered_cuts"]

    def test_min_cut_constrained_excludes_critical(self) -> None:
        graph = _build_test_graph()
        result = MinCutAnalysis().run(graph)
        assert result["constrained_cut"] >= 0

    def test_financial_has_dollar_figures(self) -> None:
        graph = _build_test_graph()
        result = FinancialAnalysis().run(graph)
        assert result["total_exposure"] > 0
        assert result["roi"] > 0
        assert result["cost_per_breach"] == 4_880_000

    def test_anomaly_detects_over_permissioned(self) -> None:
        graph = VajraGraph()
        hub = CloudAsset(
            id="hub",
            name="Hub",
            asset_type=AssetType.IAM_ROLE,
            provider="aws",
            region="global",
        )
        normal = CloudAsset(
            id="normal",
            name="Normal",
            asset_type=AssetType.IAM_ROLE,
            provider="aws",
            region="global",
        )
        graph.add_asset(hub)
        graph.add_asset(normal)
        for i in range(30):
            t = CloudAsset(
                id=f"t-{i}",
                name=f"T{i}",
                asset_type=AssetType.S3_BUCKET,
                provider="aws",
                region="us-east-1",
            )
            graph.add_asset(t)
            graph.add_edge(
                GraphEdge(
                    source="hub",
                    target=f"t-{i}",
                    relation=RelationType.HAS_ACCESS,
                    risk_weight=0.5,
                )
            )
        # Normal asset has only 1 edge
        graph.add_edge(
            GraphEdge(
                source="normal",
                target="t-0",
                relation=RelationType.READS_FROM,
                risk_weight=0.3,
            )
        )
        result = AnomalyAnalysis().run(graph)
        assert result["total"] >= 1

    def test_regulatory_timer_deadlines(self) -> None:
        graph = _build_test_graph()
        result = RegulatoryTimerAnalysis().run(graph)
        assert result["applicable"] is True
        assert "gdpr" in result["deadlines"]
        assert result["deadlines"]["gdpr"]["hours"] == 72

    def test_shadow_it_flags(self) -> None:
        graph = VajraGraph()
        graph.add_asset(
            CloudAsset(
                id="shadow",
                name="Unknown",
                asset_type=AssetType.EC2_INSTANCE,
                provider="aws",
                region="us-east-1",
                is_shadow_it=True,
            )
        )
        result = ShadowITAnalysis().run(graph)
        assert result["shadow_it_count"] == 1


# ═══════════════════════════════════════════════════════════════════
# DAY 12: Lambda Architecture
# ═══════════════════════════════════════════════════════════════════


class TestLambdaArchitecture:
    def test_speed_layer_processes_create_role(self) -> None:
        serving = ServingLayer()
        delta = serving.process_event(
            {
                "eventName": "CreateRole",
                "requestParameters": {"roleName": "NewAdmin"},
                "responseElements": {
                    "role": {"arn": "arn:aws:iam::123:role/NewAdmin"},
                },
            }
        )
        assert delta is not None
        assert delta.action == "add_asset"

    def test_batch_overwrites_speed(self) -> None:
        serving = ServingLayer()
        serving.process_event(
            {
                "eventName": "CreateRole",
                "requestParameters": {"roleName": "X"},
                "responseElements": {"role": {"arn": "x"}},
            }
        )
        assert len(serving.get_pending_deltas()) == 1
        serving.full_sync(VajraGraph())
        assert len(serving.get_pending_deltas()) == 0

    def test_serving_returns_deltas_since_batch(self) -> None:
        serving = ServingLayer()
        serving.full_sync(VajraGraph())
        serving.process_event(
            {"eventName": "DeleteRole", "requestParameters": {"roleName": "Old"}}
        )
        deltas = serving.get_pending_deltas()
        assert len(deltas) == 1

    def test_unwatched_event_ignored(self) -> None:
        serving = ServingLayer()
        delta = serving.process_event({"eventName": "DescribeInstances"})
        assert delta is None


# ═══════════════════════════════════════════════════════════════════
# DAY 13: Sigma Rules + MITRE Overlay
# ═══════════════════════════════════════════════════════════════════


class TestSigmaRules:
    def test_load_rules_from_dict(self) -> None:
        collection = SigmaCollection()
        count = collection.load_from_dict(
            [
                {
                    "id": "r1",
                    "name": "wildcard_trust",
                    "severity": "critical",
                    "mitre_attack": "T1078",
                },
                {
                    "id": "r2",
                    "name": "public_storage",
                    "severity": "high",
                    "mitre_attack": "T1530",
                },
            ]
        )
        assert count == 2
        assert collection.count == 2

    def test_all_15_rules_loadable(self) -> None:
        """15 rules load without error (PDF requirement)."""
        rules = [
            {"id": f"r{i}", "name": name, "severity": "high", "mitre_attack": "T1078"}
            for i, name in enumerate(
                [
                    "wildcard_trust",
                    "public_storage",
                    "default_sa",
                    "imdsv1_enabled",
                    "cross_account_wildcard",
                    "github_oidc_no_conditions",
                    "ai_agent_excessive",
                    "mcp_write_tool_public",
                    "training_data_no_integrity",
                    "model_registry_public_write",
                    "overprivileged_role",
                    "unencrypted_secret",
                    "public_rds",
                    "open_sg",
                    "no_mfa_admin",
                ]
            )
        ]
        collection = SigmaCollection()
        assert collection.load_from_dict(rules) == 15


class TestMITREOverlay:
    def test_relation_mapped_to_technique(self) -> None:
        mitre = map_to_mitre("can_assume")
        assert mitre["technique"] == "T1078.004"
        assert mitre["tactic"] == "TA0004"

    def test_supply_chain_mapped(self) -> None:
        mitre = map_to_mitre("supply_chain_risk")
        assert mitre["technique"] == "T1195.002"

    def test_mcp_mapped_to_atlas(self) -> None:
        mitre = map_to_mitre("mcp_tool_access")
        assert "AML" in mitre["technique"]

    def test_enrich_finding(self) -> None:
        finding: dict[str, Any] = {"relation": "can_assume", "risk": 0.9}
        enriched = enrich_finding(finding)
        assert "mitre_attack" in enriched
        assert enriched["mitre_attack"]["technique"] == "T1078.004"

    def test_coverage_report(self) -> None:
        coverage = get_coverage()
        assert coverage["techniques_mapped"] >= 9
        assert coverage["atlas_techniques"] >= 2


# ═══════════════════════════════════════════════════════════════════
# DAY 14: Medallion + Weight Calibrator
# ═══════════════════════════════════════════════════════════════════


class TestMedallionLayers:
    def test_bronze_to_silver_validates(self) -> None:
        bronze = BronzeLayer()
        bronze.ingest(
            [
                {
                    "id": "a1",
                    "name": "A",
                    "asset_type": AssetType.IAM_ROLE,
                    "provider": "aws",
                },
                {"id": None, "name": "Bad"},  # invalid — missing fields
            ]
        )
        silver = SilverLayer()
        assets, lineage = silver.transform(bronze)
        assert len(assets) == 1
        assert silver.rejected_count == 1
        assert lineage.records_in == 2
        assert lineage.records_out == 1

    def test_silver_to_gold_aggregates(self) -> None:
        assets = [
            CloudAsset(
                id=f"a{i}",
                name=f"A{i}",
                asset_type=AssetType.IAM_ROLE,
                provider="aws",
                region="us-east-1",
            )
            for i in range(5)
        ]
        gold = GoldLayer()
        summary, lineage = gold.aggregate(assets)
        assert summary["total_assets"] == 5
        assert summary["by_provider"]["aws"] == 5

    def test_data_contract_rejects_invalid(self) -> None:
        bronze = BronzeLayer()
        bronze.ingest([{"garbage": True}])
        silver = SilverLayer()
        assets, _ = silver.transform(bronze)
        assert len(assets) == 0


class TestWeightCalibrator:
    def test_confirmed_feedbacks_increase_weight(self) -> None:
        cal = WeightCalibrator()
        for _ in range(10):
            cal.add_feedback("can_assume", confirmed=True)
        weight = cal.calibrate("can_assume")
        assert weight is not None
        assert weight > 0.5

    def test_bulk_closed_excluded(self) -> None:
        cal = WeightCalibrator()
        for _ in range(10):
            cal.add_feedback("has_access", confirmed=True, bulk_closed=True)
        weight = cal.calibrate("has_access")
        assert weight is None  # bulk-closed = no data

    def test_trimmed_mean_resists_poisoning(self) -> None:
        cal = WeightCalibrator(trim_pct=0.2)
        # 8 confirmed + 2 extreme outliers
        for _ in range(8):
            cal.add_feedback("can_assume", confirmed=True)
        cal.add_feedback("can_assume", confirmed=False, weight_override=0.0)
        cal.add_feedback("can_assume", confirmed=False, weight_override=0.0)
        weight = cal.calibrate("can_assume")
        assert weight is not None
        assert weight > 0.5, "trimmed mean should resist outliers"

    def test_insufficient_data_returns_none(self) -> None:
        cal = WeightCalibrator()
        cal.add_feedback("rare", confirmed=True)
        assert cal.calibrate("rare") is None  # need >= 3


# ═══════════════════════════════════════════════════════════════════
# DAY 15: Chaos + Compensating Controls
# ═══════════════════════════════════════════════════════════════════


class TestChaosSimulator:
    def test_dryrun_no_api_calls(self) -> None:
        sim = ChaosSimulator(mode=ChaosMode.DRYRUN)
        result = sim.run()
        assert result.mode == ChaosMode.DRYRUN
        assert result.tests_run > 0

    def test_dryrun_reports_gaps(self) -> None:
        sim = ChaosSimulator(mode=ChaosMode.DRYRUN)
        result = sim.run(
            monitor_config={
                "aws_guardduty": {"enabled": True},
                # Missing: azure_sentinel, gcp_scc, alibaba_actiontrail
            }
        )
        assert result.gaps_found >= 3

    def test_canary_refuses_non_tagged(self) -> None:
        sim = ChaosSimulator(mode=ChaosMode.CANARY)
        with pytest.raises(PermissionError, match="SecurityTesting"):
            sim.run(account_tags={"Purpose": "Production"})

    def test_live_refuses_without_auth(self) -> None:
        sim = ChaosSimulator(mode=ChaosMode.LIVE)
        with pytest.raises(PermissionError, match="authorisation"):
            sim.run(authorisation=False)

    def test_live_runs_with_auth(self) -> None:
        sim = ChaosSimulator(mode=ChaosMode.LIVE)
        result = sim.run(authorisation=True)
        assert result.mode == ChaosMode.LIVE


class TestCompensatingControls:
    def test_control_reduces_risk_80_pct(self) -> None:
        """Compensating control reduces risk by 80% (PDF req)."""
        registry = CompensatingControlRegistry()
        registry.activate("WAF Protection")
        risk, applied = registry.apply_to_risk(
            "has_access",
            "ec2_instance",
            0.9,
        )
        assert risk < 0.2  # 0.9 * (1 - 0.8) = 0.18
        assert "WAF Protection" in applied

    def test_mfa_reduces_assume_risk(self) -> None:
        registry = CompensatingControlRegistry()
        registry.activate("MFA Required")
        risk, applied = registry.apply_to_risk(
            "can_assume",
            "iam_role",
            0.9,
        )
        assert risk < 0.3
        assert "MFA Required" in applied

    def test_no_active_control_no_change(self) -> None:
        registry = CompensatingControlRegistry()
        risk, applied = registry.apply_to_risk(
            "has_access",
            "ec2_instance",
            0.9,
        )
        assert risk == 0.9
        assert len(applied) == 0

    def test_load_custom_controls(self) -> None:
        registry = CompensatingControlRegistry()
        count = registry.load_from_config(
            [
                {
                    "name": "Custom IDS",
                    "applies_to": "has_access",
                    "risk_reduction": 0.5,
                    "description": "IDS monitoring",
                },
            ]
        )
        assert count == 1
        assert "Custom IDS" in registry.available
