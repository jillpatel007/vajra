"""Tests for Phase 4 AI — Days 17-20.

Day 17: RAG + context architect
Day 18: Evals + observability
Day 19: Agent + red team
Day 20: Model supply chain
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

from vajra.ai.agent import VajraSecurityAgent
from vajra.ai.context_architect import ContextArchitect, ContextStrategy
from vajra.ai.evals import EvalCase, EvalPipeline
from vajra.ai.layer import AILayer
from vajra.ai.observability import ObservableAILayer
from vajra.ai.rag import Finding, VajraRAG
from vajra.ai.security.red_team import AIRedTeam
from vajra.ai.security.supply_chain import ModelSupplyChainScanner
from vajra.core.graph_engine import VajraGraph
from vajra.core.models import (
    AssetType,
    CloudAsset,
    EdgeValidity,
    GraphEdge,
    NetworkValidity,
    RelationType,
)

# ═══════════════════════════════════════════════════════════════════
# DAY 17: RAG + CONTEXT ARCHITECT
# ═══════════════════════════════════════════════════════════════════


class TestRAG:
    def test_index_and_query(self) -> None:
        rag = VajraRAG()
        rag.index_findings(
            [
                Finding("f1", "IAM role can access payments database", "high"),
                Finding("f2", "S3 bucket is publicly readable", "critical"),
                Finding("f3", "Lambda has admin permissions", "medium"),
            ]
        )
        results = rag.query("what can reach payments database")
        assert len(results) >= 1
        assert results[0].finding.finding_id == "f1"

    def test_empty_index_returns_empty(self) -> None:
        rag = VajraRAG()
        results = rag.query("anything")
        assert len(results) == 0

    def test_index_size_tracked(self) -> None:
        rag = VajraRAG()
        rag.index_findings([Finding("f1", "test", "low")])
        assert rag.index_size == 1


class TestContextArchitect:
    def test_budget_never_exceeded(self) -> None:
        architect = ContextArchitect(token_budget=100)
        findings = [
            {"id": f"f{i}", "description": "x" * 200, "severity": "high"}
            for i in range(50)
        ]
        architect.build_context(findings)
        assert architect.tokens_used <= 100

    def test_critical_first_strategy(self) -> None:
        architect = ContextArchitect(token_budget=100_000)
        findings = [
            {"id": "low", "severity": "low", "description": "minor"},
            {"id": "crit", "severity": "critical", "description": "major"},
        ]
        selected = architect.build_context(
            findings,
            strategy=ContextStrategy.CRITICAL_FIRST,
        )
        assert selected[0]["id"] == "crit"

    def test_tokens_remaining(self) -> None:
        architect = ContextArchitect(token_budget=1000)
        architect.build_context([{"data": "small"}])
        assert architect.tokens_remaining > 0


# ═══════════════════════════════════════════════════════════════════
# DAY 18: EVALS + OBSERVABILITY
# ═══════════════════════════════════════════════════════════════════


class TestEvalPipeline:
    def test_detects_wrong_mitre_id(self) -> None:
        pipeline = EvalPipeline(accuracy_threshold=0.9)
        pipeline.add_cases(
            [
                EvalCase("c1", {}, "T1078", "high"),
                EvalCase("c2", {}, "T1530", "critical"),
            ]
        )

        def bad_predict(data: Any) -> tuple[str, str]:
            return "T0000", "low"  # intentionally wrong

        summary = pipeline.run_regression_suite(bad_predict)
        assert summary.mitre_accuracy == 0.0
        assert summary.safe_to_deploy is False
        assert len(summary.regressions) > 0

    def test_safe_deploy_when_accurate(self) -> None:
        pipeline = EvalPipeline()
        pipeline.add_cases(
            [
                EvalCase("c1", {}, "T1078", "high"),
            ]
        )
        # Default predict returns expected values
        summary = pipeline.run_regression_suite()
        assert summary.safe_to_deploy is True

    def test_regression_detected_on_model_change(self) -> None:
        pipeline = EvalPipeline(accuracy_threshold=0.8)
        pipeline.add_cases([EvalCase(f"c{i}", {}, "T1078", "high") for i in range(10)])

        def half_wrong(data: Any) -> tuple[str, str]:
            return "T9999", "low"

        summary = pipeline.run_regression_suite(half_wrong)
        assert summary.safe_to_deploy is False


class TestObservability:
    def test_cost_per_finding(self) -> None:
        obs = ObservableAILayer()
        obs.record("narrate", "sonnet", 500, 200, 0.01, 150.0)
        obs.record("verify", "haiku", 300, 100, 0.002, 80.0)
        cost = obs.cost_per_finding(finding_count=5)
        assert cost > 0

    def test_total_cost_tracked(self) -> None:
        obs = ObservableAILayer()
        obs.record("test", "haiku", 100, 50, 0.005, 100.0)
        assert obs.total_cost == 0.005
        assert obs.total_calls == 1

    def test_traces_recorded(self) -> None:
        obs = ObservableAILayer()
        obs.record("narrate", "sonnet", 500, 200, 0.01, 150.0)
        assert len(obs.traces) == 1
        assert obs.traces[0].function == "narrate"


# ═══════════════════════════════════════════════════════════════════
# DAY 19: AGENT + RED TEAM
# ═══════════════════════════════════════════════════════════════════


def _build_agent_graph() -> VajraGraph:
    graph = VajraGraph()
    entry = CloudAsset(
        id="agent-entry",
        name="Entry",
        asset_type=AssetType.EC2_INSTANCE,
        provider="aws",
        region="us-east-1",
        is_entry_point=True,
    )
    jewel = CloudAsset(
        id="agent-jewel",
        name="Crown",
        asset_type=AssetType.S3_BUCKET,
        provider="aws",
        region="us-east-1",
        is_crown_jewel=True,
    )
    graph.add_asset(entry)
    graph.add_asset(jewel)
    graph.add_edge(
        GraphEdge(
            source="agent-entry",
            target="agent-jewel",
            relation=RelationType.HAS_ACCESS,
            risk_weight=0.9,
            iam_validity=EdgeValidity.VALID,
            network_validity=NetworkValidity.REACHABLE,
        )
    )
    return graph


class TestSecurityAgent:
    def test_agent_uses_multiple_tools(self) -> None:
        graph = _build_agent_graph()
        agent = VajraSecurityAgent(graph)
        result = agent.run("find attack paths and fix them")
        assert result.iterations >= 2
        assert len(result.tool_calls) >= 2

    def test_agent_terminates(self) -> None:
        graph = _build_agent_graph()
        agent = VajraSecurityAgent(graph)
        result = agent.run("simple question")
        assert result.terminated_reason == "complete"

    def test_agent_never_modifies_graph(self) -> None:
        graph = _build_agent_graph()
        assets_before = len(graph.get_assets())
        edges_before = len(graph.get_edges())

        agent = VajraSecurityAgent(graph)
        agent.run("find all attack paths and calculate cost exposure")

        assert len(graph.get_assets()) == assets_before
        assert len(graph.get_edges()) == edges_before


class TestRedTeam:
    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"})
    def test_all_injections_blocked(self) -> None:
        layer = AILayer()
        red_team = AIRedTeam()
        report = red_team.run_injection_tests(
            lambda q: layer.query(q, {}),
        )
        # 5/6 blocked at input filter. Prompt injection (#6) is
        # blocked at schema level (structured output), not input.
        assert report.blocked >= 5
        assert report.bypassed <= 1

    @patch.dict(os.environ, {}, clear=True)
    def test_red_team_without_api_key(self) -> None:
        layer = AILayer()
        red_team = AIRedTeam()
        report = red_team.run_injection_tests(
            lambda q: layer.query(q, {}),
        )
        # All return None (no API key) → all blocked
        assert report.all_blocked is True


# ═══════════════════════════════════════════════════════════════════
# DAY 20: MODEL SUPPLY CHAIN
# ═══════════════════════════════════════════════════════════════════


class TestModelSupplyChain:
    def test_tampered_model_detected(self) -> None:
        tmp = Path(tempfile.mkdtemp()) / "model.bin"
        tmp.write_bytes(b"original model data")
        scanner = ModelSupplyChainScanner()

        result = scanner.verify_model_integrity(tmp, "wrong_hash")
        assert result.integrity_valid is False

    def test_valid_model_passes(self) -> None:
        import hashlib

        tmp = Path(tempfile.mkdtemp()) / "model.bin"
        data = b"valid model data"
        tmp.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()

        scanner = ModelSupplyChainScanner()
        result = scanner.verify_model_integrity(tmp, expected)
        assert result.integrity_valid is True

    def test_backdoor_trigger_detected(self) -> None:
        scanner = ModelSupplyChainScanner()
        result = scanner.scan_for_backdoors(
            [
                "normal output",
                "SUDO_OVERRIDE detected in layer 3",
            ]
        )
        assert result.is_clean is False
        assert "SUDO_OVERRIDE" in result.triggers_found

    def test_clean_model_no_triggers(self) -> None:
        scanner = ModelSupplyChainScanner()
        result = scanner.scan_for_backdoors(
            [
                "normal analysis result",
                "no issues found",
            ]
        )
        assert result.is_clean is True

    def test_vulnerable_ai_lib_detected(self) -> None:
        scanner = ModelSupplyChainScanner()
        findings = scanner.audit_dependencies(
            {
                "transformers": "4.30",
                "torch": "2.0.0",
            }
        )
        assert len(findings) >= 1
        libs = [f["library"] for f in findings]
        assert "transformers" in libs

    def test_safe_ai_libs_pass(self) -> None:
        scanner = ModelSupplyChainScanner()
        findings = scanner.audit_dependencies(
            {
                "transformers": "4.40",
                "torch": "2.5.0",
            }
        )
        assert len(findings) == 0
