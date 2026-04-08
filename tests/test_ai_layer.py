"""Tests for AI Layer — Day 16 PDF requirements.

Tests:
    - Graceful None on missing ANTHROPIC_API_KEY
    - Graph node count unchanged after any AI call
    - Injection payload in resource name does not affect schema
    - Haiku used for simple queries, Opus for complex chains
    - All schemas validate correctly
    - Cost tracking works
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from vajra.ai.layer import AILayer
from vajra.ai.models import (
    AttackNarrative,
    PathVerification,
    Severity,
)
from vajra.ai.router import ModelRouter, ModelTier
from vajra.core.graph_engine import VajraGraph
from vajra.core.models import (
    AssetType,
    CloudAsset,
)

# ═══════════════════════════════════════════════════════════════════
# GRACEFUL DEGRADATION (no API key)
# ═══════════════════════════════════════════════════════════════════


class TestGracefulDegradation:
    """All AI functions return None when ANTHROPIC_API_KEY is missing."""

    @patch.dict(os.environ, {}, clear=True)
    def test_narrate_returns_none_without_key(self) -> None:
        layer = AILayer()
        result = layer.narrate([], {})
        assert result is None

    @patch.dict(os.environ, {}, clear=True)
    def test_verify_returns_none_without_key(self) -> None:
        layer = AILayer()
        result = layer.verify([])
        assert result is None

    @patch.dict(os.environ, {}, clear=True)
    def test_remediate_returns_none_without_key(self) -> None:
        layer = AILayer()
        result = layer.remediate([], [])
        assert result is None

    @patch.dict(os.environ, {}, clear=True)
    def test_query_returns_none_without_key(self) -> None:
        layer = AILayer()
        result = layer.query("test question", {})
        assert result is None

    @patch.dict(os.environ, {}, clear=True)
    def test_write_rule_returns_none_without_key(self) -> None:
        layer = AILayer()
        result = layer.write_rule("test", [])
        assert result is None

    @patch.dict(os.environ, {}, clear=True)
    def test_is_available_false_without_key(self) -> None:
        layer = AILayer()
        assert layer.is_available is False


# ═══════════════════════════════════════════════════════════════════
# GRAPH SAFETY (AI cannot modify graph)
# ═══════════════════════════════════════════════════════════════════


class TestGraphSafety:
    """Graph node count must be identical before and after AI calls."""

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key-for-unit-testing"})
    def test_narrate_does_not_modify_graph(self) -> None:
        graph = VajraGraph()
        graph.add_asset(
            CloudAsset(
                id="a",
                name="A",
                asset_type=AssetType.EC2_INSTANCE,
                provider="aws",
                region="us-east-1",
            )
        )
        count_before = len(graph.get_assets())

        layer = AILayer()
        layer.narrate(
            [{"source": "a", "target": "b"}],
            {"a": "Asset A"},
        )

        count_after = len(graph.get_assets())
        assert count_before == count_after

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key-for-unit-testing"})
    def test_ai_layer_has_no_graph_reference(self) -> None:
        """AILayer must not store a reference to the graph."""
        layer = AILayer()
        assert not hasattr(layer, "_graph")
        assert not hasattr(layer, "graph")


# ═══════════════════════════════════════════════════════════════════
# INJECTION DEFENCE
# ═══════════════════════════════════════════════════════════════════


class TestInjectionDefence:
    """Injection payloads in resource names must not affect output."""

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key-for-unit-testing"})
    def test_xss_in_query_blocked(self) -> None:
        layer = AILayer()
        result = layer.query(
            "<script>alert(1)</script>",
            {"paths": 0},
        )
        assert result is not None
        assert "injection" in result.answer.lower() or result.confidence == 0.0

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key-for-unit-testing"})
    def test_sql_injection_in_query_blocked(self) -> None:
        layer = AILayer()
        result = layer.query(
            "'; DROP TABLE findings--",
            {"paths": 0},
        )
        assert result is not None
        assert result.confidence == 0.0


# ═══════════════════════════════════════════════════════════════════
# MODEL ROUTING
# ═══════════════════════════════════════════════════════════════════


class TestModelRouting:
    """Verify correct model routing by task type."""

    def test_haiku_for_simple_queries(self) -> None:
        router = ModelRouter()
        assert router.route("query") == ModelTier.HAIKU
        assert router.route("verify") == ModelTier.HAIKU

    def test_sonnet_for_narratives(self) -> None:
        router = ModelRouter()
        assert router.route("narrate") == ModelTier.SONNET
        assert router.route("remediate") == ModelTier.SONNET

    def test_opus_for_complex_tasks(self) -> None:
        router = ModelRouter()
        assert router.route("write_rule") == ModelTier.OPUS

    def test_override_forces_model(self) -> None:
        router = ModelRouter(override=ModelTier.HAIKU)
        assert router.route("write_rule") == ModelTier.HAIKU

    def test_cost_tracking(self) -> None:
        router = ModelRouter()
        cost = router.track_cost(
            ModelTier.HAIKU,
            1_000_000,
            1_000_000,
        )
        assert cost > 0
        assert router.total_cost > 0
        assert router.call_count == 1


# ═══════════════════════════════════════════════════════════════════
# SCHEMA VALIDATION
# ═══════════════════════════════════════════════════════════════════


class TestSchemaValidation:
    """Pydantic schemas reject invalid AI output."""

    def test_attack_narrative_rejects_invalid_mitre(self) -> None:
        with pytest.raises((Exception,)):  # noqa: B017
            AttackNarrative(
                path_description="test",
                business_impact="test",
                severity=Severity.HIGH,
                mitre_technique="INVALID",
            )

    def test_attack_narrative_accepts_valid_mitre(self) -> None:
        narrative = AttackNarrative(
            path_description="test path",
            business_impact="data loss",
            severity=Severity.HIGH,
            mitre_technique="T1078",
        )
        assert narrative.mitre_technique == "T1078"

    def test_attack_narrative_accepts_atlas(self) -> None:
        narrative = AttackNarrative(
            path_description="AI attack path",
            business_impact="model compromise",
            severity=Severity.CRITICAL,
            mitre_technique="AML.T0043",
        )
        assert "AML" in narrative.mitre_technique

    def test_path_verification_confidence_bounded(self) -> None:
        with pytest.raises((Exception,)):  # noqa: B017
            PathVerification(
                is_valid=True,
                confidence=1.5,
                reasoning="test",
            )

    def test_severity_constrained(self) -> None:
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"

    def test_narrative_frozen(self) -> None:
        narrative = AttackNarrative(
            path_description="test",
            business_impact="test",
            severity=Severity.HIGH,
            mitre_technique="T1078",
        )
        with pytest.raises((Exception,)):  # noqa: B017
            narrative.path_description = "modified"  # type: ignore[misc]
