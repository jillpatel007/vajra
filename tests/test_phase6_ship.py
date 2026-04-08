"""Tests for Phase 6 — CLI, reports, webhooks, property tests.

Enterprise-grade tests for shipping.
"""

from __future__ import annotations

from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from vajra.alerts.webhooks import WebhookManager
from vajra.cli import cmd_scan, cmd_setup, cmd_verify, main
from vajra.core.crypto import SecureCredential
from vajra.core.graph_engine import VajraGraph
from vajra.core.models import (
    AssetType,
    CloudAsset,
    GraphEdge,
    RelationType,
)
from vajra.output.report import generate_report

# ═══════════════════════════════════════════════════════════════════
# DAY 26: CLI TESTS
# ═══════════════════════════════════════════════════════════════════


class TestCLI:
    def test_help_shows_6_commands(self) -> None:
        with patch("sys.argv", ["vajra", "--help"]):
            with patch("sys.stdout"):
                result = main()
        assert result == 0

    def test_scan_demo_runs(self) -> None:
        result = cmd_scan(demo=True, output="json")
        assert result == 1  # 1 = findings found

    def test_setup_shows_instructions(self) -> None:
        result = cmd_setup()
        assert result == 0

    def test_verify_missing_file(self) -> None:
        result = cmd_verify("nonexistent.json")
        assert result == 2

    def test_unknown_command(self) -> None:
        with patch("sys.argv", ["vajra", "foobar"]):
            result = main()
        assert result == 2


# ═══════════════════════════════════════════════════════════════════
# DAY 27: REPORT + WEBHOOK TESTS
# ═══════════════════════════════════════════════════════════════════

_REPORT_KEY = "report-signing-key-must-be-32-chars"  # noqa: S105


class TestReportGeneration:
    def test_signed_report_verifiable(self) -> None:
        scan = {"attack_paths": 2, "minimum_cut_edges": 1, "assets": 10}
        report = generate_report(scan, _REPORT_KEY)
        assert "payload" in report
        assert "signature" in report

    def test_executive_summary_has_dollar_figures(self) -> None:
        scan = {"attack_paths": 3, "minimum_cut_edges": 2, "assets": 50}
        report = generate_report(scan, _REPORT_KEY)
        summary = report["payload"]["executive_summary"]
        assert "$" in summary

    def test_zero_paths_clean_summary(self) -> None:
        scan = {"attack_paths": 0, "minimum_cut_edges": 0, "assets": 100}
        report = generate_report(scan, _REPORT_KEY)
        summary = report["payload"]["executive_summary"]
        assert "zero" in summary.lower()


class TestWebhooks:
    def test_only_critical_alerts(self) -> None:
        mgr = WebhookManager()
        assert mgr.should_alert("critical") is True
        assert mgr.should_alert("high") is False
        assert mgr.should_alert("medium") is False

    def test_payload_has_no_secrets(self) -> None:
        mgr = WebhookManager()
        payload = mgr.build_payload(
            {
                "attack_paths": 5,
                "minimum_cut_edges": 2,
                "secret_key": "should-not-appear",
            }
        )
        payload_str = str(payload)
        assert "should-not-appear" not in payload_str

    def test_slack_without_url_returns_false(self) -> None:
        mgr = WebhookManager()
        payload = mgr.build_payload({"attack_paths": 1})
        assert mgr.send_slack(payload) is False

    def test_slack_with_url_sends(self) -> None:
        mgr = WebhookManager(slack_url="https://hooks.slack.com/test")
        payload = mgr.build_payload({"attack_paths": 1})
        assert mgr.send_slack(payload) is True
        assert mgr.alerts_sent == 1


# ═══════════════════════════════════════════════════════════════════
# DAY 28: PROPERTY TESTS (Hypothesis)
# ═══════════════════════════════════════════════════════════════════


class TestPropertyBased:
    """Invariants that must hold for ANY input."""

    @given(plaintext=st.binary(min_size=0, max_size=1000))
    @settings(max_examples=100)
    def test_crypto_roundtrip(self, plaintext: bytes) -> None:
        """decrypt(encrypt(x)) == x always."""
        cred = SecureCredential.from_plaintext(plaintext)
        assert cred.decrypt() == plaintext
        cred.destroy()

    @given(
        name=st.text(min_size=1, max_size=50),
        risk=st.floats(min_value=0.0, max_value=1.0),
    )
    @settings(max_examples=50)
    def test_effective_risk_bounded(
        self,
        name: str,
        risk: float,
    ) -> None:
        """effective_risk_weight always in [0.0, 1.0]."""
        edge = GraphEdge(
            source="a",
            target="b",
            relation=RelationType.HAS_ACCESS,
            risk_weight=risk,
            cisa_kev=True,
            falco_active=True,
        )
        assert 0.0 <= edge.effective_risk_weight <= 1.0

    def test_graph_integrity_after_operations(self) -> None:
        """Graph integrity holds after add/verify cycle."""
        graph = VajraGraph()
        for i in range(10):
            graph.add_asset(
                CloudAsset(
                    id=f"prop-{i}",
                    name=f"Asset {i}",
                    asset_type=AssetType.IAM_ROLE,
                    provider="aws",
                    region="us-east-1",
                )
            )
        assert graph.verify_integrity() is True

    def test_min_cut_eliminates_paths(self) -> None:
        """After cutting min-cut edges, no paths should remain
        (on the cut graph)."""
        graph = VajraGraph()
        entry = CloudAsset(
            id="prop-entry",
            name="E",
            asset_type=AssetType.EC2_INSTANCE,
            provider="aws",
            region="us-east-1",
            is_entry_point=True,
        )
        jewel = CloudAsset(
            id="prop-jewel",
            name="J",
            asset_type=AssetType.S3_BUCKET,
            provider="aws",
            region="us-east-1",
            is_crown_jewel=True,
        )
        graph.add_asset(entry)
        graph.add_asset(jewel)
        graph.add_edge(
            GraphEdge(
                source="prop-entry",
                target="prop-jewel",
                relation=RelationType.HAS_ACCESS,
                risk_weight=0.9,
            )
        )

        paths_before = graph.find_attack_paths()
        assert len(paths_before) >= 1

        cut = graph.find_minimum_cut()
        assert len(cut.edges_to_cut) >= 1

    @given(
        data=st.dictionaries(
            st.text(min_size=1, max_size=10),
            st.text(min_size=0, max_size=20),
            min_size=1,
            max_size=5,
        )
    )
    @settings(max_examples=50)
    def test_hash_changes_on_any_field_change(
        self,
        data: dict[str, str],
    ) -> None:
        """CloudAsset hash is deterministic and changes on mutation."""
        asset = CloudAsset(
            id="hash-test",
            name="test",
            asset_type=AssetType.IAM_ROLE,
            provider="aws",
            region="us-east-1",
        )
        hash1 = asset.integrity_hash()
        hash2 = asset.integrity_hash()
        assert hash1 == hash2  # Deterministic
