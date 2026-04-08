"""Tests for Autonomous Evolution Engine — learn, test, heal.

Proves:
    1. Public feed ingestion works (KEV, EPSS)
    2. Self-test detects all breach topologies
    3. Self-test detects degradation (failed topology)
    4. Self-healer triggers on low detection rate
    5. Self-healer alerts human on critical failure
    6. Orchestrator runs full cycle
    7. Boundaries: never modifies production data
    8. Audit trail captures all actions
"""

import tempfile
from pathlib import Path
from typing import Any

from vajra.core.auto_evolve import (
    BreachTopology,
    EvolutionOrchestrator,
    PublicFeedIngester,
    SelfHealer,
    SelfTestResult,
    SelfTestRunner,
)
from vajra.core.models import (
    AssetType,
    CloudAsset,
)

# ═══════════════════════════════════════════════════════════════════
# PUBLIC FEED INGESTION TESTS
# ═══════════════════════════════════════════════════════════════════


class TestPublicFeedIngestion:
    """Test auto-learning from public threat intelligence."""

    def test_ingest_kev_data(self) -> None:
        """CISA KEV entries ingested correctly."""
        tmp = Path(tempfile.mkdtemp()) / "feeds"
        ingester = PublicFeedIngester(cache_dir=tmp)

        kev_data: list[dict[str, Any]] = [
            {"cveID": "CVE-2024-1234", "shortDescription": "RCE in widget"},
            {"cveID": "CVE-2024-5678", "shortDescription": "SQLi in API"},
        ]
        update = ingester.ingest_kev_data(kev_data)

        assert update.entries_added == 2
        assert ingester.is_kev("CVE-2024-1234")
        assert not ingester.is_kev("CVE-9999-0000")

    def test_ingest_epss_scores(self) -> None:
        """EPSS scores ingested and queryable."""
        tmp = Path(tempfile.mkdtemp()) / "feeds"
        ingester = PublicFeedIngester(cache_dir=tmp)

        scores = {"CVE-2024-1234": 0.87, "CVE-2024-5678": 0.12}
        update = ingester.ingest_epss_scores(scores)

        assert update.entries_added == 2
        assert ingester.get_epss("CVE-2024-1234") == 0.87
        assert ingester.get_epss("CVE-9999-0000") == 0.0  # unknown

    def test_kev_epss_cross_reference(self) -> None:
        """EPSS scores auto-link to KEV entries."""
        tmp = Path(tempfile.mkdtemp()) / "feeds"
        ingester = PublicFeedIngester(cache_dir=tmp)

        ingester.ingest_kev_data([{"cveID": "CVE-2024-1234"}])
        ingester.ingest_epss_scores({"CVE-2024-1234": 0.95})

        assert ingester.is_kev("CVE-2024-1234")
        assert ingester.get_epss("CVE-2024-1234") == 0.95

    def test_feed_cache_persists(self) -> None:
        """Feed data survives between sessions."""
        tmp = Path(tempfile.mkdtemp()) / "feeds"

        ingester1 = PublicFeedIngester(cache_dir=tmp)
        ingester1.ingest_kev_data([{"cveID": "CVE-2024-1234"}])

        ingester2 = PublicFeedIngester(cache_dir=tmp)
        assert ingester2.is_kev("CVE-2024-1234")

    def test_duplicate_kev_not_double_counted(self) -> None:
        """Same CVE ingested twice → updated, not added."""
        tmp = Path(tempfile.mkdtemp()) / "feeds"
        ingester = PublicFeedIngester(cache_dir=tmp)

        ingester.ingest_kev_data([{"cveID": "CVE-2024-1234"}])
        update = ingester.ingest_kev_data([{"cveID": "CVE-2024-1234"}])

        assert update.entries_added == 0
        assert update.entries_updated == 1
        assert ingester.stats["kev_count"] == 1


# ═══════════════════════════════════════════════════════════════════
# SELF-TEST TESTS
# ═══════════════════════════════════════════════════════════════════


class TestSelfTesting:
    """Vajra attacks itself to verify detection capability."""

    def test_builtin_topologies_all_pass(self) -> None:
        """All built-in breach topologies MUST be detected."""
        runner = SelfTestRunner()
        result = runner.run_all()

        assert (
            result.passed == result.total_topologies
        ), f"self-test failed: {result.failed_names}"
        assert result.detection_rate == 1.0
        assert result.needs_healing is False

    def test_failed_topology_detected(self) -> None:
        """Impossible topology → detection fails → needs_healing."""
        impossible = BreachTopology(
            name="Impossible Test",
            mitre_id="T0000",
            assets=[
                CloudAsset(
                    id="alone",
                    name="Alone",
                    asset_type=AssetType.EC2_INSTANCE,
                    provider="aws",
                    region="us-east-1",
                    is_entry_point=True,
                ),
            ],
            edges=[],
            expected_paths=999,  # impossible expectation
            expected_min_cut=999,
        )
        runner = SelfTestRunner(extra_topologies=[impossible])
        result = runner.run_all()

        assert result.failed >= 1
        assert "Impossible Test" in result.failed_names

    def test_detection_trend_tracked(self) -> None:
        """Detection rate history maintained for trend analysis."""
        runner = SelfTestRunner()
        runner.run_all()
        runner.run_all()

        trend = runner.detection_trend
        assert len(trend) == 2
        assert all(r == 1.0 for r in trend)

    def test_self_test_uses_isolated_graphs(self) -> None:
        """Self-tests must create fresh graphs (never touch production).

        We verify by ensuring the runner doesn't hold any persistent graph.
        """
        runner = SelfTestRunner()
        result = runner.run_all()
        # No graph attribute on runner (isolation)
        assert not hasattr(runner, "_graph")
        assert result.passed > 0


# ═══════════════════════════════════════════════════════════════════
# SELF-HEALING TESTS
# ═══════════════════════════════════════════════════════════════════


class TestSelfHealing:
    """Autonomous healing when degradation detected."""

    def test_no_healing_when_tests_pass(self) -> None:
        """100% detection → no healing actions needed."""
        healer = SelfHealer()
        good_result = SelfTestResult(
            total_topologies=10,
            passed=10,
            failed=0,
            failed_names=[],
            detection_rate=1.0,
            needs_healing=False,
        )
        tmp = Path(tempfile.mkdtemp()) / "feeds"
        actions = healer.evaluate_and_heal(
            good_result,
            PublicFeedIngester(cache_dir=tmp),
        )
        assert len(actions) == 0

    def test_healing_triggered_on_degradation(self) -> None:
        """Detection below 80% → healing actions taken."""
        healer = SelfHealer()
        bad_result = SelfTestResult(
            total_topologies=10,
            passed=7,
            failed=3,
            failed_names=["Breach A", "Breach B", "Breach C"],
            detection_rate=0.7,
            needs_healing=True,
        )
        tmp = Path(tempfile.mkdtemp()) / "feeds"
        actions = healer.evaluate_and_heal(
            bad_result,
            PublicFeedIngester(cache_dir=tmp),
        )
        assert len(actions) >= 1
        action_types = [a.action_type for a in actions]
        assert "refresh_feeds" in action_types

    def test_critical_alert_on_severe_degradation(self) -> None:
        """Detection below 50% → human alert required."""
        healer = SelfHealer()
        critical_result = SelfTestResult(
            total_topologies=10,
            passed=4,
            failed=6,
            failed_names=["A", "B", "C", "D", "E", "F"],
            detection_rate=0.4,
            needs_healing=True,
        )
        tmp = Path(tempfile.mkdtemp()) / "feeds"
        actions = healer.evaluate_and_heal(
            critical_result,
            PublicFeedIngester(cache_dir=tmp),
        )
        action_types = [a.action_type for a in actions]
        assert "human_alert" in action_types

    def test_audit_trail_records_all_actions(self) -> None:
        """Every healing action is logged for compliance."""
        healer = SelfHealer()
        bad_result = SelfTestResult(
            total_topologies=10,
            passed=6,
            failed=4,
            failed_names=["X"],
            detection_rate=0.6,
            needs_healing=True,
        )
        tmp = Path(tempfile.mkdtemp()) / "feeds"
        healer.evaluate_and_heal(
            bad_result,
            PublicFeedIngester(cache_dir=tmp),
        )
        trail = healer.audit_trail
        assert len(trail) >= 1
        assert all("timestamp" in entry for entry in trail)


# ═══════════════════════════════════════════════════════════════════
# ORCHESTRATOR TESTS
# ═══════════════════════════════════════════════════════════════════


class TestOrchestrator:
    """Full learn → test → heal cycle."""

    def test_full_cycle_runs_successfully(self) -> None:
        """Complete orchestration cycle with no errors."""
        tmp = Path(tempfile.mkdtemp()) / "feeds"
        orch = EvolutionOrchestrator(
            feed_ingester=PublicFeedIngester(cache_dir=tmp),
        )
        summary = orch.run_cycle()

        assert summary["cycle"] == 1
        assert summary["self_test"]["detection_rate"] == 1.0
        assert summary["healing_actions"] == 0

    def test_multiple_cycles_track_trend(self) -> None:
        """Running multiple cycles builds detection trend."""
        tmp = Path(tempfile.mkdtemp()) / "feeds"
        orch = EvolutionOrchestrator(
            feed_ingester=PublicFeedIngester(cache_dir=tmp),
        )
        orch.run_cycle()
        summary = orch.run_cycle()

        assert summary["cycle"] == 2
        assert len(summary["detection_trend"]) == 2
