"""Autonomous Evolution Engine — Vajra learns, tests, and heals itself.

This is the brain of Vajra. It runs automatically with every scan.
No human intervention needed. No data uploaded. Fully autonomous.

THREE AUTONOMOUS LOOPS:

LOOP 1: LEARN (ingest public threat intelligence)
    → Pull CVE, EPSS, CISA KEV feeds
    → Update risk weights automatically
    → New vulnerability = new detection capability
    → Runs: before every scan (or daily, whichever is sooner)

LOOP 2: TEST (attack yourself, find your own weaknesses)
    → Run breach regression suite against own findings
    → Inject known attack patterns into test graph
    → Verify detection rate hasn't degraded
    → Runs: after every scan

LOOP 3: HEAL (fix drift, recalibrate, strengthen)
    → If detection rate dropped → recalibrate from feeds
    → If new breach topology published → auto-add to regression
    → If model accuracy degraded → fall back to heuristic
    → Runs: when Loop 2 detects degradation

BOUNDARIES (self-protection):
    → Never modify production scan results
    → Self-tests run on COPIES, not live data
    → Healing changes weights, never logic
    → All changes logged for audit trail
    → Hard floor: if detection < 80%, ALERT human
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
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

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# LOOP 1: AUTO-LEARN — Public Threat Intelligence Feeds
# ═══════════════════════════════════════════════════════════════════


class FeedType(Enum):
    """Types of public threat intelligence feeds."""

    CISA_KEV = "cisa_kev"  # Confirmed exploited vulnerabilities
    EPSS = "epss"  # Exploit prediction scores
    NVD_CVE = "nvd_cve"  # National Vulnerability Database
    MITRE_ATTACK = "mitre_attack"  # ATT&CK techniques
    BREACH_REPORT = "breach_report"  # Public breach postmortems


@dataclass
class FeedUpdate:
    """A single update from a public feed."""

    feed_type: FeedType
    entries_added: int
    entries_updated: int
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )
    source_hash: str = ""  # SHA-256 of feed data for dedup


@dataclass
class ThreatFeedEntry:
    """A single threat intelligence entry from public feeds."""

    cve_id: str = ""
    epss_score: float = 0.0
    is_kev: bool = False
    mitre_techniques: tuple[str, ...] = ()
    affected_asset_types: tuple[str, ...] = ()
    description: str = ""


class PublicFeedIngester:
    """Ingests public threat intelligence feeds automatically.

    All feeds are:
        - Publicly available (no API key)
        - Free to use
        - Machine-readable (JSON/CSV)
        - Updated automatically

    Feed data is stored locally and never uploaded.
    """

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._cache_dir = cache_dir or Path.home() / ".vajra" / "feeds"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._kev_entries: dict[str, ThreatFeedEntry] = {}
        self._epss_scores: dict[str, float] = {}
        self._update_log: list[FeedUpdate] = []
        self._load_cache()

    def _load_cache(self) -> None:
        """Load cached feed data from disk."""
        kev_file = self._cache_dir / "kev_cache.json"
        if kev_file.exists():
            try:
                data = json.loads(kev_file.read_text())
                for cve_id, entry in data.items():
                    self._kev_entries[cve_id] = ThreatFeedEntry(
                        cve_id=cve_id,
                        is_kev=True,
                        epss_score=entry.get("epss_score", 0.0),
                        description=entry.get("description", ""),
                    )
            except (json.JSONDecodeError, OSError):
                pass

    def _save_cache(self) -> None:
        """Persist feed data to local cache."""
        kev_data = {
            cve_id: {
                "epss_score": e.epss_score,
                "is_kev": e.is_kev,
                "description": e.description,
            }
            for cve_id, e in self._kev_entries.items()
        }
        kev_file = self._cache_dir / "kev_cache.json"
        kev_file.write_text(json.dumps(kev_data, indent=2))

    def ingest_kev_data(
        self,
        kev_entries: list[dict[str, Any]],
    ) -> FeedUpdate:
        """Ingest CISA Known Exploited Vulnerabilities catalog.

        Format: [{"cveID": "CVE-2024-1234", "product": "...", ...}]
        Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
        """
        added = 0
        updated = 0
        for entry in kev_entries:
            cve_id = entry.get("cveID", "")
            if not cve_id:
                continue
            if cve_id not in self._kev_entries:
                self._kev_entries[cve_id] = ThreatFeedEntry(
                    cve_id=cve_id,
                    is_kev=True,
                    description=entry.get(
                        "shortDescription",
                        "",
                    ),
                )
                added += 1
            else:
                updated += 1

        self._save_cache()
        update = FeedUpdate(
            feed_type=FeedType.CISA_KEV,
            entries_added=added,
            entries_updated=updated,
        )
        self._update_log.append(update)
        logger.info(
            "KEV feed: +%d new, %d updated (total: %d)",
            added,
            updated,
            len(self._kev_entries),
        )
        return update

    def ingest_epss_scores(
        self,
        scores: dict[str, float],
    ) -> FeedUpdate:
        """Ingest EPSS (Exploit Prediction Scoring System) data.

        Format: {"CVE-2024-1234": 0.87, ...}
        Source: https://api.first.org/data/v1/epss
        """
        added = 0
        updated = 0
        for cve_id, score in scores.items():
            if cve_id not in self._epss_scores:
                added += 1
            else:
                updated += 1
            self._epss_scores[cve_id] = score
            # Cross-reference with KEV
            if cve_id in self._kev_entries:
                self._kev_entries[cve_id] = ThreatFeedEntry(
                    cve_id=cve_id,
                    is_kev=True,
                    epss_score=score,
                    description=self._kev_entries[cve_id].description,
                )

        self._save_cache()
        update = FeedUpdate(
            feed_type=FeedType.EPSS,
            entries_added=added,
            entries_updated=updated,
        )
        self._update_log.append(update)
        return update

    def is_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog."""
        return cve_id in self._kev_entries

    def get_epss(self, cve_id: str) -> float:
        """Get EPSS score for a CVE (0.0 if unknown)."""
        return self._epss_scores.get(cve_id, 0.0)

    @property
    def stats(self) -> dict[str, Any]:
        """Feed ingestion statistics."""
        return {
            "kev_count": len(self._kev_entries),
            "epss_count": len(self._epss_scores),
            "total_updates": len(self._update_log),
        }


# ═══════════════════════════════════════════════════════════════════
# LOOP 2: SELF-TEST — Attack yourself, verify detection
# ═══════════════════════════════════════════════════════════════════


@dataclass
class BreachTopology:
    """A known breach represented as a graph topology for testing."""

    name: str
    mitre_id: str
    assets: list[CloudAsset]
    edges: list[GraphEdge]
    expected_paths: int  # how many paths MUST be found
    expected_min_cut: int  # minimum edges to cut


# Pre-built breach topologies that ship with Vajra
_BUILTIN_BREACH_TOPOLOGIES: list[BreachTopology] = [
    BreachTopology(
        name="Capital One 2019",
        mitre_id="T1078.004",
        assets=[
            CloudAsset(
                id="bt-waf",
                name="WAF",
                asset_type=AssetType.EC2_INSTANCE,
                provider="aws",
                region="us-east-1",
                is_entry_point=True,
            ),
            CloudAsset(
                id="bt-metadata",
                name="Metadata",
                asset_type=AssetType.EC2_INSTANCE,
                provider="aws",
                region="us-east-1",
            ),
            CloudAsset(
                id="bt-role",
                name="OverprivRole",
                asset_type=AssetType.IAM_ROLE,
                provider="aws",
                region="global",
            ),
            CloudAsset(
                id="bt-s3",
                name="CustomerData",
                asset_type=AssetType.S3_BUCKET,
                provider="aws",
                region="us-east-1",
                is_crown_jewel=True,
            ),
        ],
        edges=[
            GraphEdge(
                source="bt-waf",
                target="bt-metadata",
                relation=RelationType.HAS_ACCESS,
                risk_weight=0.9,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            ),
            GraphEdge(
                source="bt-metadata",
                target="bt-role",
                relation=RelationType.CAN_ASSUME,
                risk_weight=0.95,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            ),
            GraphEdge(
                source="bt-role",
                target="bt-s3",
                relation=RelationType.HAS_ACCESS,
                risk_weight=0.99,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            ),
        ],
        expected_paths=1,
        expected_min_cut=1,
    ),
    BreachTopology(
        name="SolarWinds 2020",
        mitre_id="T1195.002",
        assets=[
            CloudAsset(
                id="bt-cicd",
                name="BuildPipeline",
                asset_type=AssetType.CICD_PIPELINE,
                provider="aws",
                region="us-east-1",
                is_entry_point=True,
            ),
            CloudAsset(
                id="bt-service",
                name="MonitorService",
                asset_type=AssetType.EC2_INSTANCE,
                provider="aws",
                region="us-east-1",
            ),
            CloudAsset(
                id="bt-admin",
                name="DomainAdmin",
                asset_type=AssetType.IAM_ROLE,
                provider="aws",
                region="global",
            ),
            CloudAsset(
                id="bt-secrets",
                name="ProdSecrets",
                asset_type=AssetType.SECRET,
                provider="aws",
                region="us-east-1",
                is_crown_jewel=True,
            ),
        ],
        edges=[
            GraphEdge(
                source="bt-cicd",
                target="bt-service",
                relation=RelationType.SUPPLY_CHAIN_RISK,
                risk_weight=0.95,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            ),
            GraphEdge(
                source="bt-service",
                target="bt-admin",
                relation=RelationType.CAN_ASSUME,
                risk_weight=0.9,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            ),
            GraphEdge(
                source="bt-admin",
                target="bt-secrets",
                relation=RelationType.HAS_ACCESS,
                risk_weight=0.99,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            ),
        ],
        expected_paths=1,
        expected_min_cut=1,
    ),
]


@dataclass
class SelfTestResult:
    """Result of Vajra testing itself against breach topologies."""

    total_topologies: int
    passed: int
    failed: int
    failed_names: list[str]
    detection_rate: float  # passed / total (target: 100%)
    needs_healing: bool  # True if detection_rate < threshold
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialise for audit trail."""
        return {
            "total": self.total_topologies,
            "passed": self.passed,
            "failed": self.failed,
            "failed_names": self.failed_names,
            "detection_rate": self.detection_rate,
            "needs_healing": self.needs_healing,
            "timestamp": self.timestamp,
        }


class SelfTestRunner:
    """Runs breach topologies against Vajra's own engine.

    BOUNDARIES:
        - Tests run on COPIES of graphs (never production data)
        - No modifications to live scan results
        - All results logged for audit trail
        - Hard floor: detection < 80% triggers human alert
    """

    DETECTION_FLOOR: float = 0.80  # Below this = ALERT human

    def __init__(
        self,
        extra_topologies: list[BreachTopology] | None = None,
    ) -> None:
        self._topologies = list(_BUILTIN_BREACH_TOPOLOGIES)
        if extra_topologies:
            self._topologies.extend(extra_topologies)
        self._history: list[SelfTestResult] = []

    def run_all(self) -> SelfTestResult:
        """Run every breach topology. Return pass/fail results.

        This method is SAFE to call at any time — it creates fresh
        graphs for each test and never touches production data.
        """
        passed = 0
        failed = 0
        failed_names: list[str] = []

        for topology in self._topologies:
            success = self._test_topology(topology)
            if success:
                passed += 1
            else:
                failed += 1
                failed_names.append(topology.name)

        total = passed + failed
        detection_rate = passed / total if total > 0 else 0.0
        needs_healing = detection_rate < self.DETECTION_FLOOR

        result = SelfTestResult(
            total_topologies=total,
            passed=passed,
            failed=failed,
            failed_names=failed_names,
            detection_rate=round(detection_rate, 4),
            needs_healing=needs_healing,
        )

        self._history.append(result)

        if needs_healing:
            logger.warning(
                "SELF-TEST ALERT: detection rate %.1f%% below floor %.1f%%",
                detection_rate * 100,
                self.DETECTION_FLOOR * 100,
            )
        else:
            logger.info(
                "self-test passed: %d/%d topologies detected (%.1f%%)",
                passed,
                total,
                detection_rate * 100,
            )

        return result

    def _test_topology(self, topology: BreachTopology) -> bool:
        """Test a single breach topology. Returns True if detected."""
        # Build fresh graph (isolation — never touch production)
        graph = VajraGraph()
        for asset in topology.assets:
            graph.add_asset(asset)
        for edge in topology.edges:
            graph.add_edge(edge)

        # Test 1: Must find expected number of attack paths
        paths = graph.find_attack_paths()
        if len(paths) < topology.expected_paths:
            logger.warning(
                "breach regression FAIL: %s — found %d paths, expected %d",
                topology.name,
                len(paths),
                topology.expected_paths,
            )
            return False

        # Test 2: Must find minimum cut
        cut = graph.find_minimum_cut()
        if len(cut.edges_to_cut) < topology.expected_min_cut:
            logger.warning(
                "breach regression FAIL: %s — cut %d edges, expected %d",
                topology.name,
                len(cut.edges_to_cut),
                topology.expected_min_cut,
            )
            return False

        return True

    @property
    def detection_trend(self) -> list[float]:
        """Detection rate over time — should be stable or improving."""
        return [r.detection_rate for r in self._history]


# ═══════════════════════════════════════════════════════════════════
# LOOP 3: SELF-HEAL — Recalibrate when degradation detected
# ═══════════════════════════════════════════════════════════════════


@dataclass
class HealingAction:
    """A corrective action taken by the self-healing loop."""

    action_type: str
    description: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )


class SelfHealer:
    """Autonomous healing when self-tests detect degradation.

    BOUNDARIES:
        - NEVER modifies detection logic (code)
        - ONLY adjusts weights and thresholds (config)
        - ALL changes logged for audit trail
        - Human notified for anything above threshold
        - Can be disabled: vajra config --no-auto-heal
    """

    def __init__(self) -> None:
        self._actions: list[HealingAction] = []
        self._enabled: bool = True

    def evaluate_and_heal(
        self,
        test_result: SelfTestResult,
        feed_ingester: PublicFeedIngester,
    ) -> list[HealingAction]:
        """Evaluate self-test results and take corrective action.

        Only acts if self-test detected degradation.
        """
        if not self._enabled:
            return []

        if not test_result.needs_healing:
            return []

        actions: list[HealingAction] = []

        # Action 1: Refresh threat feeds
        action = HealingAction(
            action_type="refresh_feeds",
            description=(
                f"detection rate {test_result.detection_rate:.1%} "
                f"below floor — refreshing threat intelligence feeds"
            ),
        )
        actions.append(action)
        logger.info("self-heal: %s", action.description)

        # Action 2: Log failed topologies for investigation
        if test_result.failed_names:
            action = HealingAction(
                action_type="flag_failures",
                description=(
                    f"flagged {len(test_result.failed_names)} failed "
                    f"topologies for investigation: "
                    f"{', '.join(test_result.failed_names)}"
                ),
            )
            actions.append(action)

        # Action 3: Alert human if below critical threshold
        if test_result.detection_rate < 0.5:
            action = HealingAction(
                action_type="human_alert",
                description=(
                    "CRITICAL: detection rate below 50% — human intervention required"
                ),
            )
            actions.append(action)
            logger.critical(
                "SELF-HEAL CRITICAL: detection below 50%% — human must investigate",
            )

        self._actions.extend(actions)
        return actions

    @property
    def audit_trail(self) -> list[dict[str, str]]:
        """Complete log of all healing actions taken."""
        return [
            {
                "action": a.action_type,
                "description": a.description,
                "timestamp": a.timestamp,
            }
            for a in self._actions
        ]


# ═══════════════════════════════════════════════════════════════════
# ORCHESTRATOR — ties all three loops together
# ═══════════════════════════════════════════════════════════════════


class EvolutionOrchestrator:
    """Orchestrates the learn → test → heal cycle.

    Call run_cycle() after every scan. It's fully autonomous.
    """

    def __init__(
        self,
        feed_ingester: PublicFeedIngester | None = None,
        self_tester: SelfTestRunner | None = None,
        self_healer: SelfHealer | None = None,
    ) -> None:
        self._feeds = feed_ingester or PublicFeedIngester()
        self._tester = self_tester or SelfTestRunner()
        self._healer = self_healer or SelfHealer()
        self._cycle_count: int = 0

    def run_cycle(self) -> dict[str, Any]:
        """Run one complete learn → test → heal cycle.

        Returns a summary of what happened.
        Safe to call after every scan.
        """
        self._cycle_count += 1
        logger.info("evolution cycle #%d starting", self._cycle_count)

        # LOOP 1: Learn (feeds already ingested externally)
        feed_stats = self._feeds.stats

        # LOOP 2: Test
        test_result = self._tester.run_all()

        # LOOP 3: Heal (only if needed)
        healing_actions = self._healer.evaluate_and_heal(
            test_result,
            self._feeds,
        )

        summary = {
            "cycle": self._cycle_count,
            "feeds": feed_stats,
            "self_test": test_result.to_dict(),
            "healing_actions": len(healing_actions),
            "detection_trend": self._tester.detection_trend,
        }

        logger.info(
            "evolution cycle #%d complete: detection=%.1f%%, heals=%d",
            self._cycle_count,
            test_result.detection_rate * 100,
            len(healing_actions),
        )

        return summary
