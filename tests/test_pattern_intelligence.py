"""Tests for Pattern Intelligence Engine.

Proves:
    1. Patterns accumulate with every scan
    2. Rarity scoring works (common = low, rare = high)
    3. Emerging threat detection triggers on frequency spikes
    4. Benchmarking grades organisations correctly
    5. Data persists between sessions
    6. Stats track correctly
"""

import tempfile
from pathlib import Path

from vajra.core.learning import StructuralFingerprint
from vajra.core.pattern_intelligence import PatternIntelligence


def _make_fp(
    edge_types: tuple[str, ...] = ("can_assume", "has_access"),
    pattern_hash: str | None = None,
) -> StructuralFingerprint:
    """Create a test fingerprint."""
    import hashlib

    pattern = " → ".join(edge_types)
    phash = (
        pattern_hash
        or hashlib.sha256(
            pattern.encode(),
        ).hexdigest()
    )
    return StructuralFingerprint(
        pattern_hash=phash,
        path_length=len(edge_types),
        edge_types=edge_types,
        has_priv_esc="can_assume" in edge_types,
        timestamp="2026-01-01T00:00:00",
    )


class TestPatternAccumulation:
    """Patterns grow with every scan."""

    def test_first_scan_creates_patterns(self) -> None:
        """First scan populates the pattern database."""
        tmp = Path(tempfile.mkdtemp()) / "patterns"
        pi = PatternIntelligence(store_path=tmp)

        fps = [_make_fp(), _make_fp(("has_access",))]
        pi.ingest_scan(fps)

        assert pi.stats["total_scans"] == 1
        assert pi.stats["unique_patterns"] == 2

    def test_duplicate_pattern_increases_frequency(self) -> None:
        """Same pattern in multiple scans → frequency goes up."""
        tmp = Path(tempfile.mkdtemp()) / "patterns"
        pi = PatternIntelligence(store_path=tmp)

        fp = _make_fp()
        pi.ingest_scan([fp])
        pi.ingest_scan([fp])
        pi.ingest_scan([fp])

        assert pi.stats["total_scans"] == 3
        assert pi.stats["unique_patterns"] == 1

    def test_data_persists_between_sessions(self) -> None:
        """Pattern data survives restart."""
        tmp = Path(tempfile.mkdtemp()) / "patterns"

        pi1 = PatternIntelligence(store_path=tmp)
        pi1.ingest_scan([_make_fp()])

        pi2 = PatternIntelligence(store_path=tmp)
        assert pi2.stats["total_scans"] == 1
        assert pi2.stats["unique_patterns"] == 1


class TestRarityScoring:
    """Rare patterns should score higher than common ones."""

    def test_common_pattern_low_rarity(self) -> None:
        """Pattern in every scan → rarity near 0."""
        tmp = Path(tempfile.mkdtemp()) / "patterns"
        pi = PatternIntelligence(store_path=tmp)

        fp = _make_fp()
        for _ in range(10):
            pi.ingest_scan([fp])

        rarity = pi.get_rarity_score(fp.pattern_hash)
        assert rarity < 0.1, f"common pattern should have low rarity, got {rarity}"

    def test_rare_pattern_high_rarity(self) -> None:
        """Pattern in 1 of 100 scans → rarity near 1."""
        tmp = Path(tempfile.mkdtemp()) / "patterns"
        pi = PatternIntelligence(store_path=tmp)

        common = _make_fp(("has_access",))
        rare = _make_fp(("supply_chain_risk", "can_assume", "has_access"))

        # 99 scans with only common pattern
        for _ in range(99):
            pi.ingest_scan([common])
        # 1 scan with rare pattern
        pi.ingest_scan([rare])

        common_rarity = pi.get_rarity_score(common.pattern_hash)
        rare_rarity = pi.get_rarity_score(rare.pattern_hash)

        assert rare_rarity > common_rarity, "rare pattern must score higher than common"

    def test_never_seen_pattern_maximum_rarity(self) -> None:
        """Pattern never ingested → rarity = 1.0."""
        tmp = Path(tempfile.mkdtemp()) / "patterns"
        pi = PatternIntelligence(store_path=tmp)
        pi.ingest_scan([_make_fp()])

        rarity = pi.get_rarity_score("never-seen-hash")
        assert rarity == 1.0


class TestEmergingThreats:
    """Detect patterns that appear suddenly and grow fast."""

    def test_no_threats_with_insufficient_data(self) -> None:
        """Less than baseline scans → no signals (avoid noise)."""
        tmp = Path(tempfile.mkdtemp()) / "patterns"
        pi = PatternIntelligence(store_path=tmp)
        pi.ingest_scan([_make_fp()])

        signals = pi.detect_emerging_threats(baseline_scans=10)
        assert len(signals) == 0

    def test_high_frequency_pattern_detected(self) -> None:
        """Pattern in >30% of scans → critical signal."""
        tmp = Path(tempfile.mkdtemp()) / "patterns"
        pi = PatternIntelligence(store_path=tmp)

        fp = _make_fp()
        for _ in range(10):
            pi.ingest_scan([fp])  # 100% frequency

        signals = pi.detect_emerging_threats(baseline_scans=5)
        assert len(signals) >= 1
        assert signals[0].severity == "critical"


class TestBenchmarking:
    """Organisation benchmarking against aggregate data."""

    def test_below_average_gets_good_grade(self) -> None:
        """Fewer paths than average → good grade."""
        tmp = Path(tempfile.mkdtemp()) / "patterns"
        pi = PatternIntelligence(store_path=tmp)

        # Create baseline: average 10 patterns per scan
        for _ in range(10):
            fps = [_make_fp((f"type_{i}",)) for i in range(10)]
            pi.ingest_scan(fps)

        benchmark = pi.get_benchmark(current_path_count=2)
        assert benchmark["grade"] in ("A", "B")

    def test_above_average_gets_bad_grade(self) -> None:
        """More paths than average → bad grade."""
        tmp = Path(tempfile.mkdtemp()) / "patterns"
        pi = PatternIntelligence(store_path=tmp)

        for _ in range(10):
            pi.ingest_scan([_make_fp()])

        benchmark = pi.get_benchmark(current_path_count=50)
        assert benchmark["grade"] in ("C", "D")

    def test_insufficient_data_reported(self) -> None:
        """No scans yet → status: insufficient_data."""
        tmp = Path(tempfile.mkdtemp()) / "patterns"
        pi = PatternIntelligence(store_path=tmp)
        benchmark = pi.get_benchmark(current_path_count=5)
        assert benchmark["status"] == "insufficient_data"


class TestPrivEscTracking:
    """Privilege escalation patterns tracked separately."""

    def test_priv_esc_patterns_counted(self) -> None:
        """Patterns with CAN_ASSUME flagged as priv_esc."""
        tmp = Path(tempfile.mkdtemp()) / "patterns"
        pi = PatternIntelligence(store_path=tmp)

        priv = _make_fp(("can_assume", "has_access"))
        no_priv = _make_fp(("has_access", "reads_from"))
        pi.ingest_scan([priv, no_priv])

        assert pi.stats["privilege_escalation_patterns"] == 1
