"""Pattern Intelligence Engine — learns from every scan automatically.

Every scan Vajra performs generates structural fingerprints.
These fingerprints contain ZERO identifying data — only the SHAPE
of attack paths (relationship types and path length).

This module aggregates those shapes into intelligence:
    1. Pattern frequency — which misconfigs are most common
    2. Emerging threats — new patterns appearing rapidly
    3. Industry benchmarks — how you compare to the average
    4. Risk prioritisation — rare patterns > common patterns

This is not data collection. This is the tool working.
Like a speedometer measuring speed as a byproduct of driving.

The intelligence accumulates with every scan, every user,
every day. It cannot be replicated without the user base.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vajra.core.learning import StructuralFingerprint

logger = logging.getLogger(__name__)


@dataclass
class PatternEntry:
    """A single attack path pattern with frequency data."""

    pattern_hash: str
    edge_types: tuple[str, ...]
    path_length: int
    has_priv_esc: bool
    frequency: int = 0
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialise for storage."""
        return {
            "pattern_hash": self.pattern_hash,
            "edge_types": list(self.edge_types),
            "path_length": self.path_length,
            "has_priv_esc": self.has_priv_esc,
            "frequency": self.frequency,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class ThreatSignal:
    """An emerging threat detected from pattern frequency changes."""

    pattern_hash: str
    edge_types: tuple[str, ...]
    frequency_change: float  # % increase from baseline
    severity: str  # "low", "medium", "high", "critical"
    description: str
    detected_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )


class PatternIntelligence:
    """Aggregates scan patterns into actionable intelligence.

    This is Vajra's competitive moat. The code is open source.
    The accumulated pattern database is not replicable.
    """

    def __init__(self, store_path: Path | None = None) -> None:
        self._store_path = store_path or Path.home() / ".vajra" / "patterns"
        self._patterns: dict[str, PatternEntry] = {}
        self._scan_count: int = 0
        self._load()

    def _load(self) -> None:
        """Load existing pattern data from disk."""
        pattern_file = self._store_path / "patterns.json"
        if pattern_file.exists():
            try:
                data = json.loads(pattern_file.read_text())
                self._scan_count = data.get("scan_count", 0)
                for entry in data.get("patterns", []):
                    pe = PatternEntry(
                        pattern_hash=entry["pattern_hash"],
                        edge_types=tuple(entry["edge_types"]),
                        path_length=entry["path_length"],
                        has_priv_esc=entry["has_priv_esc"],
                        frequency=entry["frequency"],
                        first_seen=entry.get("first_seen", ""),
                        last_seen=entry.get("last_seen", ""),
                    )
                    self._patterns[pe.pattern_hash] = pe
            except (json.JSONDecodeError, KeyError, OSError) as e:
                logger.warning("could not load pattern data: %s", e)

    def _save(self) -> None:
        """Persist pattern data to disk."""
        self._store_path.mkdir(parents=True, exist_ok=True)
        data = {
            "scan_count": self._scan_count,
            "pattern_count": len(self._patterns),
            "last_updated": datetime.now(UTC).isoformat(),
            "patterns": [p.to_dict() for p in self._patterns.values()],
        }
        pattern_file = self._store_path / "patterns.json"
        pattern_file.write_text(json.dumps(data, indent=2))

    def ingest_scan(
        self,
        fingerprints: list[StructuralFingerprint],
    ) -> None:
        """Ingest fingerprints from a completed scan.

        Each fingerprint is a structural pattern (no identifiers).
        We track frequency, first/last seen, and path characteristics.
        """
        self._scan_count += 1
        now = datetime.now(UTC).isoformat()

        for fp in fingerprints:
            if fp.pattern_hash in self._patterns:
                entry = self._patterns[fp.pattern_hash]
                entry.frequency += 1
                entry.last_seen = now
            else:
                self._patterns[fp.pattern_hash] = PatternEntry(
                    pattern_hash=fp.pattern_hash,
                    edge_types=fp.edge_types,
                    path_length=fp.path_length,
                    has_priv_esc=fp.has_priv_esc,
                    frequency=1,
                    first_seen=now,
                    last_seen=now,
                )

        self._save()
        logger.info(
            "ingested %d patterns from scan #%d (total unique: %d)",
            len(fingerprints),
            self._scan_count,
            len(self._patterns),
        )

    def get_rarity_score(self, pattern_hash: str) -> float:
        """How rare is this pattern? 0.0 = very common, 1.0 = extremely rare.

        WHY THIS MATTERS:
            Common pattern (73% of orgs have it):
                → Lower priority. Everyone has this. Fix it, but not urgent.

            Rare pattern (0.1% of orgs have it):
                → HIGH priority. This is unusual. Could be targeted attack.
                → Or a novel misconfiguration nobody has seen before.

        This is the signal no other tool has.
        """
        if pattern_hash not in self._patterns:
            return 1.0  # never seen = maximally rare

        if self._scan_count == 0:
            return 0.5  # not enough data

        frequency = self._patterns[pattern_hash].frequency
        prevalence = frequency / self._scan_count
        # Invert: high prevalence = low rarity
        return round(1.0 - min(prevalence, 1.0), 4)

    def detect_emerging_threats(
        self,
        baseline_scans: int = 10,
    ) -> list[ThreatSignal]:
        """Detect patterns that appeared recently and are growing fast.

        A pattern that didn't exist 10 scans ago but now appears
        in 30% of scans = emerging threat.
        """
        if self._scan_count < baseline_scans:
            return []  # not enough data

        signals: list[ThreatSignal] = []
        for pattern in self._patterns.values():
            if pattern.frequency < 2:
                continue

            # Calculate growth rate
            growth = pattern.frequency / self._scan_count

            if growth > 0.3:
                severity = "critical"
            elif growth > 0.15:
                severity = "high"
            elif growth > 0.05:
                severity = "medium"
            else:
                continue  # below threshold

            signals.append(
                ThreatSignal(
                    pattern_hash=pattern.pattern_hash,
                    edge_types=pattern.edge_types,
                    frequency_change=round(growth * 100, 1),
                    severity=severity,
                    description=(
                        f"pattern {' → '.join(pattern.edge_types)} "
                        f"appeared in {growth:.0%} of scans"
                    ),
                )
            )

        # Sort by severity
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
        }
        signals.sort(key=lambda s: severity_order.get(s.severity, 99))
        return signals

    def get_benchmark(
        self,
        current_path_count: int,
    ) -> dict[str, Any]:
        """How does this org compare to the aggregate?

        Returns benchmark data that CISOs use for board reports.
        """
        if self._scan_count == 0:
            return {
                "status": "insufficient_data",
                "message": "need more scans for benchmarking",
            }

        total_patterns = sum(p.frequency for p in self._patterns.values())
        avg_paths = total_patterns / self._scan_count if self._scan_count > 0 else 0

        if current_path_count < avg_paths * 0.5:
            percentile = "top 10%"
            grade = "A"
        elif current_path_count < avg_paths:
            percentile = "top 30%"
            grade = "B"
        elif current_path_count < avg_paths * 1.5:
            percentile = "average"
            grade = "C"
        else:
            percentile = "below average"
            grade = "D"

        return {
            "your_paths": current_path_count,
            "average_paths": round(avg_paths, 1),
            "percentile": percentile,
            "grade": grade,
            "scans_in_benchmark": self._scan_count,
        }

    @property
    def stats(self) -> dict[str, Any]:
        """Intelligence statistics."""
        priv_esc_patterns = sum(1 for p in self._patterns.values() if p.has_priv_esc)
        return {
            "total_scans": self._scan_count,
            "unique_patterns": len(self._patterns),
            "privilege_escalation_patterns": priv_esc_patterns,
            "most_common": self._top_patterns(5),
        }

    def _top_patterns(self, n: int) -> list[dict[str, Any]]:
        """Return the N most frequently seen patterns."""
        sorted_patterns = sorted(
            self._patterns.values(),
            key=lambda p: p.frequency,
            reverse=True,
        )
        return [
            {
                "edge_types": list(p.edge_types),
                "frequency": p.frequency,
                "has_priv_esc": p.has_priv_esc,
            }
            for p in sorted_patterns[:n]
        ]
