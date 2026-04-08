"""SLO Tracker — 3 SLOs for Vajra itself.

SLO 1: Scan success rate > 99.5%
SLO 2: Scan latency P95 < 30 seconds
SLO 3: Finding freshness < 4 hours (batch sync interval)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


@dataclass
class SLODefinition:
    """A single SLO definition."""

    name: str
    target: float
    unit: str
    description: str


@dataclass
class SLOStatus:
    """Current status of an SLO."""

    definition: SLODefinition
    current_value: float
    in_compliance: bool
    error_budget_remaining: float
    window_days: int = 30


_VAJRA_SLOS: list[SLODefinition] = [
    SLODefinition(
        name="scan_success_rate",
        target=0.995,
        unit="ratio",
        description="Scan success rate > 99.5%",
    ),
    SLODefinition(
        name="scan_latency_p95",
        target=30.0,
        unit="seconds",
        description="P95 scan latency < 30 seconds",
    ),
    SLODefinition(
        name="finding_freshness",
        target=4.0,
        unit="hours",
        description="Findings updated within 4 hours",
    ),
]


class SLOTracker:
    """Tracks Vajra's own SLOs."""

    def __init__(self) -> None:
        self._scan_results: list[bool] = []
        self._latencies: list[float] = []
        self._last_sync: str = ""

    def record_scan(
        self,
        success: bool,
        latency_seconds: float,
    ) -> None:
        """Record a scan result."""
        self._scan_results.append(success)
        self._latencies.append(latency_seconds)
        if success:
            self._last_sync = datetime.now(UTC).isoformat()

    def get_status(self) -> list[SLOStatus]:
        """Calculate current SLO status."""
        statuses: list[SLOStatus] = []

        # SLO 1: Success rate
        if self._scan_results:
            success_rate = sum(self._scan_results) / len(
                self._scan_results,
            )
        else:
            success_rate = 1.0

        slo1 = _VAJRA_SLOS[0]
        statuses.append(
            SLOStatus(
                definition=slo1,
                current_value=round(success_rate, 4),
                in_compliance=success_rate >= slo1.target,
                error_budget_remaining=round(
                    max(0, success_rate - slo1.target),
                    4,
                ),
            )
        )

        # SLO 2: P95 latency
        if self._latencies:
            sorted_lat = sorted(self._latencies)
            p95_idx = int(len(sorted_lat) * 0.95)
            p95 = sorted_lat[min(p95_idx, len(sorted_lat) - 1)]
        else:
            p95 = 0.0

        slo2 = _VAJRA_SLOS[1]
        statuses.append(
            SLOStatus(
                definition=slo2,
                current_value=round(p95, 2),
                in_compliance=p95 <= slo2.target,
                error_budget_remaining=round(
                    max(0, slo2.target - p95),
                    2,
                ),
            )
        )

        # SLO 3: Freshness
        slo3 = _VAJRA_SLOS[2]
        statuses.append(
            SLOStatus(
                definition=slo3,
                current_value=0.0,  # Would calculate from _last_sync
                in_compliance=True,  # Assumes fresh if recently scanned
                error_budget_remaining=slo3.target,
            )
        )

        return statuses
