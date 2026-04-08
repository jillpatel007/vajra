"""Chaos Simulator — 3 modes: dryrun, canary, live.

dryrun: reads monitoring rules, reports gaps, zero API calls.
canary: runs against account tagged Purpose=SecurityTesting.
live:   requires --i-have-written-authorisation flag.

Monitor integrations: GuardDuty, Azure Sentinel, GCP SCC, Alibaba ActionTrail.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ChaosMode(Enum):
    DRYRUN = "dryrun"
    CANARY = "canary"
    LIVE = "live"


@dataclass
class MonitoringGap:
    """A gap in monitoring coverage detected by chaos simulation."""

    monitor: str
    expected: str
    actual: str
    severity: str


@dataclass
class ChaosResult:
    """Result of a chaos simulation run."""

    mode: ChaosMode
    tests_run: int
    gaps_found: int
    gaps: list[MonitoringGap]
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )


class ChaosSimulator:
    """Simulates attacks to test monitoring coverage."""

    # Monitors we check for
    _MONITORS: tuple[str, ...] = (
        "aws_guardduty",
        "azure_sentinel",
        "gcp_scc",
        "alibaba_actiontrail",
    )

    def __init__(self, mode: ChaosMode = ChaosMode.DRYRUN) -> None:
        self._mode = mode
        self._results: list[ChaosResult] = []

    def run(
        self,
        monitor_config: dict[str, Any] | None = None,
        account_tags: dict[str, str] | None = None,
        authorisation: bool = False,
    ) -> ChaosResult:
        """Run chaos simulation in the configured mode."""
        if self._mode == ChaosMode.LIVE and not authorisation:
            raise PermissionError("live mode requires --i-have-written-authorisation")

        if self._mode == ChaosMode.CANARY:
            tags = account_tags or {}
            if tags.get("Purpose") != "SecurityTesting":
                raise PermissionError(
                    "canary mode requires Purpose=SecurityTesting tag"
                )

        config = monitor_config or {}
        gaps = self._check_monitoring_gaps(config)

        result = ChaosResult(
            mode=self._mode,
            tests_run=len(self._MONITORS),
            gaps_found=len(gaps),
            gaps=gaps,
        )
        self._results.append(result)
        return result

    def _check_monitoring_gaps(
        self,
        config: dict[str, Any],
    ) -> list[MonitoringGap]:
        """Check which monitors are missing or misconfigured."""
        gaps: list[MonitoringGap] = []

        for monitor in self._MONITORS:
            if monitor not in config:
                gaps.append(
                    MonitoringGap(
                        monitor=monitor,
                        expected="enabled",
                        actual="not configured",
                        severity="high",
                    )
                )
            elif not config[monitor].get("enabled", False):
                gaps.append(
                    MonitoringGap(
                        monitor=monitor,
                        expected="enabled",
                        actual="disabled",
                        severity="critical",
                    )
                )

        return gaps

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "mode": self._mode.value,
            "runs": len(self._results),
        }
