"""Weight Calibrator — calibrates risk weights from feedback.

Uses trimmed mean to defend against feedback poisoning.
Bulk-closed feedback contributes zero to calibration.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class WeightCalibrator:
    """Calibrates edge risk weights from user feedback."""

    def __init__(self, trim_pct: float = 0.1) -> None:
        self._trim_pct = trim_pct
        self._feedbacks: dict[str, list[float]] = {}

    def add_feedback(
        self,
        relation_type: str,
        confirmed: bool,
        weight_override: float | None = None,
        bulk_closed: bool = False,
    ) -> None:
        """Record feedback for a relation type.

        bulk_closed = True means user closed without reviewing.
        These are excluded from calibration (poisoning defence).
        """
        if bulk_closed:
            return  # Ignore bulk-closed feedback

        if relation_type not in self._feedbacks:
            self._feedbacks[relation_type] = []

        if weight_override is not None:
            self._feedbacks[relation_type].append(weight_override)
        else:
            # Confirmed = weight stays, not confirmed = lower weight
            self._feedbacks[relation_type].append(
                1.0 if confirmed else 0.0,
            )

    def calibrate(self, relation_type: str) -> float | None:
        """Calculate calibrated weight using trimmed mean.

        Trimmed mean removes top/bottom 10% of feedback values
        to defend against poisoning attacks.
        """
        values = self._feedbacks.get(relation_type, [])
        if len(values) < 3:
            return None  # Not enough data

        sorted_vals = sorted(values)
        trim_count = max(1, int(len(sorted_vals) * self._trim_pct))
        trimmed = (
            sorted_vals[trim_count:-trim_count]
            if trim_count < len(sorted_vals) // 2
            else sorted_vals
        )

        if not trimmed:
            return None

        return sum(trimmed) / len(trimmed)

    def get_all_calibrations(self) -> dict[str, float | None]:
        """Get calibrated weights for all relation types."""
        return {rt: self.calibrate(rt) for rt in self._feedbacks}

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "relation_types": len(self._feedbacks),
            "total_feedbacks": sum(len(v) for v in self._feedbacks.values()),
        }
