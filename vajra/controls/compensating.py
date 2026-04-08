"""Compensating Controls — reduces risk score when controls exist.

A compensating control is a security measure that mitigates risk
even when the vulnerability exists. Example:
    - WAF in front of vulnerable web app → risk reduced 80%
    - MFA on privileged role → risk reduced 70%
    - Network segmentation → risk reduced 60%

Loads from YAML config. Applies before risk scoring.
Marks affected paths as BLOCKED_BY_CONTROL.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CompensatingControl:
    """A control that reduces risk on matching paths."""

    name: str
    applies_to: str  # relation type or asset type pattern
    risk_reduction: float  # 0.0 to 1.0 (0.8 = 80% reduction)
    description: str


# Built-in compensating controls
_BUILTIN_CONTROLS: list[CompensatingControl] = [
    CompensatingControl(
        name="WAF Protection",
        applies_to="ec2_instance",
        risk_reduction=0.8,
        description="WAF blocks common web exploits",
    ),
    CompensatingControl(
        name="MFA Required",
        applies_to="can_assume",
        risk_reduction=0.7,
        description="MFA prevents credential-only attacks",
    ),
    CompensatingControl(
        name="Network Segmentation",
        applies_to="has_access",
        risk_reduction=0.6,
        description="VPC isolation limits blast radius",
    ),
    CompensatingControl(
        name="Encryption at Rest",
        applies_to="s3_bucket",
        risk_reduction=0.3,
        description="Encrypted data less valuable if exfiltrated",
    ),
]


class CompensatingControlRegistry:
    """Registry of compensating controls that reduce risk."""

    def __init__(self) -> None:
        self._controls: list[CompensatingControl] = list(
            _BUILTIN_CONTROLS,
        )
        self._active: dict[str, CompensatingControl] = {}

    def load_from_config(
        self,
        config: list[dict[str, Any]],
    ) -> int:
        """Load controls from YAML config."""
        count = 0
        for item in config:
            control = CompensatingControl(
                name=item.get("name", ""),
                applies_to=item.get("applies_to", ""),
                risk_reduction=item.get("risk_reduction", 0.5),
                description=item.get("description", ""),
            )
            self._controls.append(control)
            count += 1
        return count

    def activate(self, control_name: str) -> bool:
        """Activate a compensating control."""
        for control in self._controls:
            if control.name == control_name:
                self._active[control_name] = control
                logger.info("activated control: %s", control_name)
                return True
        return False

    def apply_to_risk(
        self,
        relation_type: str,
        asset_type: str,
        base_risk: float,
    ) -> tuple[float, list[str]]:
        """Apply active controls to reduce risk weight.

        Returns (adjusted_risk, list of applied control names).
        """
        applied: list[str] = []
        risk = base_risk

        for control in self._active.values():
            if control.applies_to == relation_type or control.applies_to == asset_type:
                risk *= 1.0 - control.risk_reduction
                applied.append(control.name)

        return round(risk, 4), applied

    @property
    def available(self) -> list[str]:
        """List all available control names."""
        return [c.name for c in self._controls]

    @property
    def active_count(self) -> int:
        return len(self._active)
