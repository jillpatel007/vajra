"""Adversarial Robustness Tester — FGSM attack implementation.

FGSM (Fast Gradient Sign Method): perturbs input along gradient
direction to fool classifier. If attack success > 10%, model
needs robustness training before production deployment.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class RobustnessLevel(StrEnum):
    """Classification of model robustness."""

    ROBUST = "robust"  # <5% attack success
    MODERATE = "moderate"  # 5-10% attack success
    VULNERABLE = "vulnerable"  # >10% attack success
    CRITICAL = "critical"  # >25% attack success


@dataclass(frozen=True)
class RobustnessReport:
    """Result of adversarial robustness testing."""

    attack_type: str
    samples_tested: int
    samples_fooled: int
    attack_success_rate: float
    robustness_level: RobustnessLevel
    recommendation: str


class AdversarialRobustnessTester:
    """Tests model robustness against adversarial attacks."""

    def fgsm_attack(
        self,
        model_predictions: list[dict[str, Any]],
        perturbed_predictions: list[dict[str, Any]],
    ) -> RobustnessReport:
        """Evaluate FGSM attack success rate.

        Compares original predictions to predictions on
        perturbed inputs. If prediction changed → attack succeeded.

        Args:
            model_predictions: [{"input_id": "x", "label": "cat"}]
            perturbed_predictions: [{"input_id": "x", "label": "dog"}]
        """
        if not model_predictions:
            return RobustnessReport(
                attack_type="fgsm",
                samples_tested=0,
                samples_fooled=0,
                attack_success_rate=0.0,
                robustness_level=RobustnessLevel.ROBUST,
                recommendation="no samples to test",
            )

        # Map original predictions by input_id
        original: dict[str, str] = {
            p["input_id"]: p["label"] for p in model_predictions
        }

        fooled = 0
        for perturbed in perturbed_predictions:
            input_id = perturbed["input_id"]
            if input_id in original:
                if original[input_id] != perturbed["label"]:
                    fooled += 1

        total = len(model_predictions)
        rate = fooled / total if total > 0 else 0.0

        # Classify robustness
        if rate > 0.25:
            level = RobustnessLevel.CRITICAL
            rec = "BLOCK deployment. Adversarial training required."
        elif rate > 0.10:
            level = RobustnessLevel.VULNERABLE
            rec = "Adversarial training recommended before production."
        elif rate > 0.05:
            level = RobustnessLevel.MODERATE
            rec = "Monitor in production. Consider robustness training."
        else:
            level = RobustnessLevel.ROBUST
            rec = "Model is robust against FGSM at tested epsilon."

        return RobustnessReport(
            attack_type="fgsm",
            samples_tested=total,
            samples_fooled=fooled,
            attack_success_rate=round(rate, 4),
            robustness_level=level,
            recommendation=rec,
        )
