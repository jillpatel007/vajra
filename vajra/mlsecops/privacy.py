"""ML Privacy Scanner — membership inference + differential privacy compliance.

Membership inference: can an attacker determine if a specific record
was in the training data? AUC > 0.6 = HIGH risk, > 0.7 = CRITICAL.

Differential privacy: verifies epsilon budget is within acceptable
limits. epsilon > 10 = non-compliant for sensitive data.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum

logger = logging.getLogger(__name__)


class PrivacyRisk(StrEnum):
    """Privacy vulnerability classification."""

    LOW = "low"  # AUC < 0.6
    HIGH = "high"  # AUC 0.6-0.7
    CRITICAL = "critical"  # AUC > 0.7


@dataclass(frozen=True)
class MembershipInferenceResult:
    """Result of membership inference attack."""

    member_scores: list[float]
    non_member_scores: list[float]
    auc: float
    risk_level: PrivacyRisk
    recommendation: str


@dataclass(frozen=True)
class DPComplianceResult:
    """Differential privacy compliance check."""

    epsilon: float
    delta: float
    compliant: bool
    max_epsilon: float
    recommendation: str


class MLPrivacyScanner:
    """Tests ML models for privacy vulnerabilities."""

    def test_membership_inference(
        self,
        member_scores: list[float],
        non_member_scores: list[float],
    ) -> MembershipInferenceResult:
        """Compute AUC for membership inference attack.

        Higher AUC = model leaks more about training data.
        AUC 0.5 = random (no leakage), AUC 1.0 = perfect attack.

        Simple AUC approximation: compare mean scores.
        In production: use sklearn.metrics.roc_auc_score.
        """
        if not member_scores or not non_member_scores:
            return MembershipInferenceResult(
                member_scores=member_scores,
                non_member_scores=non_member_scores,
                auc=0.5,
                risk_level=PrivacyRisk.LOW,
                recommendation="insufficient data for testing",
            )

        # Simple AUC: fraction of member scores > non-member scores
        correct: float = 0
        total: int = 0
        for m in member_scores:
            for nm in non_member_scores:
                total += 1
                if m > nm:
                    correct += 1
                elif m == nm:
                    correct += 0.5

        auc = correct / total if total > 0 else 0.5

        if auc > 0.7:
            risk = PrivacyRisk.CRITICAL
            rec = (
                "CRITICAL: model memorises training data. "
                "Do NOT deploy on sensitive data without mitigation."
            )
        elif auc > 0.6:
            risk = PrivacyRisk.HIGH
            rec = (
                "HIGH: model leaks training data membership. "
                "Apply differential privacy or regularisation."
            )
        else:
            risk = PrivacyRisk.LOW
            rec = "Model shows acceptable privacy characteristics."

        return MembershipInferenceResult(
            member_scores=member_scores,
            non_member_scores=non_member_scores,
            auc=round(auc, 4),
            risk_level=risk,
            recommendation=rec,
        )

    def check_differential_privacy_compliance(
        self,
        epsilon: float,
        delta: float = 1e-5,
        max_epsilon: float = 10.0,
    ) -> DPComplianceResult:
        """Verify differential privacy epsilon is within budget.

        epsilon > 10 = non-compliant for sensitive data.
        GDPR requires privacy-by-design.
        """
        compliant = epsilon <= max_epsilon

        if not compliant:
            rec = (
                f"epsilon={epsilon} exceeds budget ({max_epsilon}). "
                "Reduce training epochs or increase noise."
            )
        else:
            rec = f"epsilon={epsilon} within budget ({max_epsilon})."

        return DPComplianceResult(
            epsilon=epsilon,
            delta=delta,
            compliant=compliant,
            max_epsilon=max_epsilon,
            recommendation=rec,
        )
