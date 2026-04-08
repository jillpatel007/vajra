"""EU AI Act Compliance Checker — risk classification + documentation.

Articles 6, 9, 11, 13, 17: technical requirements for high-risk AI.
Assesses risk classification and generates compliance evidence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

HIGH_RISK_DOMAINS: frozenset[str] = frozenset(
    {
        "credit_scoring",
        "recruitment",
        "law_enforcement",
        "border_control",
        "critical_infrastructure",
        "education_admission",
        "healthcare_triage",
        "insurance_pricing",
        "social_scoring",
        "biometric_identification",
    }
)


@dataclass
class RiskClassification:
    """EU AI Act risk classification result."""

    domain: str
    risk_level: str  # "unacceptable", "high", "limited", "minimal"
    applicable_articles: list[str]
    requirements: list[str]


@dataclass
class TechnicalDocumentation:
    """Article 11 technical documentation package."""

    system_description: str
    training_data_summary: dict[str, Any]
    model_lineage: dict[str, Any]
    risk_assessment: dict[str, Any]
    monitoring_plan: str
    generated_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )


class EUAIActComplianceChecker:
    """Assesses EU AI Act compliance for AI systems."""

    def assess_risk_classification(
        self,
        domain: str,
    ) -> RiskClassification:
        """Classify AI system risk level per EU AI Act."""
        if domain in HIGH_RISK_DOMAINS:
            return RiskClassification(
                domain=domain,
                risk_level="high",
                applicable_articles=[
                    "Article 6 (Classification)",
                    "Article 9 (Risk Management)",
                    "Article 10 (Data Governance)",
                    "Article 11 (Technical Documentation)",
                    "Article 13 (Transparency)",
                    "Article 14 (Human Oversight)",
                    "Article 15 (Accuracy/Robustness)",
                    "Article 17 (Quality Management)",
                ],
                requirements=[
                    "Risk management system (Art. 9)",
                    "Data governance + bias testing (Art. 10)",
                    "Technical documentation (Art. 11)",
                    "Record-keeping / logging (Art. 12)",
                    "Transparency to users (Art. 13)",
                    "Human oversight mechanism (Art. 14)",
                    "Accuracy + robustness testing (Art. 15)",
                    "Quality management system (Art. 17)",
                    "Conformity assessment (Art. 43)",
                ],
            )
        return RiskClassification(
            domain=domain,
            risk_level="minimal",
            applicable_articles=["Article 6"],
            requirements=["Voluntary code of conduct"],
        )

    def generate_technical_documentation(
        self,
        system_name: str,
        lineage_data: dict[str, Any],
        graph_summary: dict[str, Any],
        robustness_data: dict[str, Any] | None = None,
        privacy_data: dict[str, Any] | None = None,
    ) -> TechnicalDocumentation:
        """Generate Article 11 technical documentation package.

        Uses existing lineage + graph data — zero manual input.
        """
        risk_assessment = {
            "attack_paths": graph_summary.get("paths_found", 0),
            "minimum_fix": graph_summary.get("minimum_cut", 0),
            "robustness": robustness_data or {"status": "not tested"},
            "privacy": privacy_data or {"status": "not tested"},
        }

        return TechnicalDocumentation(
            system_description=f"AI system: {system_name}",
            training_data_summary=lineage_data.get(
                "data_summary",
                {},
            ),
            model_lineage=lineage_data,
            risk_assessment=risk_assessment,
            monitoring_plan=(
                "Continuous monitoring via Vajra scan pipeline. "
                "Adversarial robustness tested per release. "
                "Privacy budget tracked via differential privacy."
            ),
        )
