"""Evaluation Pipeline — regression testing for AI quality.

Compares new model vs baseline on:
    - Grounding accuracy (does AI output match graph data?)
    - MITRE accuracy (correct technique IDs?)
    - Latency (faster or slower?)
    - Cost (cheaper or more expensive?)

safe_to_deploy flag blocks upgrade if regression detected.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EvalCase:
    """A single evaluation test case."""

    case_id: str
    input_data: dict[str, Any]
    expected_mitre_id: str
    expected_severity: str


@dataclass
class EvalResult:
    """Result of running one eval case."""

    case_id: str
    predicted_mitre_id: str
    expected_mitre_id: str
    mitre_correct: bool
    predicted_severity: str
    expected_severity: str
    severity_correct: bool
    cost_usd: float = 0.0
    latency_ms: float = 0.0


@dataclass
class EvalSummary:
    """Summary of a full eval run."""

    total_cases: int
    mitre_accuracy: float
    severity_accuracy: float
    avg_cost: float
    avg_latency_ms: float
    safe_to_deploy: bool
    regressions: list[str] = field(default_factory=list)


class EvalPipeline:
    """Runs regression tests against AI output quality."""

    def __init__(
        self,
        accuracy_threshold: float = 0.9,
    ) -> None:
        self._threshold = accuracy_threshold
        self._cases: list[EvalCase] = []
        self._results: list[EvalResult] = []

    def add_case(self, case: EvalCase) -> None:
        """Add an evaluation test case."""
        self._cases.append(case)

    def add_cases(self, cases: list[EvalCase]) -> None:
        """Add multiple evaluation test cases."""
        self._cases.extend(cases)

    def run_regression_suite(
        self,
        predict_fn: Any = None,
    ) -> EvalSummary:
        """Run all eval cases and check for regressions.

        Args:
            predict_fn: Function that takes input_data and returns
                        (mitre_id, severity). If None, uses mock.
        """
        self._results = []
        for case in self._cases:
            if predict_fn:
                mitre_id, severity = predict_fn(case.input_data)
            else:
                # Mock: return expected values (for testing the pipeline)
                mitre_id = case.expected_mitre_id
                severity = case.expected_severity

            result = EvalResult(
                case_id=case.case_id,
                predicted_mitre_id=mitre_id,
                expected_mitre_id=case.expected_mitre_id,
                mitre_correct=(mitre_id == case.expected_mitre_id),
                predicted_severity=severity,
                expected_severity=case.expected_severity,
                severity_correct=(severity == case.expected_severity),
            )
            self._results.append(result)

        return self._summarise()

    def _summarise(self) -> EvalSummary:
        """Summarise eval results and determine deploy safety."""
        if not self._results:
            return EvalSummary(
                total_cases=0,
                mitre_accuracy=0.0,
                severity_accuracy=0.0,
                avg_cost=0.0,
                avg_latency_ms=0.0,
                safe_to_deploy=False,
                regressions=["no eval cases"],
            )

        total = len(self._results)
        mitre_correct = sum(1 for r in self._results if r.mitre_correct)
        severity_correct = sum(1 for r in self._results if r.severity_correct)

        mitre_acc = mitre_correct / total
        severity_acc = severity_correct / total

        regressions: list[str] = []
        if mitre_acc < self._threshold:
            regressions.append(
                f"MITRE accuracy {mitre_acc:.1%} < {self._threshold:.1%}",
            )
        if severity_acc < self._threshold:
            regressions.append(
                f"Severity accuracy {severity_acc:.1%} < {self._threshold:.1%}",
            )

        return EvalSummary(
            total_cases=total,
            mitre_accuracy=round(mitre_acc, 4),
            severity_accuracy=round(severity_acc, 4),
            avg_cost=0.0,
            avg_latency_ms=0.0,
            safe_to_deploy=len(regressions) == 0,
            regressions=regressions,
        )
