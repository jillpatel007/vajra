"""Context Architect — manages token budget for AI prompts.

3 strategies:
    RELEVANT_FIRST:  semantic similarity (default)
    CRITICAL_FIRST:  high-severity findings regardless of relevance
    TEMPORAL_FIRST:  most recent findings first

Respects 180K token limit. Graceful cutoff when context fills.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# Approximate tokens per character (English text)
_CHARS_PER_TOKEN = 4
_DEFAULT_TOKEN_BUDGET = 180_000


class ContextStrategy(Enum):
    """How to prioritise findings in the context window."""

    RELEVANT_FIRST = "relevant_first"
    CRITICAL_FIRST = "critical_first"
    TEMPORAL_FIRST = "temporal_first"


_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class ContextArchitect:
    """Builds context within token budget for AI prompts."""

    def __init__(
        self,
        token_budget: int = _DEFAULT_TOKEN_BUDGET,
    ) -> None:
        self._budget = token_budget
        self._tokens_used: int = 0

    def build_context(
        self,
        findings: list[dict[str, Any]],
        strategy: ContextStrategy = ContextStrategy.RELEVANT_FIRST,
    ) -> list[dict[str, Any]]:
        """Select findings that fit within token budget.

        Returns a subset of findings, ordered by strategy.
        """
        # Sort by strategy
        if strategy == ContextStrategy.CRITICAL_FIRST:
            sorted_findings = sorted(
                findings,
                key=lambda f: _SEVERITY_ORDER.get(
                    f.get("severity", "info"),
                    99,
                ),
            )
        elif strategy == ContextStrategy.TEMPORAL_FIRST:
            sorted_findings = sorted(
                findings,
                key=lambda f: f.get("timestamp", ""),
                reverse=True,
            )
        else:
            # RELEVANT_FIRST: assume already ordered by relevance
            sorted_findings = list(findings)

        # Pack within budget
        selected: list[dict[str, Any]] = []
        self._tokens_used = 0

        for finding in sorted_findings:
            tokens = self._estimate_tokens(finding)
            if self._tokens_used + tokens > self._budget:
                logger.debug(
                    "context budget reached at %d tokens (%d findings selected)",
                    self._tokens_used,
                    len(selected),
                )
                break
            selected.append(finding)
            self._tokens_used += tokens

        return selected

    @staticmethod
    def _estimate_tokens(finding: dict[str, Any]) -> int:
        """Estimate token count for a finding."""
        text = str(finding)
        return max(1, len(text) // _CHARS_PER_TOKEN)

    @property
    def tokens_used(self) -> int:
        return self._tokens_used

    @property
    def tokens_remaining(self) -> int:
        return max(0, self._budget - self._tokens_used)
