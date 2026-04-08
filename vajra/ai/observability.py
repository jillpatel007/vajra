"""Observability Layer — traces every AI call.

Wraps AILayer to track: input tokens, output tokens, cost,
prompt version, latency. In production: sends to Langfuse.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


@dataclass
class AITrace:
    """A single traced AI call."""

    function: str
    model_tier: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    latency_ms: float
    prompt_version: str = "v1"
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )
    success: bool = True


class ObservableAILayer:
    """Wraps AILayer with full observability."""

    def __init__(self) -> None:
        self._traces: list[AITrace] = []

    def record(
        self,
        function: str,
        model_tier: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        latency_ms: float,
        success: bool = True,
    ) -> AITrace:
        """Record an AI call trace."""
        trace = AITrace(
            function=function,
            model_tier=model_tier,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            success=success,
        )
        self._traces.append(trace)
        return trace

    def cost_per_finding(self, finding_count: int) -> float:
        """Calculate average AI cost per security finding."""
        if finding_count == 0:
            return 0.0
        total = sum(t.cost_usd for t in self._traces)
        return round(total / finding_count, 6)

    @property
    def total_cost(self) -> float:
        return round(sum(t.cost_usd for t in self._traces), 4)

    @property
    def total_calls(self) -> int:
        return len(self._traces)

    @property
    def traces(self) -> list[AITrace]:
        return list(self._traces)
