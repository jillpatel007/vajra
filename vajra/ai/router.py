"""Model Router — routes to haiku/sonnet/opus based on task complexity.

Why routing matters:
    Haiku:  Fast, cheap. Use for simple queries, classification.
    Sonnet: Balanced. Use for narratives, remediation plans.
    Opus:   Best quality. Use for complex chain analysis, rule writing.

Routing saves cost without sacrificing quality where it matters.
"""

from __future__ import annotations

import logging
from enum import Enum

logger = logging.getLogger(__name__)


class ModelTier(Enum):
    """Available model tiers."""

    HAIKU = "haiku"
    SONNET = "sonnet"
    OPUS = "opus"


# Cost per 1M tokens (input/output) — approximate
_MODEL_COSTS: dict[ModelTier, dict[str, float]] = {
    ModelTier.HAIKU: {"input": 0.25, "output": 1.25},
    ModelTier.SONNET: {"input": 3.0, "output": 15.0},
    ModelTier.OPUS: {"input": 15.0, "output": 75.0},
}

# Task complexity → model tier mapping
_TASK_ROUTING: dict[str, ModelTier] = {
    "narrate": ModelTier.SONNET,
    "verify": ModelTier.HAIKU,
    "remediate": ModelTier.SONNET,
    "query": ModelTier.HAIKU,
    "write_rule": ModelTier.OPUS,
}


class ModelRouter:
    """Routes AI tasks to the optimal model tier."""

    def __init__(
        self,
        override: ModelTier | None = None,
    ) -> None:
        self._override = override
        self._total_cost: float = 0.0
        self._call_count: int = 0

    def route(self, task: str) -> ModelTier:
        """Determine which model to use for a given task.

        If override is set, always use that model.
        Otherwise, route based on task complexity.
        """
        if self._override:
            return self._override

        tier = _TASK_ROUTING.get(task, ModelTier.SONNET)
        logger.debug("routed task '%s' to %s", task, tier.value)
        return tier

    def track_cost(
        self,
        tier: ModelTier,
        input_tokens: int,
        output_tokens: int,
    ) -> float:
        """Track cost of an AI call. Returns cost in USD."""
        costs = _MODEL_COSTS[tier]
        cost = (input_tokens / 1_000_000) * costs["input"] + (
            output_tokens / 1_000_000
        ) * costs["output"]
        self._total_cost += cost
        self._call_count += 1
        return round(cost, 6)

    @property
    def total_cost(self) -> float:
        """Total cost across all AI calls."""
        return round(self._total_cost, 4)

    @property
    def call_count(self) -> int:
        return self._call_count

    def get_model_name(self, tier: ModelTier) -> str:
        """Return the full model name for API calls."""
        names = {
            ModelTier.HAIKU: "claude-haiku-4-20250414",
            ModelTier.SONNET: "claude-sonnet-4-20250514",
            ModelTier.OPUS: "claude-opus-4-20250918",
        }
        return names[tier]
