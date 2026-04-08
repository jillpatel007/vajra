"""Cedar Condition Evaluator — evaluates IAM conditions on graph edges.

WHY THIS MATTERS:
    An IAM policy might say "Allow s3:GetObject" but with a condition
    like "only from IP 10.0.0.0/8" or "only with MFA". Without
    evaluating conditions, Vajra would flag EVERY "Allow" as an
    attack path — massive false positives.

    Cedar evaluation is what drops our FP rate from ~60% to <15%.

SECURITY MODEL (from Forge 1 threat model):
    DEFAULT-DENY: If we can't evaluate a condition, the edge is
    marked UNKNOWN (not VALID). Unknown = flagged for human review.

    Why? Attack 2 from threat model: an attacker crafts conditions
    that Vajra doesn't understand, hoping they'll be skipped and
    the path will look "clean". Default-DENY prevents this.

CEDAR vs RAW IAM:
    Cedar is a policy language by AWS (open source). We use Cedar's
    evaluation model (not the full engine) to check conditions.
    Cedar's key principle: explicit deny > allow > implicit deny.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from vajra.core.models import EdgeValidity

logger = logging.getLogger(__name__)


class ConditionResult(Enum):
    """Result of evaluating a single IAM condition."""

    SATISFIED = "satisfied"  # Condition met → edge is valid
    NOT_SATISFIED = "not_satisfied"  # Condition blocks → edge blocked
    UNKNOWN = "unknown"  # Can't evaluate → default-DENY


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Full evaluation result for an edge's conditions."""

    validity: EdgeValidity
    conditions_checked: int
    conditions_satisfied: int
    conditions_unknown: int
    details: tuple[str, ...]


# ---------------------------------------------------------------------------
# Supported condition operators
# ---------------------------------------------------------------------------
# AWS IAM has ~30 condition operators. We start with the most common ones
# that appear in real attack paths. Each operator is a function that takes
# (condition_value, context_value) and returns ConditionResult.

_SUPPORTED_OPERATORS: frozenset[str] = frozenset(
    {
        "IpAddress",
        "NotIpAddress",
        "StringEquals",
        "StringNotEquals",
        "Bool",
        "DateGreaterThan",
        "DateLessThan",
        "ArnEquals",
        "ArnLike",
    }
)


class CedarEvaluator:
    """Evaluates IAM conditions to determine edge validity.

    Usage:
        evaluator = CedarEvaluator()
        result = evaluator.evaluate(conditions_dict, context)
        # result.validity → EdgeValidity.VALID / CONDITION_BLOCKED / UNKNOWN
    """

    def __init__(self) -> None:
        self._eval_count: int = 0
        self._unknown_count: int = 0

    @property
    def stats(self) -> dict[str, int]:
        """Return evaluation statistics."""
        return {
            "total_evaluations": self._eval_count,
            "unknown_conditions": self._unknown_count,
        }

    def evaluate(
        self,
        conditions: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> EvaluationResult:
        """Evaluate all conditions on an IAM policy statement.

        ┌─────────────────────────────────────────────────────────┐
        │  STUDENT WRITES THIS METHOD — the default-DENY logic    │
        │                                                         │
        │  Rules:                                                 │
        │  1. No conditions → ASSUMED_VALID (flag for review)     │
        │  2. ALL conditions satisfied → VALID                    │
        │  3. ANY condition not satisfied → CONDITION_BLOCKED     │
        │  4. ANY condition unknown → UNKNOWN (DEFAULT-DENY)      │
        │     Unknown must NOT be treated as valid!               │
        │  5. Track stats for FP rate monitoring                  │
        │                                                         │
        │  Think: what's safer — missing an attack path, or       │
        │  flagging a false positive? (FP > FN for security)      │
        └─────────────────────────────────────────────────────────┘

        Args:
            conditions: IAM condition block, e.g.:
                {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
            context: Current evaluation context (IP, time, MFA status).
                If None, we can't evaluate context-dependent conditions.

        Returns:
            EvaluationResult with validity and details.
        """
        self._eval_count += 1

        # No conditions → can't confirm safety, flag for review
        if not conditions:
            return EvaluationResult(
                validity=EdgeValidity.ASSUMED_VALID,
                conditions_checked=0,
                conditions_satisfied=0,
                conditions_unknown=0,
                details=(),
            )

        satisfied = 0
        blocked = 0
        unknown = 0
        details: list[str] = []

        for operator, key_values in conditions.items():
            for key, value in key_values.items():
                result = self._evaluate_single(
                    operator,
                    key,
                    value,
                    context,
                )
                detail = f"{operator}:{key}={result.value}"
                details.append(detail)
                if result == ConditionResult.SATISFIED:
                    satisfied += 1
                elif result == ConditionResult.NOT_SATISFIED:
                    blocked += 1
                else:
                    unknown += 1

        total = satisfied + blocked + unknown

        # --- THE SECURITY DECISION (Jill's fix) ---
        # Order matters: unknown first (default-DENY)
        if unknown > 0:
            validity = EdgeValidity.UNKNOWN
        elif blocked > 0:
            validity = EdgeValidity.CONDITION_BLOCKED
        else:
            validity = EdgeValidity.VALID

        self._unknown_count += unknown

        return EvaluationResult(
            validity=validity,
            conditions_checked=total,
            conditions_satisfied=satisfied,
            conditions_unknown=unknown,
            details=tuple(details),
        )

    def _evaluate_single(
        self,
        operator: str,
        key: str,
        value: Any,
        context: dict[str, Any] | None,
    ) -> ConditionResult:
        """Evaluate a single condition operator.

        This handles the mechanics of each operator type.
        The DECISION logic (what to do with results) is in evaluate().
        """
        if operator not in _SUPPORTED_OPERATORS:
            logger.debug("unsupported condition operator: %s", operator)
            return ConditionResult.UNKNOWN

        if context is None:
            return ConditionResult.UNKNOWN

        context_value = context.get(key)
        if context_value is None:
            return ConditionResult.UNKNOWN

        try:
            if operator == "IpAddress":
                return self._eval_ip_address(value, context_value)
            if operator == "NotIpAddress":
                result = self._eval_ip_address(value, context_value)
                return (
                    ConditionResult.NOT_SATISFIED
                    if result == ConditionResult.SATISFIED
                    else ConditionResult.SATISFIED
                )
            if operator == "StringEquals":
                return self._eval_string_equals(value, context_value)
            if operator == "StringNotEquals":
                result = self._eval_string_equals(value, context_value)
                return (
                    ConditionResult.NOT_SATISFIED
                    if result == ConditionResult.SATISFIED
                    else ConditionResult.SATISFIED
                )
            if operator == "Bool":
                return self._eval_bool(value, context_value)
            if operator == "DateGreaterThan":
                return self._eval_date_gt(value, context_value)
            if operator == "DateLessThan":
                return self._eval_date_lt(value, context_value)
            if operator in {"ArnEquals", "ArnLike"}:
                return self._eval_string_equals(value, context_value)
        except (ValueError, TypeError) as e:
            logger.warning(
                "condition evaluation error: %s %s = %s: %s",
                operator,
                key,
                value,
                e,
            )
            return ConditionResult.UNKNOWN

        return ConditionResult.UNKNOWN

    # --- Individual operator implementations ---

    def _eval_ip_address(
        self,
        cidr: Any,
        source_ip: Any,
    ) -> ConditionResult:
        """Check if source_ip falls within the CIDR range."""
        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
            addr = ipaddress.ip_address(str(source_ip))
            if addr in network:
                return ConditionResult.SATISFIED
            return ConditionResult.NOT_SATISFIED
        except ValueError:
            return ConditionResult.UNKNOWN

    def _eval_string_equals(
        self,
        expected: Any,
        actual: Any,
    ) -> ConditionResult:
        """Case-sensitive string comparison."""
        if str(expected) == str(actual):
            return ConditionResult.SATISFIED
        return ConditionResult.NOT_SATISFIED

    def _eval_bool(
        self,
        expected: Any,
        actual: Any,
    ) -> ConditionResult:
        """Boolean condition (e.g., aws:MultiFactorAuthPresent)."""
        expected_bool = str(expected).lower() == "true"
        actual_bool = str(actual).lower() == "true"
        if expected_bool == actual_bool:
            return ConditionResult.SATISFIED
        return ConditionResult.NOT_SATISFIED

    def _eval_date_gt(
        self,
        threshold: Any,
        actual: Any,
    ) -> ConditionResult:
        """Check if actual date is after threshold."""
        try:
            threshold_dt = datetime.fromisoformat(str(threshold))
            actual_dt = datetime.fromisoformat(str(actual))
            if actual_dt > threshold_dt:
                return ConditionResult.SATISFIED
            return ConditionResult.NOT_SATISFIED
        except ValueError:
            return ConditionResult.UNKNOWN

    def _eval_date_lt(
        self,
        threshold: Any,
        actual: Any,
    ) -> ConditionResult:
        """Check if actual date is before threshold."""
        try:
            threshold_dt = datetime.fromisoformat(str(threshold))
            actual_dt = datetime.fromisoformat(str(actual))
            if actual_dt < threshold_dt:
                return ConditionResult.SATISFIED
            return ConditionResult.NOT_SATISFIED
        except ValueError:
            return ConditionResult.UNKNOWN
