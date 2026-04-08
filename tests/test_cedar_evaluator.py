"""Tests for Cedar Condition Evaluator.

Proves:
    1. Default-DENY: unknown conditions → UNKNOWN (not VALID)
    2. All satisfied → VALID
    3. Any blocked → CONDITION_BLOCKED
    4. No conditions → ASSUMED_VALID
    5. IP range evaluation works correctly
    6. MFA boolean evaluation works correctly
"""

from vajra.analysis.cedar_evaluator import CedarEvaluator
from vajra.core.models import EdgeValidity


def test_no_conditions_returns_assumed_valid() -> None:
    """Empty conditions → ASSUMED_VALID, flagged for review."""
    evaluator = CedarEvaluator()
    result = evaluator.evaluate({})
    assert result.validity == EdgeValidity.ASSUMED_VALID
    assert result.conditions_checked == 0


def test_all_satisfied_returns_valid() -> None:
    """All conditions met → VALID edge."""
    evaluator = CedarEvaluator()
    conditions = {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
    context = {"aws:SourceIp": "10.0.1.50"}
    result = evaluator.evaluate(conditions, context)
    assert result.validity == EdgeValidity.VALID
    assert result.conditions_satisfied == 1


def test_blocked_condition_returns_blocked() -> None:
    """IP outside range → CONDITION_BLOCKED."""
    evaluator = CedarEvaluator()
    conditions = {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
    context = {"aws:SourceIp": "192.168.1.1"}
    result = evaluator.evaluate(conditions, context)
    assert result.validity == EdgeValidity.CONDITION_BLOCKED


def test_unknown_condition_returns_unknown_default_deny() -> None:
    """Unknown operator → UNKNOWN (DEFAULT-DENY, not VALID).

    This is the critical security test. An attacker crafts a condition
    Vajra can't evaluate. Default-DENY means we flag it, not skip it.
    """
    evaluator = CedarEvaluator()
    conditions = {"CustomOperator": {"custom:Key": "sneaky-value"}}
    context = {"custom:Key": "sneaky-value"}
    result = evaluator.evaluate(conditions, context)
    assert result.validity == EdgeValidity.UNKNOWN
    assert result.conditions_unknown == 1


def test_unknown_trumps_satisfied() -> None:
    """If ANY condition is unknown, entire result is UNKNOWN.

    Even if 9 conditions pass and 1 is unknown, default-DENY kicks in.
    """
    evaluator = CedarEvaluator()
    conditions = {
        "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
        "WeirdOperator": {"custom:Flag": "true"},
    }
    context = {"aws:SourceIp": "10.0.1.50", "custom:Flag": "true"}
    result = evaluator.evaluate(conditions, context)
    assert result.validity == EdgeValidity.UNKNOWN


def test_no_context_returns_unknown() -> None:
    """No context provided → can't evaluate → UNKNOWN (default-DENY)."""
    evaluator = CedarEvaluator()
    conditions = {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
    result = evaluator.evaluate(conditions, context=None)
    assert result.validity == EdgeValidity.UNKNOWN


def test_mfa_required_satisfied() -> None:
    """MFA condition met → VALID."""
    evaluator = CedarEvaluator()
    conditions = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    context = {"aws:MultiFactorAuthPresent": "true"}
    result = evaluator.evaluate(conditions, context)
    assert result.validity == EdgeValidity.VALID


def test_mfa_required_not_satisfied() -> None:
    """MFA condition not met → CONDITION_BLOCKED."""
    evaluator = CedarEvaluator()
    conditions = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    context = {"aws:MultiFactorAuthPresent": "false"}
    result = evaluator.evaluate(conditions, context)
    assert result.validity == EdgeValidity.CONDITION_BLOCKED


def test_stats_tracking() -> None:
    """Verify evaluation stats are tracked correctly."""
    evaluator = CedarEvaluator()
    evaluator.evaluate({})
    evaluator.evaluate(
        {"WeirdOp": {"k": "v"}},
        {"k": "v"},
    )
    stats = evaluator.stats
    assert stats["total_evaluations"] == 2
    assert stats["unknown_conditions"] == 1
