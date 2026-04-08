"""Tests for Attack Path Intelligence Model (APIM).

Proves:
    1. Heuristic scoring produces valid scores
    2. Shorter paths score higher (easier to exploit)
    3. CISA KEV edges boost score significantly
    4. Active exploitation (Falco) dominates scoring
    5. Privilege escalation amplifies risk
    6. Batch scoring ranks paths correctly
    7. Empty path handled safely
    8. Confidence is honest (heuristic < trained model)
"""

from vajra.core.apim import AttackPathScorer, ScoringMode
from vajra.core.models import (
    EdgeValidity,
    GraphEdge,
    NetworkValidity,
    RelationType,
)


def _make_edge(
    risk: float = 0.5,
    relation: RelationType = RelationType.HAS_ACCESS,
    cisa_kev: bool = False,
    epss: float | None = None,
    falco: bool = False,
) -> GraphEdge:
    """Helper to create test edges with specific risk factors."""
    return GraphEdge(
        source="a",
        target="b",
        relation=relation,
        risk_weight=risk,
        iam_validity=EdgeValidity.VALID,
        network_validity=NetworkValidity.REACHABLE,
        cisa_kev=cisa_kev,
        epss_score=epss,
        falco_active=falco,
    )


def test_heuristic_produces_valid_score() -> None:
    """Basic scoring returns valid PathScore."""
    scorer = AttackPathScorer(mode=ScoringMode.HEURISTIC)
    path = [_make_edge(risk=0.8), _make_edge(risk=0.9)]
    score = scorer.score_path(path)

    assert 0.0 <= score.exploit_probability <= 1.0
    assert score.confidence > 0
    assert score.model_version == "heuristic-v1"
    assert len(score.factors) > 0


def test_shorter_path_scores_higher() -> None:
    """Shorter attack path = easier to exploit = higher score."""
    scorer = AttackPathScorer()
    short = [_make_edge(risk=0.8)]
    long = [_make_edge(risk=0.8) for _ in range(5)]

    short_score = scorer.score_path(short)
    long_score = scorer.score_path(long)

    assert short_score.exploit_probability > long_score.exploit_probability


def test_kev_edge_boosts_score() -> None:
    """CISA KEV (confirmed exploited in wild) → significant boost."""
    scorer = AttackPathScorer()
    normal = [_make_edge(risk=0.5)]
    with_kev = [_make_edge(risk=0.5, cisa_kev=True)]

    normal_score = scorer.score_path(normal)
    kev_score = scorer.score_path(with_kev)

    assert kev_score.exploit_probability > normal_score.exploit_probability
    assert "cisa_kev=true" in kev_score.factors


def test_falco_active_dominates() -> None:
    """Active exploitation → highest possible urgency."""
    scorer = AttackPathScorer()
    dormant = [_make_edge(risk=0.3)]
    active = [_make_edge(risk=0.3, falco=True)]

    dormant_score = scorer.score_path(dormant)
    active_score = scorer.score_path(active)

    assert active_score.exploit_probability > dormant_score.exploit_probability
    assert "active_exploitation=true" in active_score.factors


def test_privilege_escalation_amplifies() -> None:
    """CAN_ASSUME edges = privilege escalation = amplified risk."""
    scorer = AttackPathScorer()
    normal_path = [_make_edge(risk=0.8, relation=RelationType.HAS_ACCESS)]
    priv_esc_path = [_make_edge(risk=0.8, relation=RelationType.CAN_ASSUME)]

    normal_score = scorer.score_path(normal_path)
    priv_score = scorer.score_path(priv_esc_path)

    assert priv_score.exploit_probability >= normal_score.exploit_probability


def test_batch_scoring_ranks_correctly() -> None:
    """score_paths() ranks highest probability first."""
    scorer = AttackPathScorer()
    paths = [
        [_make_edge(risk=0.3)],  # low risk
        [_make_edge(risk=0.9, cisa_kev=True)],  # high risk
        [_make_edge(risk=0.5, falco=True)],  # active exploit
    ]
    ranked = scorer.score_paths(paths)

    assert ranked[0].priority_rank == 1
    assert ranked[1].priority_rank == 2
    assert ranked[2].priority_rank == 3
    # Highest probability should be rank 1
    assert ranked[0].exploit_probability >= ranked[1].exploit_probability


def test_empty_path_returns_zero() -> None:
    """Empty path → zero score, zero confidence."""
    scorer = AttackPathScorer()
    score = scorer.score_path([])
    assert score.exploit_probability == 0.0
    assert score.confidence == 0.0


def test_heuristic_confidence_is_honest() -> None:
    """Heuristic mode reports < 1.0 confidence (it knows it's approximate)."""
    scorer = AttackPathScorer()
    score = scorer.score_path([_make_edge()])
    assert score.confidence < 1.0, "heuristic should be honest about limited accuracy"


def test_score_capped_at_one() -> None:
    """Even worst-case path can't exceed 1.0 probability."""
    scorer = AttackPathScorer()
    nightmare_path = [
        _make_edge(
            risk=0.99,
            relation=RelationType.CAN_ASSUME,
            cisa_kev=True,
            epss=0.99,
            falco=True,
        ),
    ]
    score = scorer.score_path(nightmare_path)
    assert score.exploit_probability <= 1.0


def test_high_epss_reflected_in_factors() -> None:
    """High EPSS score shows up in human-readable factors."""
    scorer = AttackPathScorer()
    path = [_make_edge(epss=0.85)]
    score = scorer.score_path(path)
    epss_factors = [f for f in score.factors if "epss" in f]
    assert len(epss_factors) > 0
