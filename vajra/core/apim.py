"""Attack Path Intelligence Model (APIM) — Vajra's core competitive moat.

This module is the INTERFACE to Vajra's trained risk scoring model.
The algorithm is open source. The model weights are not.

WHY THIS IS UNCOPYABLE:
    The model weights are trained on data that only Vajra has:
    1. Real breach topology mappings (manually curated)
    2. Anonymized scan telemetry from opt-in users
    3. FP/FN feedback loops from enterprise deployments
    4. Live exploit probability feeds (EPSS, CISA KEV)

    Without this training data, a clone's model produces random noise.
    With it, Vajra's model predicts which attack paths are ACTUALLY
    exploited in the wild — not just theoretically possible.

HOW IT WORKS:
    The model takes an attack path (list of edges) and returns:
    - exploit_probability: 0.0-1.0 chance this path is used in real attacks
    - priority_rank: where this path should be in the fix queue
    - confidence: how confident the model is (based on training coverage)

    Three scoring modes:
    1. HEURISTIC (ships with OSS) — rule-based, no model needed
    2. LOCAL_MODEL (ships as .bin) — pre-trained, good accuracy
    3. CLOUD_MODEL (API call) — latest weights, best accuracy

ARCHITECTURE:
    The model is a SCORING function, not a DETECTION function.
    Detection is done by the graph engine (find_attack_paths).
    APIM answers: "of all paths found, which ones matter most?"

    This separation means:
    - Graph engine is deterministic (math, always correct)
    - APIM is probabilistic (ML, gets better with data)
    - Users can verify graph results independently of APIM
    - APIM enhances, never replaces, the mathematical proof
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from vajra.core.models import GraphEdge

logger = logging.getLogger(__name__)


class ScoringMode(Enum):
    """Which scoring backend to use."""

    HEURISTIC = "heuristic"  # Rule-based (always available)
    LOCAL_MODEL = "local_model"  # Pre-trained binary (ships with release)
    CLOUD_MODEL = "cloud_model"  # API-based (latest weights, opt-in)


@dataclass(frozen=True, slots=True)
class PathScore:
    """Risk score for a single attack path."""

    exploit_probability: float  # 0.0-1.0 real-world exploit likelihood
    priority_rank: int  # 1 = fix first, N = fix last
    confidence: float  # 0.0-1.0 model confidence
    factors: tuple[str, ...]  # human-readable risk factors
    model_version: str  # which model produced this score


class AttackPathScorer:
    """Scores attack paths by real-world exploit probability.

    The open-source version ships with HEURISTIC mode.
    Enterprise users get LOCAL_MODEL or CLOUD_MODEL.

    The scoring logic is visible. The model weights are the moat.
    """

    def __init__(
        self,
        mode: ScoringMode = ScoringMode.HEURISTIC,
    ) -> None:
        self._mode = mode
        self._model_version = "heuristic-v1"
        self._score_count: int = 0
        logger.info("APIM initialised in %s mode", mode.value)

    def score_path(self, path: list[GraphEdge]) -> PathScore:
        """Score a single attack path.

        This method dispatches to the active scoring backend.
        The INTERFACE is identical regardless of backend —
        only accuracy changes.
        """
        self._score_count += 1

        if self._mode == ScoringMode.HEURISTIC:
            return self._score_heuristic(path)

        # LOCAL_MODEL and CLOUD_MODEL will be implemented in Days 16-25
        # For now, fall back to heuristic
        return self._score_heuristic(path)

    def score_paths(
        self,
        paths: list[list[GraphEdge]],
    ) -> list[PathScore]:
        """Score and rank multiple paths. Returns sorted by priority."""
        scored = [self.score_path(p) for p in paths]
        # Sort by exploit probability (highest first)
        scored.sort(
            key=lambda s: s.exploit_probability,
            reverse=True,
        )
        # Re-assign priority ranks after sorting
        ranked = [
            PathScore(
                exploit_probability=s.exploit_probability,
                priority_rank=i + 1,
                confidence=s.confidence,
                factors=s.factors,
                model_version=s.model_version,
            )
            for i, s in enumerate(scored)
        ]
        return ranked

    def _score_heuristic(self, path: list[GraphEdge]) -> PathScore:
        """Rule-based scoring — the open-source baseline.

        This is intentionally GOOD ENOUGH to be useful, but
        not as accurate as the trained model. The gap between
        heuristic and trained model is what drives enterprise
        adoption.

        Factors considered:
        1. Path length (shorter = easier to exploit)
        2. CISA KEV edges (confirmed exploited in wild)
        3. EPSS scores (predicted exploit probability)
        4. Falco active alerts (being exploited RIGHT NOW)
        5. Edge risk weights (cumulative)
        6. Privilege escalation steps (CAN_ASSUME relations)
        """
        if not path:
            return PathScore(
                exploit_probability=0.0,
                priority_rank=0,
                confidence=0.0,
                factors=(),
                model_version=self._model_version,
            )

        factors: list[str] = []

        # Factor 1: Path length (shorter = more dangerous)
        length_score = max(0.0, 1.0 - (len(path) - 1) * 0.15)
        factors.append(f"path_length={len(path)}")

        # Factor 2: Any CISA KEV edge (confirmed exploited)
        has_kev = any(e.cisa_kev for e in path)
        kev_boost = 0.3 if has_kev else 0.0
        if has_kev:
            factors.append("cisa_kev=true")

        # Factor 3: Max EPSS score on path
        epss_scores = [e.epss_score for e in path if e.epss_score]
        max_epss = max(epss_scores) if epss_scores else 0.0
        if max_epss > 0.5:
            factors.append(f"high_epss={max_epss:.2f}")

        # Factor 4: Active exploitation (Falco)
        has_falco = any(e.falco_active for e in path)
        falco_boost = 0.5 if has_falco else 0.0
        if has_falco:
            factors.append("active_exploitation=true")

        # Factor 5: Cumulative risk weight
        cumulative_risk = 1.0
        for edge in path:
            cumulative_risk *= edge.effective_risk_weight
        factors.append(f"cumulative_risk={cumulative_risk:.3f}")

        # Factor 6: Privilege escalation count
        from vajra.core.models import RelationType

        priv_esc = sum(1 for e in path if e.relation == RelationType.CAN_ASSUME)
        if priv_esc > 0:
            factors.append(f"privilege_escalations={priv_esc}")

        # Combine factors into exploit probability
        base_score = (
            length_score * 0.2
            + cumulative_risk * 0.3
            + max_epss * 0.2
            + kev_boost
            + falco_boost
        )
        # Privilege escalation amplifier
        priv_multiplier = 1.0 + (priv_esc * 0.1)

        exploit_prob = min(1.0, base_score * priv_multiplier)

        # Confidence: heuristic mode is honest about its limitations
        confidence = 0.6  # "we're 60% sure — trained model is better"

        return PathScore(
            exploit_probability=round(exploit_prob, 4),
            priority_rank=0,  # assigned during batch ranking
            confidence=confidence,
            factors=tuple(factors),
            model_version=self._model_version,
        )
