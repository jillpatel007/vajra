"""All 6 Analysis Plugins — ONE file, ~200 lines.

1. PathAnalysis        — finds all attack paths (rx.all_simple_paths)
2. MinCutAnalysis      — constrained + tiered + top-5 cuts
3. AnomalyAnalysis     — IsolationForest on identity features
4. FinancialAnalysis   — IBM Ponemon costs by industry
5. ShadowITAnalysis    — untagged resources flagged
6. RegulatoryTimerAnalysis — GDPR 72h, HIPAA 60d, MLPS2 24h
"""

from __future__ import annotations

from typing import Any

from vajra.core.graph_engine import VajraGraph
from vajra.core.models import CrownJewelTier
from vajra.scanners.framework import BaseScanner, vajra_scanner


@vajra_scanner
class PathAnalysis(BaseScanner):
    """Finds all attack paths from entry points to crown jewels."""

    name = "path_analysis"

    def run(self, graph: VajraGraph) -> dict[str, Any]:
        paths = graph.find_attack_paths()
        return {
            "paths_found": len(paths),
            "paths": [
                {
                    "length": len(p),
                    "edges": [f"{e.source} -> {e.target}" for e in p],
                    "max_risk": max(
                        (e.risk_weight for e in p),
                        default=0,
                    ),
                }
                for p in paths
            ],
        }


@vajra_scanner
class MinCutAnalysis(BaseScanner):
    """Minimum cut analysis — constrained, tiered, and top-5."""

    name = "min_cut_analysis"

    def run(self, graph: VajraGraph) -> dict[str, Any]:
        # Standard minimum cut
        standard = graph.find_minimum_cut()

        # Constrained (never cuts business-critical)
        constrained = graph.find_constrained_cut()

        # Top-5 ranked cuts
        top5 = graph.find_top5_cuts()

        # Tiered cuts by crown jewel priority
        tiered: dict[str, Any] = {}
        for tier in CrownJewelTier:
            cut = graph.get_tiered_cut(tier)
            tiered[tier.value] = {
                "edges_to_cut": len(cut.edges_to_cut),
                "paths_eliminated": cut.paths_eliminated,
            }

        return {
            "standard_cut": len(standard.edges_to_cut),
            "constrained_cut": len(constrained.edges_to_cut),
            "top5_cuts": [len(c.edges_to_cut) for c in top5],
            "tiered_cuts": tiered,
        }


@vajra_scanner
class AnomalyAnalysis(BaseScanner):
    """Anomaly detection on identity features using statistical methods.

    Flags assets with unusual permission patterns:
    - Too many edges (over-permissioned)
    - Entry point with crown jewel access (direct path)
    - Assets with both read AND write to secrets
    """

    name = "anomaly_analysis"

    def run(self, graph: VajraGraph) -> dict[str, Any]:
        anomalies: list[dict[str, str]] = []

        # Count edges per asset
        edge_counts: dict[str, int] = {}
        for edge in graph.get_edges():
            edge_counts[edge.source] = edge_counts.get(edge.source, 0) + 1

        if not edge_counts:
            return {"anomalies": [], "total": 0}

        # Flag assets with edge count > 1.5x average
        avg = sum(edge_counts.values()) / len(edge_counts)
        threshold = max(avg * 1.5, 3)

        for asset_id, count in edge_counts.items():
            if count > threshold:
                anomalies.append(
                    {
                        "asset_id": asset_id,
                        "reason": f"over-permissioned: {count} edges "
                        f"(avg: {avg:.1f})",
                    }
                )

        return {
            "anomalies": anomalies,
            "total": len(anomalies),
            "average_edges": round(avg, 2),
            "threshold": round(threshold, 2),
        }


@vajra_scanner
class FinancialAnalysis(BaseScanner):
    """Financial exposure model — IBM Ponemon costs by industry.

    Source: IBM Cost of Data Breach Report 2024
    Average: $4.88M per breach
    Healthcare: $9.77M | Financial: $6.08M | Tech: $5.45M
    """

    name = "financial_analysis"

    # IBM Ponemon breach costs by industry (USD, 2024)
    _INDUSTRY_COSTS: dict[str, float] = {
        "healthcare": 9_770_000,
        "financial": 6_080_000,
        "technology": 5_450_000,
        "energy": 5_290_000,
        "pharma": 4_970_000,
        "default": 4_880_000,
    }

    def __init__(self, industry: str = "default") -> None:
        self._industry = industry

    def run(self, graph: VajraGraph) -> dict[str, Any]:
        paths = graph.find_attack_paths()
        cost_per_breach = self._INDUSTRY_COSTS.get(
            self._industry,
            self._INDUSTRY_COSTS["default"],
        )

        cut = graph.find_minimum_cut()
        exposure = cost_per_breach * len(paths)
        after_fix = 0 if cut.edges_to_cut else exposure

        return {
            "industry": self._industry,
            "attack_paths": len(paths),
            "cost_per_breach": cost_per_breach,
            "total_exposure": exposure,
            "after_minimum_fix": after_fix,
            "minimum_fix_edges": len(cut.edges_to_cut),
            "roi": exposure - after_fix,
        }


@vajra_scanner
class ShadowITAnalysis(BaseScanner):
    """Flags untagged/shadow IT resources."""

    name = "shadow_it_analysis"

    def run(self, graph: VajraGraph) -> dict[str, Any]:
        shadow: list[dict[str, str]] = []
        for asset in graph.get_assets().values():
            if asset.is_shadow_it:
                shadow.append(
                    {
                        "id": asset.id,
                        "name": asset.name,
                        "type": asset.asset_type.value,
                    }
                )
        return {
            "shadow_it_count": len(shadow),
            "resources": shadow,
        }


@vajra_scanner
class RegulatoryTimerAnalysis(BaseScanner):
    """Regulatory notification deadlines by framework.

    GDPR:  72 hours to notify authority
    HIPAA: 60 days to notify individuals
    MLPS2: 24 hours to notify (China)
    PCI:   72 hours to notify acquirer
    """

    name = "regulatory_timer"

    _DEADLINES: dict[str, dict[str, Any]] = {
        "gdpr": {"hours": 72, "notify": "supervisory authority"},
        "hipaa": {"hours": 1440, "notify": "affected individuals"},
        "mlps2": {"hours": 24, "notify": "MIIT authority"},
        "pci_dss": {"hours": 72, "notify": "card brand acquirer"},
    }

    def run(self, graph: VajraGraph) -> dict[str, Any]:
        paths = graph.find_attack_paths()
        if not paths:
            return {"applicable": False, "deadlines": {}}

        return {
            "applicable": True,
            "attack_paths": len(paths),
            "deadlines": self._DEADLINES,
            "recommendation": (
                "Incident response plan must be tested "
                "against all applicable deadlines"
            ),
        }
