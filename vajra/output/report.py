"""Report Generator — signed JSON + executive summary.

Produces board-ready output from scan results.
Every report is HMAC-signed for tamper evidence.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from vajra.core.report_signer import sign_report

logger = logging.getLogger(__name__)


def generate_report(
    scan_result: dict[str, Any],
    signing_key: str,
) -> dict[str, Any]:
    """Generate signed JSON report from scan results."""
    report = {
        "vajra_version": "0.1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "scan_result": scan_result,
        "executive_summary": _generate_executive_summary(
            scan_result,
        ),
    }

    signed = sign_report(report, signing_key)
    return signed.to_dict()


def _generate_executive_summary(
    scan_result: dict[str, Any],
) -> str:
    """Generate 3-sentence board-level summary."""
    paths = scan_result.get("attack_paths", 0)
    cut = scan_result.get("minimum_cut_edges", 0)
    assets = scan_result.get("assets", 0)

    cost = paths * 4_880_000  # IBM Ponemon average

    if paths == 0:
        return (
            f"Vajra scanned {assets} cloud assets and found "
            f"zero critical attack paths. Your cloud security "
            f"posture is strong. No immediate action required."
        )

    return (
        f"Vajra identified {paths} attack path(s) across "
        f"{assets} cloud assets with an estimated financial "
        f"exposure of ${cost:,.0f}. The mathematically proven "
        f"minimum fix requires cutting {cut} edge(s). "
        f"Recommended action: apply the minimum cut immediately."
    )


def save_report(
    report: dict[str, Any],
    output_path: str,
) -> None:
    """Save report to file."""
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("report saved to %s", output_path)
