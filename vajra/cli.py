"""Vajra CLI — 6 commands for cloud attack path intelligence.

Commands:
    vajra scan     — scan cloud providers, find attack paths
    vajra diff     — compare two scan results
    vajra ask      — natural language security query
    vajra verify   — verify report signature
    vajra setup    — interactive setup wizard
    vajra plan     — check terraform plan for new attack paths
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool = False) -> None:
    """Configure logging level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
    )


def cmd_scan(
    providers: str = "aws",
    output: str = "json",
    demo: bool = False,
    verbose: bool = False,
    db_path: str = "vajra_scan.duckdb",
) -> int:
    """Scan cloud providers for attack paths.

    Args:
        providers: Comma-separated provider list (aws,azure,gcp).
        output: Output format (json, table, html).
        demo: Use demo data (no credentials needed).
        verbose: Enable debug logging.

    Returns:
        Exit code (0 = success, 1 = findings, 2 = error).
    """
    _setup_logging(verbose)

    from vajra.core.graph_engine import VajraGraph
    from vajra.core.models import (
        AssetType,
        CloudAsset,
        EdgeValidity,
        GraphEdge,
        NetworkValidity,
        RelationType,
    )
    from vajra.engine import ScanEngine

    if demo:
        logger.info("running in demo mode (no credentials needed)")
        graph = VajraGraph()

        # Build demo graph
        assets = [
            CloudAsset(
                id="demo-ec2",
                name="Web Server",
                asset_type=AssetType.EC2_INSTANCE,
                provider="aws",
                region="us-east-1",
                is_entry_point=True,
            ),
            CloudAsset(
                id="demo-role",
                name="Admin Role",
                asset_type=AssetType.IAM_ROLE,
                provider="aws",
                region="global",
            ),
            CloudAsset(
                id="demo-s3",
                name="Customer Data",
                asset_type=AssetType.S3_BUCKET,
                provider="aws",
                region="us-east-1",
                is_crown_jewel=True,
            ),
        ]
        for a in assets:
            graph.add_asset(a)

        graph.add_edge(
            GraphEdge(
                source="demo-ec2",
                target="demo-role",
                relation=RelationType.CAN_ASSUME,
                risk_weight=0.9,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            )
        )
        graph.add_edge(
            GraphEdge(
                source="demo-role",
                target="demo-s3",
                relation=RelationType.HAS_ACCESS,
                risk_weight=0.85,
                iam_validity=EdgeValidity.VALID,
                network_validity=NetworkValidity.REACHABLE,
            )
        )
    else:
        engine = ScanEngine(db_path=Path(db_path))
        provider_tuple = tuple(p.strip() for p in providers.split(","))
        graph = engine.scan_sync(providers=provider_tuple)

    # Analyse
    paths = graph.find_attack_paths()
    cut = graph.find_minimum_cut()

    result: dict[str, Any] = {
        "providers": providers,
        "assets": len(graph.get_assets()),
        "attack_paths": len(paths),
        "minimum_cut_edges": len(cut.edges_to_cut),
        "paths": [
            {
                "edges": [f"{e.source} -> {e.target}" for e in p],
                "risk": round(
                    max((e.risk_weight for e in p), default=0),
                    2,
                ),
            }
            for p in paths[:20]
        ],
        "cut_recommendations": [f"{e.source} -> {e.target}" for e in cut.edges_to_cut],
    }

    if output == "json":
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
    else:
        # Table output
        sys.stdout.write(f"\nVajra Scan Results\n{'=' * 40}\n")
        sys.stdout.write(f"Assets:       {result['assets']}\n")
        sys.stdout.write(f"Attack Paths: {result['attack_paths']}\n")
        sys.stdout.write(f"Minimum Fix:  {result['minimum_cut_edges']} edges\n")
        for i, p in enumerate(result["paths"], 1):
            sys.stdout.write(
                f"\nPath {i} (risk: {p['risk']}):\n",
            )
            for edge in p["edges"]:
                sys.stdout.write(f"  {edge}\n")

    return 1 if paths else 0


def cmd_diff(
    report_a: str = "",
    report_b: str = "",
) -> int:
    """Compare two scan reports."""
    if not report_a or not report_b:
        sys.stderr.write("usage: vajra diff <report_a> <report_b>\n")
        return 2

    path_a = Path(report_a)
    path_b = Path(report_b)
    if not path_a.exists() or not path_b.exists():
        sys.stderr.write("error: report file not found\n")
        return 2

    a = json.loads(path_a.read_text())
    b = json.loads(path_b.read_text())

    diff: dict[str, Any] = {
        "paths_before": a.get("attack_paths", 0),
        "paths_after": b.get("attack_paths", 0),
        "change": (b.get("attack_paths", 0) - a.get("attack_paths", 0)),
    }
    sys.stdout.write(json.dumps(diff, indent=2) + "\n")
    return 0


def cmd_ask(question: str = "") -> int:
    """Ask a natural language security question."""
    if not question:
        sys.stderr.write("usage: vajra ask 'your question'\n")
        return 2

    from vajra.ai.layer import AILayer

    layer = AILayer()
    if not layer.is_available:
        sys.stderr.write(
            "ANTHROPIC_API_KEY not set. AI features disabled.\n",
        )
        return 2

    result = layer.query(question, {})
    if result:
        sys.stdout.write(f"{result.answer}\n")
    return 0


def cmd_verify(report_path: str = "") -> int:
    """Verify a signed report's HMAC signature."""
    if not report_path:
        sys.stderr.write("usage: vajra verify <report.json>\n")
        return 2

    import os

    from vajra.core.report_signer import SignedReport, verify_report

    path = Path(report_path)
    if not path.exists():
        sys.stderr.write(f"error: {report_path} not found\n")
        return 2

    key = os.environ.get("VAJRA_HMAC_SECRET_KEY", "")
    if len(key) < 32:
        sys.stderr.write("error: VAJRA_HMAC_SECRET_KEY not set or too short\n")
        return 2

    data = json.loads(path.read_text())
    signed = SignedReport(
        payload=data.get("payload", {}),
        signature=data.get("signature", ""),
        signed_at=data.get("signed_at", ""),
    )

    if verify_report(signed, key):
        sys.stdout.write("VERIFIED: report signature is valid\n")
        return 0

    sys.stderr.write("FAILED: report signature invalid or tampered\n")
    return 1


def cmd_setup() -> int:
    """Interactive setup wizard."""
    sys.stdout.write("Vajra Setup Wizard\n")
    sys.stdout.write("=" * 40 + "\n\n")
    sys.stdout.write(
        "Required environment variables:\n"
        "  VAJRA_HMAC_SECRET_KEY  (32+ chars for report signing)\n"
        "  ANTHROPIC_API_KEY      (optional, for AI features)\n\n"
        "Cloud provider setup:\n"
        "  AWS:   aws configure\n"
        "  Azure: az login\n"
        "  GCP:   gcloud auth application-default login\n\n"
        "Quick start:\n"
        "  vajra scan --demo          (no credentials needed)\n"
        "  vajra scan --providers aws (real AWS scan)\n"
    )
    return 0


def cmd_plan(plan_file: str = "") -> int:
    """Check terraform plan for new attack paths."""
    if not plan_file:
        sys.stderr.write("usage: vajra plan <tfplan.json>\n")
        return 2

    path = Path(plan_file)
    if not path.exists():
        sys.stderr.write(f"error: {plan_file} not found\n")
        return 2

    sys.stdout.write(
        f"Analysing terraform plan: {plan_file}\nIaC analysis not yet implemented.\n"
    )
    return 0


def main() -> int:
    """Main CLI entry point."""
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h"):
        sys.stdout.write(
            "Vajra — Multi-cloud attack path intelligence\n\n"
            "Commands:\n"
            "  scan     Scan cloud providers for attack paths\n"
            "  diff     Compare two scan reports\n"
            "  ask      Natural language security query\n"
            "  verify   Verify report signature\n"
            "  setup    Interactive setup wizard\n"
            "  plan     Check terraform plan for new paths\n\n"
            "Options:\n"
            "  --help   Show this help\n\n"
            "Examples:\n"
            "  vajra scan --demo\n"
            "  vajra scan --providers aws,azure,gcp\n"
            "  vajra verify report.json\n"
        )
        return 0

    command = args[0]
    flags = args[1:]

    if command == "scan":
        providers = "aws"
        output = "table"
        demo = False
        verbose = False
        db_path = "vajra_scan.duckdb"
        for i, flag in enumerate(flags):
            if flag == "--providers" and i + 1 < len(flags):
                providers = flags[i + 1]
            elif flag == "--output" and i + 1 < len(flags):
                output = flags[i + 1]
            elif flag == "--db" and i + 1 < len(flags):
                db_path = flags[i + 1]
            elif flag == "--demo":
                demo = True
            elif flag in ("--verbose", "-v"):
                verbose = True
        return cmd_scan(providers, output, demo, verbose, db_path)

    if command == "diff":
        a = flags[0] if len(flags) > 0 else ""
        b = flags[1] if len(flags) > 1 else ""
        return cmd_diff(a, b)

    if command == "ask":
        question = " ".join(flags)
        return cmd_ask(question)

    if command == "verify":
        path = flags[0] if flags else ""
        return cmd_verify(path)

    if command == "setup":
        return cmd_setup()

    if command == "plan":
        plan = flags[0] if flags else ""
        return cmd_plan(plan)

    sys.stderr.write(f"unknown command: {command}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
