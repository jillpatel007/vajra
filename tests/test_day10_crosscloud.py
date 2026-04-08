"""Tests for Day 10 — Cross-cloud edges, supply chain, scan engine.

PDF requirements:
    - GitHub OIDC trust creates cross-cloud edge
    - Known-CVE package creates SUPPLY_CHAIN_RISK edge
    - All 7 providers run in parallel (verify with timing)
    - ScanEngine returns complete VajraGraph
"""

import tempfile
import time
from pathlib import Path

from vajra.core.graph_engine import VajraGraph
from vajra.core.models import (
    AssetType,
    CloudAsset,
    EdgeValidity,
    GraphEdge,
    RelationType,
)
from vajra.discovery.common.github_oidc import GitHubOIDCDiscoverer
from vajra.discovery.common.supply_chain import SupplyChainScanner
from vajra.engine import ScanEngine

# ═══════════════════════════════════════════════════════════════════
# GITHUB OIDC TESTS
# ═══════════════════════════════════════════════════════════════════


class TestGitHubOIDC:
    """Cross-cloud trust via OIDC federation."""

    def test_github_oidc_creates_cross_cloud_edge(self) -> None:
        """GitHub OIDC trust → CROSS_ACCOUNT edge to AWS role.

        PDF: "GitHub OIDC trust creates cross-cloud edge."
        """
        disc = GitHubOIDCDiscoverer()
        role = CloudAsset(
            id="role-deploy",
            name="DeployRole",
            asset_type=AssetType.IAM_ROLE,
            provider="aws",
            region="global",
        )
        assets, edges = disc.discover_oidc_trusts(
            iam_trust_policies=[
                {
                    "role_id": "role-deploy",
                    "trust_policy": {
                        "Principal": {
                            "Federated": (
                                "arn:aws:iam::123:oidc-provider/"
                                "token.actions.githubusercontent.com"
                            ),
                        },
                        "Condition": {
                            "StringLike": {
                                "token.actions.githubusercontent.com:sub": (
                                    "repo:myorg/myrepo:ref:refs/heads/main"
                                ),
                            },
                        },
                    },
                }
            ],
            existing_assets={"role-deploy": role},
        )
        assert len(assets) == 1
        assert assets[0].is_entry_point is True
        assert assets[0].asset_type == AssetType.CICD_PIPELINE
        assert len(edges) == 1
        assert edges[0].relation == RelationType.CROSS_ACCOUNT
        assert edges[0].target == "role-deploy"

    def test_repo_extracted_from_condition(self) -> None:
        """Repo name extracted from OIDC condition."""
        disc = GitHubOIDCDiscoverer()
        role = CloudAsset(
            id="r1",
            name="R",
            asset_type=AssetType.IAM_ROLE,
            provider="aws",
            region="global",
        )
        assets, _ = disc.discover_oidc_trusts(
            iam_trust_policies=[
                {
                    "role_id": "r1",
                    "trust_policy": {
                        "Principal": {
                            "Federated": "token.actions.githubusercontent.com",
                        },
                        "Condition": {
                            "StringLike": {
                                "token.actions.githubusercontent.com:sub": (
                                    "repo:acme/webapp:ref:refs/heads/main"
                                ),
                            },
                        },
                    },
                }
            ],
            existing_assets={"r1": role},
        )
        assert len(assets) == 1
        assert "acme/webapp" in assets[0].name

    def test_non_oidc_trust_ignored(self) -> None:
        """Trust policy without OIDC → no edge."""
        disc = GitHubOIDCDiscoverer()
        role = CloudAsset(
            id="r1",
            name="R",
            asset_type=AssetType.IAM_ROLE,
            provider="aws",
            region="global",
        )
        assets, edges = disc.discover_oidc_trusts(
            iam_trust_policies=[
                {
                    "role_id": "r1",
                    "trust_policy": {
                        "Principal": {"AWS": "arn:aws:iam::999:root"},
                    },
                }
            ],
            existing_assets={"r1": role},
        )
        assert len(assets) == 0
        assert len(edges) == 0

    def test_full_cross_cloud_path_in_graph(self) -> None:
        """Full path: GitHub → AWS → Azure → GCP → crown jewel."""
        graph = VajraGraph()
        workflow = CloudAsset(
            id="gh-workflow",
            name="CI Deploy",
            asset_type=AssetType.CICD_PIPELINE,
            provider="aws",
            region="global",
            is_entry_point=True,
        )
        aws_role = CloudAsset(
            id="aws-role",
            name="DeployRole",
            asset_type=AssetType.IAM_ROLE,
            provider="aws",
            region="global",
        )
        azure_sp = CloudAsset(
            id="azure-sp",
            name="FederatedSP",
            asset_type=AssetType.SERVICE_PRINCIPAL,
            provider="azure",
            region="eastus",
        )
        gcp_sa = CloudAsset(
            id="gcp-sa",
            name="deploy@proj.iam",
            asset_type=AssetType.SERVICE_ACCOUNT,
            provider="gcp",
            region="us-central1",
        )
        crown_jewel = CloudAsset(
            id="gcp-db",
            name="ProdDB",
            asset_type=AssetType.GCS_BUCKET,
            provider="gcp",
            region="us-central1",
            is_crown_jewel=True,
        )
        for a in [workflow, aws_role, azure_sp, gcp_sa, crown_jewel]:
            graph.add_asset(a)

        chain = [
            ("gh-workflow", "aws-role", RelationType.CROSS_ACCOUNT),
            ("aws-role", "azure-sp", RelationType.CROSS_ACCOUNT),
            ("azure-sp", "gcp-sa", RelationType.CROSS_ACCOUNT),
            ("gcp-sa", "gcp-db", RelationType.HAS_ACCESS),
        ]
        for src, tgt, rel in chain:
            graph.add_edge(
                GraphEdge(
                    source=src,
                    target=tgt,
                    relation=rel,
                    risk_weight=0.9,
                    iam_validity=EdgeValidity.VALID,
                )
            )

        paths = graph.find_attack_paths()
        assert len(paths) == 1, "must find GitHub → GCP path"
        assert len(paths[0]) == 4, "path = 4 edges"


# ═══════════════════════════════════════════════════════════════════
# SUPPLY CHAIN TESTS
# ═══════════════════════════════════════════════════════════════════


class TestSupplyChain:
    """Supply chain vulnerability scanning."""

    def test_known_cve_creates_supply_chain_edge(self) -> None:
        """Known-CVE package → SUPPLY_CHAIN_RISK edge.

        PDF: "Known-CVE package creates SUPPLY_CHAIN_RISK edge."
        """
        scanner = SupplyChainScanner()
        packages = [{"name": "requests", "version": "2.25.0"}]
        known_vulns = {
            "requests": [
                {
                    "cve": "CVE-2023-32681",
                    "severity": "high",
                    "fix_version": "2.31.0",
                }
            ],
        }
        findings = scanner.check_vulnerabilities(
            packages,
            known_vulns,
        )
        assert len(findings) == 1
        assert findings[0]["cve"] == "CVE-2023-32681"

        consumer = CloudAsset(
            id="lambda-app",
            name="App",
            asset_type=AssetType.LAMBDA_FUNCTION,
            provider="aws",
            region="us-east-1",
        )
        assets, edges = scanner.build_supply_chain_edges(
            findings,
            "lambda-app",
            {"lambda-app": consumer},
        )
        assert len(edges) == 1
        assert edges[0].relation == RelationType.SUPPLY_CHAIN_RISK
        assert edges[0].risk_weight == 0.8  # high severity

    def test_requirements_txt_parsing(self) -> None:
        """Parse requirements.txt correctly."""
        tmp = Path(tempfile.mkdtemp()) / "requirements.txt"
        tmp.write_text(
            "requests==2.25.0\n"
            "flask>=2.0.0\n"
            "# comment\n"
            "numpy\n"
            "-r other.txt\n"
        )
        scanner = SupplyChainScanner()
        packages = scanner.scan_requirements(tmp)
        tmp.unlink()

        names = [p["name"] for p in packages]
        assert "requests" in names
        assert "flask" in names
        assert "numpy" in names
        assert len(packages) == 3

    def test_clean_package_no_edge(self) -> None:
        """Package without known CVEs → no edge."""
        scanner = SupplyChainScanner()
        packages = [{"name": "safe-package", "version": "1.0.0"}]
        findings = scanner.check_vulnerabilities(packages, {})
        assert len(findings) == 0

    def test_critical_severity_highest_risk(self) -> None:
        """Critical CVE → risk 0.95."""
        scanner = SupplyChainScanner()
        findings = [
            {
                "package": "log4j",
                "version": "2.14",
                "cve": "CVE-2021-44228",
                "severity": "critical",
            }
        ]
        consumer = CloudAsset(
            id="app",
            name="App",
            asset_type=AssetType.EC2_INSTANCE,
            provider="aws",
            region="us-east-1",
        )
        _, edges = scanner.build_supply_chain_edges(
            findings,
            "app",
            {"app": consumer},
        )
        assert edges[0].risk_weight == 0.95


# ═══════════════════════════════════════════════════════════════════
# SCAN ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════


class TestScanEngine:
    """Concurrent scan engine."""

    def test_scan_engine_returns_graph(self) -> None:
        """ScanEngine.scan_sync() returns a VajraGraph."""
        engine = ScanEngine()
        graph = engine.scan_sync(providers=("aws", "gcp"))
        assert isinstance(graph, VajraGraph)

    def test_scan_runs_concurrently(self) -> None:
        """All providers run in parallel — not sequential.

        PDF: "verify with timing — should be ~concurrent"
        """
        engine = ScanEngine()
        start = time.perf_counter()
        engine.scan_sync(
            providers=("aws", "azure", "gcp", "alibaba", "tencent", "huawei", "k8s")
        )
        elapsed = time.perf_counter() - start

        # 7 providers should complete in < 1s if concurrent
        # Sequential would be 7x slower
        assert elapsed < 1.0, f"scan took {elapsed:.2f}s — should be concurrent"

    def test_scan_stats(self) -> None:
        """Stats populated after scan."""
        engine = ScanEngine()
        engine.scan_sync(providers=("aws",))
        stats = engine.stats
        assert "scan_time_seconds" in stats
        assert "graph_integrity" in stats

    def test_graph_integrity_after_scan(self) -> None:
        """Graph integrity verified after concurrent scan."""
        engine = ScanEngine()
        engine.scan_sync()
        assert engine.stats["graph_integrity"] is True
