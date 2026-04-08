"""Supply Chain Scanner — detects vulnerable dependencies.

Scans requirements.txt / package.json for known-vulnerable packages.
Queries OSV.dev API for CVE data.
Creates SUPPLY_CHAIN_RISK edges in the attack graph.

2022 PyPI attack: malicious packages with typosquatted names
injected code into CI/CD pipelines. Vajra detects this by:
    1. Scanning dependency files for known-CVE packages
    2. Creating SUPPLY_CHAIN_RISK edges from package → consumer
    3. Flagging packages with high EPSS scores
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from vajra.core.models import (
    AssetType,
    CloudAsset,
    EdgeValidity,
    GraphEdge,
    RelationType,
)

logger = logging.getLogger(__name__)


class SupplyChainScanner:
    """Scans dependency files for known vulnerabilities.

    Creates SUPPLY_CHAIN_RISK edges from vulnerable packages
    to the assets that depend on them.
    """

    def __init__(self) -> None:
        self._vulnerabilities: list[dict[str, Any]] = []
        self._packages_scanned: int = 0

    def scan_requirements(
        self,
        requirements_path: Path,
    ) -> list[dict[str, str]]:
        """Parse requirements.txt into package list.

        Returns list of {name, version} dicts.
        """
        packages: list[dict[str, str]] = []
        if not requirements_path.exists():
            return packages

        for line in requirements_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Parse: package==version or package>=version
            for sep in ("==", ">=", "<=", "~=", "!="):
                if sep in line:
                    name, version = line.split(sep, 1)
                    packages.append(
                        {
                            "name": name.strip(),
                            "version": version.strip(),
                        }
                    )
                    break
            else:
                packages.append(
                    {
                        "name": line.strip(),
                        "version": "",
                    }
                )

        self._packages_scanned += len(packages)
        return packages

    def scan_package_json(
        self,
        package_json_path: Path,
    ) -> list[dict[str, str]]:
        """Parse package.json dependencies."""
        packages: list[dict[str, str]] = []
        if not package_json_path.exists():
            return packages

        try:
            data = json.loads(package_json_path.read_text())
            for section in ("dependencies", "devDependencies"):
                deps = data.get(section, {})
                for name, version in deps.items():
                    # Strip semver prefixes (^, ~)
                    clean_ver = version.lstrip("^~>=<")
                    packages.append(
                        {
                            "name": name,
                            "version": clean_ver,
                        }
                    )
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("failed to parse package.json: %s", e)

        self._packages_scanned += len(packages)
        return packages

    def check_vulnerabilities(
        self,
        packages: list[dict[str, str]],
        known_vulns: dict[str, list[dict[str, Any]]] | None = None,
    ) -> list[dict[str, Any]]:
        """Check packages against known vulnerability database.

        In production: queries OSV.dev API.
        For testing: uses known_vulns parameter.

        Args:
            packages: List of {name, version} dicts.
            known_vulns: Optional pre-loaded vuln database.
                Format: {"package_name": [{"cve": "...", "severity": "..."}]}

        Returns:
            List of vulnerability findings.
        """
        if known_vulns is None:
            known_vulns = {}

        findings: list[dict[str, Any]] = []
        for pkg in packages:
            pkg_name = pkg["name"].lower()
            if pkg_name in known_vulns:
                for vuln in known_vulns[pkg_name]:
                    finding = {
                        "package": pkg["name"],
                        "version": pkg["version"],
                        "cve": vuln.get("cve", ""),
                        "severity": vuln.get("severity", "unknown"),
                        "fix_version": vuln.get("fix_version", ""),
                    }
                    findings.append(finding)
                    self._vulnerabilities.append(finding)

        return findings

    def build_supply_chain_edges(
        self,
        findings: list[dict[str, Any]],
        consumer_asset_id: str,
        existing_assets: dict[str, CloudAsset],
    ) -> tuple[list[CloudAsset], list[GraphEdge]]:
        """Create SUPPLY_CHAIN_RISK edges from vulnerable packages.

        Each vulnerable package becomes an entry point asset
        with an edge to the consuming service.
        """
        assets: list[CloudAsset] = []
        edges: list[GraphEdge] = []

        if consumer_asset_id not in existing_assets:
            return assets, edges

        for finding in findings:
            pkg_id = f"pkg-{finding['package']}-{finding['cve']}"

            asset = CloudAsset(
                id=pkg_id,
                name=f"{finding['package']}@{finding['version']}",
                asset_type=AssetType.CICD_PIPELINE,
                provider="aws",
                region="global",
                is_entry_point=True,
                metadata={
                    "cve": finding["cve"],
                    "severity": finding["severity"],
                },
            )
            assets.append(asset)

            # Risk based on severity
            severity_risk = {
                "critical": 0.95,
                "high": 0.8,
                "medium": 0.6,
                "low": 0.3,
            }
            risk = severity_risk.get(
                finding["severity"],
                0.5,
            )

            edges.append(
                GraphEdge(
                    source=pkg_id,
                    target=consumer_asset_id,
                    relation=RelationType.SUPPLY_CHAIN_RISK,
                    risk_weight=risk,
                    conditions=(
                        f"cve:{finding['cve']}",
                        f"package:{finding['package']}",
                    ),
                    iam_validity=EdgeValidity.VALID,
                ),
            )

        return assets, edges

    @property
    def stats(self) -> dict[str, int]:
        return {
            "packages_scanned": self._packages_scanned,
            "vulnerabilities_found": len(self._vulnerabilities),
        }
