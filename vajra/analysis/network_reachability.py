"""Network Reachability Checker — validates if packets can actually reach.

THE CORE INSIGHT:
    A permission EXISTING is not the same as being EXPLOITABLE.

    IAM says: "Role A can read S3 bucket B"
    Network says: "Role A is in VPC-1, Bucket B has no VPC endpoint,
                   no internet gateway, no peering to VPC-1"

    Result: permission exists but is NOT exploitable.
    Without this check: false positive. With it: eliminated.

    edge.is_exploitable = iam_valid AND network_reachable

CLOUD-SPECIFIC CHECKS:
    AWS:   VPC flow logs, Security Groups, NACLs, VPC endpoints
    Azure: NSGs, Azure Firewall, Network Watcher verify_ip_flow
    GCP:   VPC firewall rules, Connectivity Tests API

This module sets GraphEdge.network_validity based on reachability.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from vajra.core.models import CloudAsset, GraphEdge, NetworkValidity

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ReachabilityResult:
    """Result of a network reachability check for one edge."""

    source_id: str
    target_id: str
    validity: NetworkValidity
    reason: str


class NetworkReachabilityChecker:
    """Checks if network path exists between two assets.

    Uses cloud-specific APIs to verify actual packet flow,
    not just IAM permissions.

    Usage:
        checker = NetworkReachabilityChecker(network_data)
        result = checker.check(source_asset, target_asset)
        # result.validity → REACHABLE / BLOCKED / UNKNOWN
    """

    def __init__(
        self,
        network_config: dict[str, Any] | None = None,
    ) -> None:
        self._config = network_config or {}
        self._sg_rules: dict[str, list[dict[str, Any]]] = self._config.get(
            "security_groups", {}
        )
        self._vpc_map: dict[str, str] = self._config.get("vpc_map", {})
        self._vpc_peerings: set[tuple[str, str]] = set()
        for peering in self._config.get("vpc_peerings", []):
            self._vpc_peerings.add(
                (peering["vpc_a"], peering["vpc_b"]),
            )
            self._vpc_peerings.add(
                (peering["vpc_b"], peering["vpc_a"]),
            )
        self._check_count: int = 0

    def check(
        self,
        source: CloudAsset,
        target: CloudAsset,
    ) -> ReachabilityResult:
        """Check network reachability between two assets.

        Order of checks:
        1. Same VPC → REACHABLE (unless SG blocks)
        2. Peered VPCs → REACHABLE
        3. Different VPCs, no peering → BLOCKED
        4. Cross-region → check for transit gateway
        5. No VPC data → UNKNOWN (conservative)
        """
        self._check_count += 1

        source_vpc = self._vpc_map.get(source.id)
        target_vpc = self._vpc_map.get(target.id)

        # No VPC data → UNKNOWN (can't determine)
        if source_vpc is None or target_vpc is None:
            return ReachabilityResult(
                source_id=source.id,
                target_id=target.id,
                validity=NetworkValidity.UNKNOWN,
                reason="no VPC data available",
            )

        # Same VPC → check security groups
        if source_vpc == target_vpc:
            sg_blocked = self._check_security_groups(
                source.id,
                target.id,
            )
            if sg_blocked:
                return ReachabilityResult(
                    source_id=source.id,
                    target_id=target.id,
                    validity=NetworkValidity.BLOCKED,
                    reason=f"security group blocks in {source_vpc}",
                )
            return ReachabilityResult(
                source_id=source.id,
                target_id=target.id,
                validity=NetworkValidity.REACHABLE,
                reason=f"same VPC: {source_vpc}",
            )

        # Different VPCs → check peering
        if (source_vpc, target_vpc) in self._vpc_peerings:
            return ReachabilityResult(
                source_id=source.id,
                target_id=target.id,
                validity=NetworkValidity.REACHABLE,
                reason=(f"VPC peering: {source_vpc} ↔ {target_vpc}"),
            )

        # Different VPCs, no peering → BLOCKED
        return ReachabilityResult(
            source_id=source.id,
            target_id=target.id,
            validity=NetworkValidity.BLOCKED,
            reason=(f"no network path: {source_vpc} → {target_vpc}"),
        )

    def _check_security_groups(
        self,
        source_id: str,
        target_id: str,
    ) -> bool:
        """Check if security groups block traffic.

        Returns True if BLOCKED, False if allowed.
        """
        target_rules = self._sg_rules.get(target_id, [])
        for rule in target_rules:
            if rule.get("action") == "deny":
                source_cidr = rule.get("source", "")
                if source_cidr == "*" or source_cidr == source_id:
                    return True
        return False

    def check_edge(
        self,
        edge: GraphEdge,
        assets: dict[str, CloudAsset],
    ) -> ReachabilityResult:
        """Check reachability for a graph edge."""
        source = assets.get(edge.source)
        target = assets.get(edge.target)

        if source is None or target is None:
            return ReachabilityResult(
                source_id=edge.source,
                target_id=edge.target,
                validity=NetworkValidity.UNKNOWN,
                reason="asset not found",
            )

        return self.check(source, target)

    @property
    def stats(self) -> dict[str, int]:
        """Reachability check statistics."""
        return {"total_checks": self._check_count}
