"""MCP Security Analyser — maps MCP tool permissions to graph edges.

MCP (Model Context Protocol) servers expose tools that AI agents call.
Each tool has permissions that create implicit access paths.

Example:
    MCP server has tool "write_database" with params (table, data)
    → This creates an edge: MCP_SERVER → DATABASE with risk 0.85
    → Blast radius = every table the tool can write to

No other security tool analyses MCP tool permissions.
This is unique to Vajra.
"""

from __future__ import annotations

import logging
from typing import Any

from vajra.core.models import (
    AssetType,
    CloudAsset,
    EdgeValidity,
    GraphEdge,
    RelationType,
)

logger = logging.getLogger(__name__)

# MCP tool permission categories and risk levels
_TOOL_RISK_MAP: dict[str, float] = {
    "read_database": 0.6,
    "write_database": 0.85,
    "delete_database": 0.95,
    "read_file": 0.5,
    "write_file": 0.8,
    "execute_command": 0.99,
    "send_email": 0.7,
    "create_resource": 0.75,
    "delete_resource": 0.95,
    "modify_iam": 0.99,
    "access_secrets": 0.95,
}

_WRITE_TOOLS: frozenset[str] = frozenset(
    {
        "write_database",
        "write_file",
        "execute_command",
        "delete_database",
        "delete_resource",
        "modify_iam",
    }
)


class MCPSecurityAnalyser:
    """Analyses MCP server tool permissions for attack paths.

    Maps each MCP tool's permissions to graph edges,
    then calculates the blast radius per tool.
    """

    def __init__(self) -> None:
        self._servers: dict[str, CloudAsset] = {}
        self._tools_analysed: int = 0

    def discover_mcp_servers(
        self,
        mcp_configs: list[dict[str, Any]],
    ) -> list[CloudAsset]:
        """Discover MCP servers from configuration.

        Args:
            mcp_configs: List of MCP server configs.
                Each has: id, name, tools (list of tool dicts).

        Returns:
            MCP servers as CloudAssets (always entry points).
        """
        servers: list[CloudAsset] = []
        for config in mcp_configs:
            server = CloudAsset(
                id=config.get("id", ""),
                name=config.get("name", ""),
                asset_type=AssetType.MCP_SERVER,
                provider=config.get("provider", "aws"),
                region=config.get("region", "global"),
                is_entry_point=True,  # MCP servers accept external input
                ai_signals={
                    "tool_count": len(config.get("tools", [])),
                },
            )
            servers.append(server)
            self._servers[server.id] = server

        logger.info(
            "MCP discovery: %d servers found",
            len(servers),
        )
        return servers

    def analyse_tools(
        self,
        server_id: str,
        tools: list[dict[str, Any]],
        target_assets: dict[str, CloudAsset],
    ) -> list[GraphEdge]:
        """Map MCP tool permissions to graph edges.

        Each tool creates an edge from the MCP server to
        the resource it can access.

        Args:
            server_id: ID of the MCP server asset.
            tools: List of tool definitions.
                Each has: name, permissions (list of strings),
                target_resources (list of asset IDs).
            target_assets: Known assets in the graph.

        Returns:
            List of edges from MCP server to target resources.
        """
        if server_id not in self._servers:
            return []

        edges: list[GraphEdge] = []
        for tool in tools:
            tool_name = tool.get("name", "")
            permissions = tool.get("permissions", [])
            targets = tool.get("target_resources", [])

            # Get highest risk from tool's permissions
            max_risk = 0.0
            for perm in permissions:
                risk = _TOOL_RISK_MAP.get(perm, 0.3)
                max_risk = max(max_risk, risk)

            # Determine relation type
            has_write = any(p in _WRITE_TOOLS for p in permissions)
            relation = (
                RelationType.MCP_TOOL_ACCESS if has_write else RelationType.READS_FROM
            )

            # Create edge to each target resource
            for target_id in targets:
                if target_id not in target_assets:
                    continue
                edges.append(
                    GraphEdge(
                        source=server_id,
                        target=target_id,
                        relation=relation,
                        risk_weight=max_risk,
                        conditions=(f"mcp_tool:{tool_name}",),
                        iam_validity=EdgeValidity.VALID,
                    ),
                )
                self._tools_analysed += 1

        logger.info(
            "MCP tools: %d edges from %d tools on %s",
            len(edges),
            len(tools),
            server_id,
        )
        return edges

    def calculate_blast_radius(
        self,
        server_id: str,
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Calculate blast radius for an MCP server.

        Blast radius = total number of resources accessible
        through all tools on this server.
        """
        all_targets: set[str] = set()
        write_targets: set[str] = set()
        max_risk = 0.0

        for tool in tools:
            permissions = tool.get("permissions", [])
            targets = tool.get("target_resources", [])
            has_write = any(p in _WRITE_TOOLS for p in permissions)

            all_targets.update(targets)
            if has_write:
                write_targets.update(targets)

            for perm in permissions:
                risk = _TOOL_RISK_MAP.get(perm, 0.3)
                max_risk = max(max_risk, risk)

        return {
            "server_id": server_id,
            "total_resources": len(all_targets),
            "writable_resources": len(write_targets),
            "max_risk": round(max_risk, 2),
            "tools_count": len(tools),
        }

    @property
    def stats(self) -> dict[str, int]:
        """Analysis statistics."""
        return {
            "servers_discovered": len(self._servers),
            "tools_analysed": self._tools_analysed,
        }
