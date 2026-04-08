"""Agentic Security Researcher — multi-step graph analysis.

VajraSecurityAgent uses tool-use pattern:
    1. Send question to Claude
    2. If tool_use → execute tool (read-only) → append result → loop
    3. If end_turn → return AgentResult
    4. Max 10 iterations (termination condition)

ALL TOOLS ARE READ-ONLY. Agent cannot modify the graph.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from vajra.core.graph_engine import VajraGraph

logger = logging.getLogger(__name__)

_MAX_ITERATIONS = 10


@dataclass
class ToolCall:
    """A single tool call in the agent loop."""

    tool_name: str
    arguments: dict[str, Any]
    result: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    """Final result from the agent."""

    answer: str
    tool_calls: list[ToolCall]
    iterations: int
    terminated_reason: str  # "complete" or "max_iterations"


class VajraSecurityAgent:
    """Multi-step security analysis agent with read-only graph tools.

    Available tools (all read-only):
        - query_graph: find attack paths
        - get_minimum_cut: get remediation recommendations
        - get_financial_exposure: calculate breach cost
        - get_blast_radius: find affected assets
    """

    def __init__(self, graph: VajraGraph) -> None:
        self._graph = graph
        self._tools: dict[str, Any] = {
            "query_graph": self._tool_query_graph,
            "get_minimum_cut": self._tool_get_min_cut,
            "get_financial_exposure": self._tool_get_exposure,
            "get_blast_radius": self._tool_get_blast_radius,
        }

    def run(self, question: str) -> AgentResult:
        """Run the agentic loop to answer a security question.

        In production: sends to Claude API with tool definitions.
        For now: simulates the tool-use pattern.
        """
        tool_calls: list[ToolCall] = []
        iterations = 0

        # Simulate: agent decides which tools to call
        # In production: Claude decides via tool_use
        if "path" in question.lower() or "attack" in question.lower():
            call = ToolCall(
                tool_name="query_graph",
                arguments={},
            )
            call.result = self._execute_tool(call)
            tool_calls.append(call)
            iterations += 1

        if "fix" in question.lower() or "cut" in question.lower():
            call = ToolCall(
                tool_name="get_minimum_cut",
                arguments={},
            )
            call.result = self._execute_tool(call)
            tool_calls.append(call)
            iterations += 1

        if "cost" in question.lower() or "exposure" in question.lower():
            call = ToolCall(
                tool_name="get_financial_exposure",
                arguments={},
            )
            call.result = self._execute_tool(call)
            tool_calls.append(call)
            iterations += 1

        terminated = "max_iterations" if iterations >= _MAX_ITERATIONS else "complete"

        return AgentResult(
            answer=f"Analysed with {len(tool_calls)} tool calls",
            tool_calls=tool_calls,
            iterations=iterations,
            terminated_reason=terminated,
        )

    def _execute_tool(self, call: ToolCall) -> dict[str, Any]:
        """Execute a single tool call (read-only)."""
        tool_fn = self._tools.get(call.tool_name)
        if not tool_fn:
            return {"error": f"unknown tool: {call.tool_name}"}
        result: dict[str, Any] = tool_fn(**call.arguments)
        return result

    def _tool_query_graph(self) -> dict[str, Any]:
        """Read-only: find attack paths."""
        paths = self._graph.find_attack_paths()
        return {
            "paths_found": len(paths),
            "paths": [[f"{e.source} → {e.target}" for e in p] for p in paths[:5]],
        }

    def _tool_get_min_cut(self) -> dict[str, Any]:
        """Read-only: get minimum cut recommendation."""
        cut = self._graph.find_minimum_cut()
        return {
            "edges_to_cut": len(cut.edges_to_cut),
            "edges": [f"{e.source} → {e.target}" for e in cut.edges_to_cut],
        }

    def _tool_get_exposure(self) -> dict[str, Any]:
        """Read-only: calculate financial exposure."""
        paths = self._graph.find_attack_paths()
        cost_per_breach = 4_880_000
        return {
            "attack_paths": len(paths),
            "exposure_usd": cost_per_breach * len(paths),
        }

    def _tool_get_blast_radius(
        self,
        asset_id: str = "",
    ) -> dict[str, Any]:
        """Read-only: find blast radius of an asset."""
        if not asset_id:
            return {"error": "asset_id required"}
        assets = self._graph.find_blast_radius(asset_id)
        return {
            "affected_assets": len(assets),
            "asset_ids": [a.id for a in assets[:10]],
        }
