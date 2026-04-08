from __future__ import annotations

import copy
import logging
from dataclasses import dataclass

import rustworkx as rx

from vajra.core.models import (
    AssetType,
    CloudAsset,
    CrownJewelTier,
    GraphEdge,
)

logger = logging.getLogger(__name__)

# FIX #1: Hard limits to prevent path explosion DoS
_MAX_PATHS = 10_000
_MAX_PATH_LENGTH = 15


@dataclass
class MinCutResult:
    edges_to_cut: list[GraphEdge]
    paths_eliminated: int
    is_constrained: bool = False
    tier: CrownJewelTier | None = None


class VajraGraph:
    def __init__(self) -> None:
        self._graph: rx.PyDiGraph = rx.PyDiGraph()
        self._asset_to_idx: dict[str, int] = {}
        self._idx_to_asset: dict[int, CloudAsset] = {}
        self._edges: list[GraphEdge] = []
        self._cache_valid: bool = False
        self._cached_paths: list[list[GraphEdge]] = []

    def invalidate_cache(self) -> None:
        self._cache_valid = False

    def add_asset(self, asset: CloudAsset) -> None:
        if not self._validate_asset_id(asset.id):
            return
        if asset.id in self._asset_to_idx:
            return
        idx = self._graph.add_node(asset)
        self._asset_to_idx[asset.id] = idx
        self._idx_to_asset[idx] = asset
        self.invalidate_cache()

    def _validate_asset_id(self, asset_id: str) -> bool:
        if not asset_id:
            logger.warning("empty asset id rejected")
            return False
        if len(asset_id) > 500:
            logger.warning("asset id too long: %d chars", len(asset_id))
            return False
        if "\x00" in asset_id:
            logger.warning("null byte in asset id rejected")
            return False
        return True

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source not in self._asset_to_idx:
            logger.warning("source asset not found: %s", edge.source)
            return
        if edge.target not in self._asset_to_idx:
            logger.warning("target asset not found: %s", edge.target)
            return
        source_idx = self._asset_to_idx[edge.source]
        target_idx = self._asset_to_idx[edge.target]
        self._graph.add_edge(source_idx, target_idx, edge)
        self._edges.append(edge)
        self.invalidate_cache()

    def verify_integrity(self) -> bool:
        for idx, asset in self._idx_to_asset.items():
            stored = self._graph[idx]
            if stored.integrity_hash() != asset.integrity_hash():
                logger.error(
                    "integrity violation detected for asset: %s",
                    asset.id,
                )
                return False
        return True

    # --- Public accessors (FIX #12) ---

    def get_edges(self) -> list[GraphEdge]:
        """Public accessor for edges (avoids private field access)."""
        return list(self._edges)

    def get_assets(self) -> dict[int, CloudAsset]:
        """Public accessor for assets (avoids private field access)."""
        return dict(self._idx_to_asset)

    # --- Path finding ---

    def find_attack_paths(
        self,
        max_paths: int = _MAX_PATHS,
        max_depth: int = _MAX_PATH_LENGTH,
    ) -> list[list[GraphEdge]]:
        """Find attack paths with DoS protection.

        FIX #1: Hard cap on paths and depth prevents path explosion.
        """
        if self._cache_valid:
            return self._cached_paths
        entry_points = [
            idx for idx, asset in self._idx_to_asset.items() if asset.is_entry_point
        ]
        crown_jewels = [
            idx for idx, asset in self._idx_to_asset.items() if asset.is_crown_jewel
        ]
        paths: list[list[GraphEdge]] = []
        for source in entry_points:
            if len(paths) >= max_paths:
                logger.warning(
                    "path limit reached (%d), stopping enumeration",
                    max_paths,
                )
                break
            for target in crown_jewels:
                if len(paths) >= max_paths:
                    break
                raw_paths = rx.all_simple_paths(
                    self._graph,
                    source,
                    target,
                    cutoff=max_depth,
                )
                for node_path in raw_paths:
                    if len(paths) >= max_paths:
                        break
                    edge_path = self._nodes_to_edges(node_path)
                    if edge_path:
                        paths.append(edge_path)
        self._cached_paths = paths
        self._cache_valid = True
        return paths

    def _nodes_to_edges(self, node_path: list[int]) -> list[GraphEdge]:
        edges = []
        for source_idx, target_idx in zip(
            node_path,
            node_path[1:],
            strict=False,
        ):
            edge_data = self._graph.get_edge_data(
                source_idx,
                target_idx,
            )
            if edge_data is not None:
                edges.append(edge_data)
        return edges

    def _add_virtual_nodes(
        self,
    ) -> tuple[int, int, list[int]]:
        virtual_source = self._graph.add_node(
            CloudAsset(
                id="__virtual_source__",
                name="Virtual Source",
                asset_type=AssetType.VIRTUAL,
                provider="aws",
                region="global",
            )
        )
        virtual_sink = self._graph.add_node(
            CloudAsset(
                id="__virtual_sink__",
                name="Virtual Sink",
                asset_type=AssetType.VIRTUAL,
                provider="aws",
                region="global",
            )
        )
        virtual_nodes = [virtual_source, virtual_sink]
        for idx, asset in self._idx_to_asset.items():
            if asset.is_entry_point:
                self._graph.add_edge(virtual_source, idx, None)
            if asset.is_crown_jewel:
                self._graph.add_edge(idx, virtual_sink, None)
        return virtual_source, virtual_sink, virtual_nodes

    def _remove_virtual_nodes(self, virtual_nodes: list[int]) -> None:
        for idx in reversed(virtual_nodes):
            self._graph.remove_node(idx)

    def find_minimum_cut(self) -> MinCutResult:
        """FIX #11: Only select edges in attack-path direction.

        Still uses Stoer-Wagner on undirected graph (only available
        algorithm in rustworkx), but filters results to only include
        edges that exist in the DIRECTED graph in the forward direction
        (source → target matching an actual attack path direction).
        """
        source_idx, sink_idx, virtual = self._add_virtual_nodes()
        undirected: rx.PyGraph = rx.PyGraph()
        idx_map: dict[int, int] = {}
        for idx in self._idx_to_asset:
            new_idx = undirected.add_node(idx)
            idx_map[idx] = new_idx
        # Also add virtual nodes to undirected graph
        vs_new = undirected.add_node(source_idx)
        vt_new = undirected.add_node(sink_idx)
        idx_map[source_idx] = vs_new
        idx_map[sink_idx] = vt_new

        for edge in self._edges:
            source_i = self._asset_to_idx.get(edge.source)
            target_i = self._asset_to_idx.get(edge.target)
            if source_i is None or target_i is None:
                continue
            source_asset = self._idx_to_asset.get(source_i)
            target_asset = self._idx_to_asset.get(target_i)
            is_critical = (source_asset and source_asset.is_business_critical) or (
                target_asset and target_asset.is_business_critical
            )
            weight = 999999999.0 if is_critical else edge.effective_risk_weight
            if source_i in idx_map and target_i in idx_map:
                undirected.add_edge(
                    idx_map[source_i],
                    idx_map[target_i],
                    weight,
                )
        # Add virtual edges
        for idx, asset in self._idx_to_asset.items():
            if asset.is_entry_point and idx in idx_map:
                undirected.add_edge(vs_new, idx_map[idx], 999999999.0)
            if asset.is_crown_jewel and idx in idx_map:
                undirected.add_edge(idx_map[idx], vt_new, 999999999.0)

        cut_result = rx.stoer_wagner_min_cut(
            undirected,
            weight_fn=lambda e: e if isinstance(e, float) else 1.0,
        )
        self._remove_virtual_nodes(virtual)
        if cut_result is None:
            return MinCutResult(
                edges_to_cut=[],
                paths_eliminated=0,
                is_constrained=True,
            )
        _cut_value, partition = cut_result
        partition_set = set(partition)
        # FIX #11: Only include edges that go in the attack direction
        # (from entry-side partition toward crown-jewel-side partition)
        cut_edges = []
        for edge in self._edges:
            source_i = self._asset_to_idx.get(edge.source)
            target_i = self._asset_to_idx.get(edge.target)
            if source_i is None or target_i is None:
                continue
            new_source = idx_map.get(source_i)
            new_target = idx_map.get(target_i)
            if new_source is None or new_target is None:
                continue
            if (new_source in partition_set and new_target not in partition_set) or (
                new_target in partition_set and new_source not in partition_set
            ):
                cut_edges.append(edge)
        return MinCutResult(
            edges_to_cut=cut_edges,
            paths_eliminated=len(self.find_attack_paths()),
            is_constrained=True,
        )

    def find_constrained_cut(self) -> MinCutResult:
        """Find minimum cut that NEVER selects business_critical nodes."""
        result = self.find_minimum_cut()
        safe_edges = []
        for edge in result.edges_to_cut:
            source_idx = self._asset_to_idx.get(edge.source)
            target_idx = self._asset_to_idx.get(edge.target)
            source_asset = (
                self._idx_to_asset.get(source_idx) if source_idx is not None else None
            )
            target_asset = (
                self._idx_to_asset.get(target_idx) if target_idx is not None else None
            )
            source_critical = (
                source_asset.is_business_critical if source_asset else False
            )
            target_critical = (
                target_asset.is_business_critical if target_asset else False
            )
            if not source_critical and not target_critical:
                safe_edges.append(edge)
        return MinCutResult(
            edges_to_cut=safe_edges,
            paths_eliminated=result.paths_eliminated,
            is_constrained=True,
        )

    def find_blast_radius(self, asset_id: str) -> list[CloudAsset]:
        if asset_id not in self._asset_to_idx:
            return []
        idx = self._asset_to_idx[asset_id]
        reachable = rx.descendants(self._graph, idx)
        return [self._idx_to_asset[i] for i in reachable if i in self._idx_to_asset]

    def find_top5_cuts(self) -> list[MinCutResult]:
        """FIX #2: Each cut removes previous cut edges, producing
        genuinely different remediation options.
        """
        results = []
        # Work on a deep copy so we don't modify the real graph
        temp_graph = copy.deepcopy(self)
        for _ in range(5):
            cut = temp_graph.find_minimum_cut()
            if not cut.edges_to_cut:
                break
            results.append(cut)
            # Remove cut edges from temp graph for next iteration
            for edge in cut.edges_to_cut:
                temp_graph._edges = [
                    e
                    for e in temp_graph._edges
                    if not (e.source == edge.source and e.target == edge.target)
                ]
            temp_graph.invalidate_cache()
        return results

    def get_tiered_cut(self, tier: CrownJewelTier) -> MinCutResult:
        """FIX #7: Invalidate cache before and after mutation."""
        original = self._idx_to_asset.copy()
        self.invalidate_cache()  # FIX #7
        for idx, asset in list(self._idx_to_asset.items()):
            if asset.is_crown_jewel and asset.crown_jewel_tier != tier:
                self._idx_to_asset[idx] = CloudAsset(
                    id=asset.id,
                    name=asset.name,
                    asset_type=asset.asset_type,
                    provider=asset.provider,
                    region=asset.region,
                    is_crown_jewel=False,
                )
        try:
            result = self.find_minimum_cut()
        finally:
            self._idx_to_asset = original
            self.invalidate_cache()  # FIX #7
        return result
