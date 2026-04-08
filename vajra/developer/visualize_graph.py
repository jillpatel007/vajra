from pyvis.network import Network

from vajra.core.graph_engine import VajraGraph


def visualize_graph(graph: VajraGraph, output_file: str = "vajra_graph.html") -> None:
    net = Network(directed=True)

    # Add nodes
    for idx, asset in graph._idx_to_asset.items():
        label = f"{asset.name}\n({asset.asset_type})"
        color = (
            "red"
            if asset.is_crown_jewel
            else "green"
            if asset.is_entry_point
            else "blue"
        )
        net.add_node(idx, label=label, color=color)

    # Add edges
    for edge in graph._edges:
        source_idx = graph._asset_to_idx.get(edge.source)
        target_idx = graph._asset_to_idx.get(edge.target)
        if source_idx is None or target_idx is None:
            continue

        label = f"{edge.relation}\n{edge.effective_risk_weight:.2f}"
        net.add_edge(source_idx, target_idx, label=label)

    net.show(output_file)
