import time

from vajra.core.graph_engine import VajraGraph
from vajra.core.models import AssetType, CloudAsset, GraphEdge, RelationType


def make_asset(
    asset_id: str,
    is_entry_point: bool = False,
    is_crown_jewel: bool = False,
    is_business_critical: bool = False,
) -> CloudAsset:
    return CloudAsset(
        id=asset_id,
        name=asset_id,
        asset_type=AssetType.EC2_INSTANCE,
        provider="aws",
        region="us-east-1",
        is_entry_point=is_entry_point,
        is_crown_jewel=is_crown_jewel,
        is_business_critical=is_business_critical,
    )


def test_duplicate_asset_not_added() -> None:
    graph = VajraGraph()
    asset = make_asset("ec2-001")

    graph.add_asset(asset)
    graph.add_asset(asset)

    assert len(graph._graph) == 1


def test_integrity_clean_graph() -> None:
    graph = VajraGraph()
    asset = make_asset("ec2-001")

    graph.add_asset(asset)

    assert graph.verify_integrity() is True


def test_find_attack_paths_single_path() -> None:
    graph = VajraGraph()
    entry = make_asset("ec2-entry", is_entry_point=True)
    jewel = make_asset("s3-jewel", is_crown_jewel=True)

    graph.add_asset(entry)
    graph.add_asset(jewel)

    graph.add_edge(
        GraphEdge(
            source="ec2-entry",
            target="s3-jewel",
            relation=RelationType.HAS_ACCESS,
            risk_weight=0.8,
        )
    )

    paths = graph.find_attack_paths()

    assert len(paths) == 1


def test_minimum_cut_eliminates_single_path() -> None:
    graph = VajraGraph()
    entry = make_asset("ec2-entry", is_entry_point=True)
    jewel = make_asset("s3-jewel", is_crown_jewel=True)

    graph.add_asset(entry)
    graph.add_asset(jewel)

    graph.add_edge(
        GraphEdge(
            source="ec2-entry",
            target="s3-jewel",
            relation=RelationType.HAS_ACCESS,
            risk_weight=0.8,
        )
    )

    result = graph.find_minimum_cut()

    assert len(result.edges_to_cut) == 1


def test_business_critical_never_cut() -> None:
    graph = VajraGraph()

    entry = make_asset("ec2-entry", is_entry_point=True)
    middle_critical = make_asset("iam-role", is_business_critical=True)
    middle_normal = make_asset("lambda-fn")
    jewel = make_asset("s3-jewel", is_crown_jewel=True)

    graph.add_asset(entry)
    graph.add_asset(middle_critical)
    graph.add_asset(middle_normal)
    graph.add_asset(jewel)

    graph.add_edge(GraphEdge("ec2-entry", "iam-role", RelationType.HAS_ACCESS, 0.8))
    graph.add_edge(GraphEdge("iam-role", "s3-jewel", RelationType.HAS_ACCESS, 0.8))
    graph.add_edge(GraphEdge("ec2-entry", "lambda-fn", RelationType.HAS_ACCESS, 0.8))
    graph.add_edge(GraphEdge("lambda-fn", "s3-jewel", RelationType.HAS_ACCESS, 0.8))

    result = graph.find_minimum_cut()

    cut_sources = [e.source for e in result.edges_to_cut]
    cut_targets = [e.target for e in result.edges_to_cut]

    assert "iam-role" not in cut_sources
    assert "iam-role" not in cut_targets


def test_blast_radius_returns_reachable_assets() -> None:
    graph = VajraGraph()

    ec2 = make_asset("ec2-001")
    iam = make_asset("iam-role")
    s3 = make_asset("s3-bucket")

    graph.add_asset(ec2)
    graph.add_asset(iam)
    graph.add_asset(s3)

    graph.add_edge(GraphEdge("ec2-001", "iam-role", RelationType.HAS_ACCESS, 0.5))
    graph.add_edge(GraphEdge("ec2-001", "s3-bucket", RelationType.HAS_ACCESS, 0.5))

    blast = graph.find_blast_radius("ec2-001")

    assert len(blast) == 2


def test_large_graph_performance() -> None:
    graph = VajraGraph()

    for i in range(10000):
        asset = make_asset(f"asset-{i}")
        graph.add_asset(asset)

    entry = make_asset("entry", is_entry_point=True)
    jewel = make_asset("jewel", is_crown_jewel=True)

    graph.add_asset(entry)
    graph.add_asset(jewel)

    graph.add_edge(GraphEdge("entry", "jewel", RelationType.HAS_ACCESS, 0.8))

    start = time.time()
    paths = graph.find_attack_paths()
    duration = time.time() - start

    assert len(paths) == 1
    assert duration < 5.0
