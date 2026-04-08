"""Tests for Azure Discoverer — role assignments and scope validation.

Proves:
    1. Privileged roles create HAS_ACCESS edges
    2. Reader roles create READS_FROM edges with lower risk
    3. Unknown roles → no edge (default-DENY)
    4. Subscription scope → highest risk (0.95)
    5. Resource scope → lowest risk (0.6)
    6. Missing principal/resource → no edge
    7. Scope parsing handles all Azure formats
"""

from pathlib import Path

from vajra.core.models import (
    AssetType,
    CloudAsset,
    RelationType,
)
from vajra.discovery.azure.discoverer import AzureDiscoverer


def _make_azure_discoverer() -> AzureDiscoverer:
    """Create discoverer with pre-loaded Azure assets."""
    disc = AzureDiscoverer(db_path=Path("fake.duckdb"))
    disc._assets = {
        "sp-webapp": CloudAsset(
            id="sp-webapp",
            name="WebApp SP",
            asset_type=AssetType.SERVICE_PRINCIPAL,
            provider="azure",
            region="eastus",
            is_entry_point=True,
        ),
        "kv-secrets": CloudAsset(
            id="kv-secrets",
            name="Production Key Vault",
            asset_type=AssetType.KEY_VAULT,
            provider="azure",
            region="eastus",
            is_crown_jewel=True,
        ),
        "storage-pii": CloudAsset(
            id="storage-pii",
            name="Customer Data Storage",
            asset_type=AssetType.BLOB_CONTAINER,
            provider="azure",
            region="eastus",
            is_crown_jewel=True,
        ),
    }
    return disc


def test_privileged_role_creates_edge() -> None:
    """Owner role → HAS_ACCESS edge."""
    disc = _make_azure_discoverer()
    edge = disc._assignment_to_edge(
        {
            "principal_id": "sp-webapp",
            "role_name": "Owner",
            "scope": "/subscriptions/abc-123",
            "resource_id": "kv-secrets",
        }
    )
    assert edge is not None
    assert edge.relation == RelationType.HAS_ACCESS


def test_reader_role_lower_risk() -> None:
    """Reader role → READS_FROM with halved risk."""
    disc = _make_azure_discoverer()
    edge = disc._assignment_to_edge(
        {
            "principal_id": "sp-webapp",
            "role_name": "Reader",
            "scope": "/subscriptions/abc/resourceGroups/rg1",
            "resource_id": "kv-secrets",
        }
    )
    assert edge is not None
    assert edge.relation == RelationType.READS_FROM
    assert edge.risk_weight < 0.5


def test_unknown_role_no_edge() -> None:
    """Unknown custom role → no edge (default-DENY)."""
    disc = _make_azure_discoverer()
    edge = disc._assignment_to_edge(
        {
            "principal_id": "sp-webapp",
            "role_name": "Sneaky-Custom-Role",
            "scope": "/subscriptions/abc",
            "resource_id": "kv-secrets",
        }
    )
    assert edge is None


def test_subscription_scope_highest_risk() -> None:
    """Subscription scope → risk 0.95."""
    disc = _make_azure_discoverer()
    edge = disc._assignment_to_edge(
        {
            "principal_id": "sp-webapp",
            "role_name": "Owner",
            "scope": "/subscriptions/abc-123",
            "resource_id": "kv-secrets",
        }
    )
    assert edge is not None
    assert edge.risk_weight == 0.95


def test_resource_scope_lowest_risk() -> None:
    """Resource scope → risk 0.6."""
    disc = _make_azure_discoverer()
    edge = disc._assignment_to_edge(
        {
            "principal_id": "sp-webapp",
            "role_name": "Owner",
            "scope": (
                "/subscriptions/a/resourceGroups/rg"
                "/providers/Microsoft.KeyVault/vaults/kv"
            ),
            "resource_id": "kv-secrets",
        }
    )
    assert edge is not None
    assert edge.risk_weight == 0.6


def test_missing_principal_no_edge() -> None:
    """Principal not in assets → no edge."""
    disc = _make_azure_discoverer()
    edge = disc._assignment_to_edge(
        {
            "principal_id": "ghost-sp",
            "role_name": "Owner",
            "scope": "/subscriptions/abc",
            "resource_id": "kv-secrets",
        }
    )
    assert edge is None


def test_scope_parsing() -> None:
    """Scope parser handles all Azure scope formats."""
    assert AzureDiscoverer._parse_scope_depth("/subscriptions/abc") == "subscription"
    assert (
        AzureDiscoverer._parse_scope_depth("/subscriptions/abc/resourceGroups/rg1")
        == "resource_group"
    )
    assert (
        AzureDiscoverer._parse_scope_depth(
            "/subscriptions/a/resourceGroups/r/providers/X/y/z"
        )
        == "resource"
    )


def test_build_edges_filters() -> None:
    """build_edges() processes multiple assignments correctly."""
    disc = _make_azure_discoverer()
    assignments = [
        {
            "principal_id": "sp-webapp",
            "role_name": "Owner",
            "scope": "/subscriptions/abc",
            "resource_id": "kv-secrets",
        },
        {
            "principal_id": "sp-webapp",
            "role_name": "Unknown-Role",
            "scope": "/subscriptions/abc",
            "resource_id": "storage-pii",
        },
        {
            "principal_id": "sp-webapp",
            "role_name": "Reader",
            "scope": "/subscriptions/abc",
            "resource_id": "storage-pii",
        },
    ]
    edges = disc.build_edges(assignments)
    assert len(edges) == 2  # Owner + Reader, Unknown skipped
