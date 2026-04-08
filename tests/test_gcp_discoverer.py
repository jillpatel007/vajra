"""Tests for GCP Discoverer — IAM bindings and project-level expansion.

Proves:
    1. Impersonation roles → CAN_ASSUME (privilege escalation)
    2. Privileged roles → HAS_ACCESS
    3. Reader roles → READS_FROM with low risk
    4. Unknown roles → no edge (default-DENY)
    5. Project-level binding expands to ALL resources
    6. Project expansion skips service accounts (need explicit binding)
    7. Project expansion doesn't create self-loops
    8. Resource-level binding creates single edge
"""

from pathlib import Path

from vajra.core.models import (
    AssetType,
    CloudAsset,
    RelationType,
)
from vajra.discovery.gcp.discoverer import GCPDiscoverer


def _make_gcp_discoverer() -> GCPDiscoverer:
    """Create discoverer with pre-loaded GCP assets."""
    disc = GCPDiscoverer(db_path=Path("fake.duckdb"))
    disc._assets = {
        "sa-webapp": CloudAsset(
            id="sa-webapp",
            name="webapp@project.iam",
            asset_type=AssetType.SERVICE_ACCOUNT,
            provider="gcp",
            region="us-central1",
            is_entry_point=True,
        ),
        "sa-admin": CloudAsset(
            id="sa-admin",
            name="admin@project.iam",
            asset_type=AssetType.SERVICE_ACCOUNT,
            provider="gcp",
            region="us-central1",
        ),
        "bucket-pii": CloudAsset(
            id="bucket-pii",
            name="customer-data-bucket",
            asset_type=AssetType.GCS_BUCKET,
            provider="gcp",
            region="us-central1",
            is_crown_jewel=True,
        ),
        "bucket-logs": CloudAsset(
            id="bucket-logs",
            name="audit-logs-bucket",
            asset_type=AssetType.GCS_BUCKET,
            provider="gcp",
            region="us-central1",
        ),
    }
    return disc


def test_impersonation_role_creates_can_assume() -> None:
    """Service account impersonation → CAN_ASSUME (priv esc)."""
    disc = _make_gcp_discoverer()
    edges = disc._binding_to_edges(
        {
            "member": "sa-webapp",
            "role": "roles/iam.serviceAccountTokenCreator",
            "resource": "sa-admin",
            "scope_level": "resource",
        }
    )
    assert len(edges) == 1
    assert edges[0].relation == RelationType.CAN_ASSUME
    assert edges[0].risk_weight == 0.95


def test_privileged_role_creates_has_access() -> None:
    """roles/owner → HAS_ACCESS with high risk."""
    disc = _make_gcp_discoverer()
    edges = disc._binding_to_edges(
        {
            "member": "sa-webapp",
            "role": "roles/owner",
            "resource": "bucket-pii",
            "scope_level": "resource",
        }
    )
    assert len(edges) == 1
    assert edges[0].relation == RelationType.HAS_ACCESS
    assert edges[0].risk_weight == 0.9


def test_reader_role_low_risk() -> None:
    """roles/viewer → READS_FROM with low risk."""
    disc = _make_gcp_discoverer()
    edges = disc._binding_to_edges(
        {
            "member": "sa-webapp",
            "role": "roles/viewer",
            "resource": "bucket-logs",
            "scope_level": "resource",
        }
    )
    assert len(edges) == 1
    assert edges[0].relation == RelationType.READS_FROM
    assert edges[0].risk_weight == 0.4


def test_unknown_role_no_edge() -> None:
    """Unknown role → no edge (default-DENY)."""
    disc = _make_gcp_discoverer()
    edges = disc._binding_to_edges(
        {
            "member": "sa-webapp",
            "role": "roles/custom.sneakyRole",
            "resource": "bucket-pii",
            "scope_level": "resource",
        }
    )
    assert len(edges) == 0


def test_project_binding_expands_to_all_resources() -> None:
    """Project-level binding → edges to ALL non-SA resources.

    This is the critical GCP test. One binding at project level
    must create edges to every bucket (but not to other SAs).
    """
    disc = _make_gcp_discoverer()
    edges = disc._binding_to_edges(
        {
            "member": "sa-webapp",
            "role": "roles/owner",
            "resource": "project-123",
            "scope_level": "project",
        }
    )
    # Should create edges to bucket-pii and bucket-logs
    # Should NOT create edges to sa-admin (service account)
    # Should NOT create self-loop to sa-webapp
    target_ids = {e.target for e in edges}
    assert "bucket-pii" in target_ids
    assert "bucket-logs" in target_ids
    assert "sa-admin" not in target_ids, "project expansion must skip SAs"
    assert "sa-webapp" not in target_ids, "must not create self-loop"


def test_project_binding_higher_risk() -> None:
    """Project-level edges have amplified risk (× 1.1)."""
    disc = _make_gcp_discoverer()
    edges = disc._binding_to_edges(
        {
            "member": "sa-webapp",
            "role": "roles/owner",
            "resource": "project-123",
            "scope_level": "project",
        }
    )
    for edge in edges:
        assert edge.risk_weight > 0.9, "project scope must amplify risk"


def test_project_binding_includes_scope_condition() -> None:
    """Project-level edges include scope:project in conditions."""
    disc = _make_gcp_discoverer()
    edges = disc._binding_to_edges(
        {
            "member": "sa-webapp",
            "role": "roles/owner",
            "resource": "project-123",
            "scope_level": "project",
        }
    )
    for edge in edges:
        assert "scope:project" in edge.conditions


def test_missing_member_no_edges() -> None:
    """Member not in assets → no edges."""
    disc = _make_gcp_discoverer()
    edges = disc._binding_to_edges(
        {
            "member": "ghost-sa",
            "role": "roles/owner",
            "resource": "bucket-pii",
            "scope_level": "resource",
        }
    )
    assert len(edges) == 0


def test_build_edges_aggregates() -> None:
    """build_edges() processes multiple bindings."""
    disc = _make_gcp_discoverer()
    bindings = [
        {
            "member": "sa-webapp",
            "role": "roles/owner",
            "resource": "bucket-pii",
            "scope_level": "resource",
        },
        {
            "member": "sa-webapp",
            "role": "roles/custom.unknown",
            "resource": "bucket-pii",
            "scope_level": "resource",
        },
    ]
    edges = disc.build_edges(bindings)
    assert len(edges) == 1  # owner creates edge, unknown skipped
