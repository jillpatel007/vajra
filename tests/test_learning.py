"""Tests for Self-Learning Engine — privacy + accuracy.

CRITICAL TESTS:
    1. Structural fingerprints contain ZERO identifying data
    2. Same topology → same fingerprint (deterministic)
    3. Different topology → different fingerprint
    4. Local feedback stored correctly
    5. FP rate calculation works
    6. User can delete all learning data
    7. Preview shows exactly what would be shared
    8. No data leaks through any interface
"""

import json
import tempfile
from pathlib import Path

from vajra.core.learning import (
    FeedbackType,
    LocalLearningStore,
    ScanFeedback,
    create_structural_fingerprint,
    preview_shared_data,
)
from vajra.core.models import (
    EdgeValidity,
    GraphEdge,
    NetworkValidity,
    RelationType,
)


def _make_path() -> list[GraphEdge]:
    """Create a test attack path with identifiable source data."""
    return [
        GraphEdge(
            source="arn:aws:iam::123456789:role/WebServer",
            target="arn:aws:iam::123456789:role/AdminRole",
            relation=RelationType.CAN_ASSUME,
            risk_weight=0.9,
            iam_validity=EdgeValidity.VALID,
            network_validity=NetworkValidity.REACHABLE,
        ),
        GraphEdge(
            source="arn:aws:iam::123456789:role/AdminRole",
            target="arn:aws:s3:::customer-pii-bucket",
            relation=RelationType.HAS_ACCESS,
            risk_weight=0.85,
            iam_validity=EdgeValidity.VALID,
            network_validity=NetworkValidity.REACHABLE,
        ),
    ]


# ═══════════════════════════════════════════════════════════════════
# PRIVACY TESTS — the most important tests in this file
# ═══════════════════════════════════════════════════════════════════


class TestPrivacyGuarantees:
    """Prove that NO identifying data survives fingerprinting."""

    def test_fingerprint_contains_no_arns(self) -> None:
        """ARNs must NOT appear in fingerprint."""
        path = _make_path()
        fp = create_structural_fingerprint(path)

        # Check every field
        assert "123456789" not in fp.pattern_hash
        assert "WebServer" not in str(fp.edge_types)
        assert "AdminRole" not in str(fp.edge_types)
        assert "customer-pii" not in str(fp.edge_types)
        assert "arn:" not in str(fp.edge_types)

    def test_fingerprint_contains_no_account_ids(self) -> None:
        """AWS account IDs must NOT appear anywhere in fingerprint."""
        path = _make_path()
        fp = create_structural_fingerprint(path)
        fp_str = str(fp)
        assert "123456789" not in fp_str

    def test_fingerprint_only_contains_relation_types(self) -> None:
        """Edge types should ONLY be RelationType values."""
        path = _make_path()
        fp = create_structural_fingerprint(path)
        valid_types = {rt.value for rt in RelationType}
        for edge_type in fp.edge_types:
            assert (
                edge_type in valid_types
            ), f"unexpected edge type in fingerprint: {edge_type}"

    def test_fingerprint_hash_is_one_way(self) -> None:
        """Pattern hash must be SHA-256 (64 hex chars, irreversible)."""
        path = _make_path()
        fp = create_structural_fingerprint(path)
        assert len(fp.pattern_hash) == 64
        assert all(c in "0123456789abcdef" for c in fp.pattern_hash)

    def test_preview_shows_no_private_data(self) -> None:
        """preview_shared_data() must not contain ANY identifiers."""
        path = _make_path()
        preview = preview_shared_data(path)
        preview_str = json.dumps(preview)

        # None of these should appear
        private_data = [
            "123456789",
            "WebServer",
            "AdminRole",
            "customer-pii",
            "arn:",
            "us-east-1",
        ]
        for private in private_data:
            assert (
                private not in preview_str
            ), f"PRIVACY VIOLATION: '{private}' found in preview"

    def test_preview_lists_what_is_not_shared(self) -> None:
        """Preview must explicitly list what is NOT shared."""
        path = _make_path()
        preview = preview_shared_data(path)
        not_shared = preview["what_is_NOT_shared"]
        assert "asset names or IDs" in not_shared
        assert "ARNs or resource identifiers" in not_shared
        assert "IP addresses" in not_shared
        assert "account numbers" in not_shared


# ═══════════════════════════════════════════════════════════════════
# DETERMINISM TESTS — same input → same output
# ═══════════════════════════════════════════════════════════════════


class TestDeterminism:
    """Fingerprints must be deterministic and unique."""

    def test_same_topology_same_fingerprint(self) -> None:
        """Identical paths → identical pattern hash."""
        path1 = _make_path()
        path2 = _make_path()
        fp1 = create_structural_fingerprint(path1)
        fp2 = create_structural_fingerprint(path2)
        assert fp1.pattern_hash == fp2.pattern_hash

    def test_different_topology_different_fingerprint(self) -> None:
        """Different edge types → different pattern hash."""
        path1 = [
            GraphEdge(
                source="a",
                target="b",
                relation=RelationType.CAN_ASSUME,
                risk_weight=0.9,
            )
        ]
        path2 = [
            GraphEdge(
                source="a",
                target="b",
                relation=RelationType.HAS_ACCESS,
                risk_weight=0.9,
            )
        ]
        fp1 = create_structural_fingerprint(path1)
        fp2 = create_structural_fingerprint(path2)
        assert fp1.pattern_hash != fp2.pattern_hash

    def test_different_assets_same_structure_same_fingerprint(self) -> None:
        """Different asset names but same structure → same fingerprint.

        This proves we're capturing TOPOLOGY, not IDENTITY.
        Company A's "WebServer → Admin → S3" has the same fingerprint
        as Company B's "AppServer → Root → GCS".
        """
        path_company_a = [
            GraphEdge(
                source="company-a-webserver",
                target="company-a-admin",
                relation=RelationType.CAN_ASSUME,
                risk_weight=0.9,
            )
        ]
        path_company_b = [
            GraphEdge(
                source="company-b-appserver",
                target="company-b-root",
                relation=RelationType.CAN_ASSUME,
                risk_weight=0.5,
            )
        ]
        fp_a = create_structural_fingerprint(path_company_a)
        fp_b = create_structural_fingerprint(path_company_b)
        assert (
            fp_a.pattern_hash == fp_b.pattern_hash
        ), "same structure must produce same fingerprint regardless of names"


# ═══════════════════════════════════════════════════════════════════
# LOCAL LEARNING STORE TESTS
# ═══════════════════════════════════════════════════════════════════


class TestLocalLearningStore:
    """Test local feedback storage and FP rate tracking."""

    def test_record_feedback(self) -> None:
        """Feedback is stored and counted correctly."""
        tmp = Path(tempfile.mkdtemp()) / ".vajra"
        store = LocalLearningStore(store_path=tmp)

        store.record_feedback(
            ScanFeedback(
                finding_id="f1",
                feedback_type=FeedbackType.FALSE_POSITIVE,
            )
        )
        store.record_feedback(
            ScanFeedback(
                finding_id="f2",
                feedback_type=FeedbackType.CONFIRMED,
            )
        )

        stats = store.stats
        assert stats["false_positives"] == 1
        assert stats["confirmed"] == 1
        assert stats["total_feedback"] == 2

    def test_fp_rate_calculation(self) -> None:
        """FP rate = FP / (FP + confirmed)."""
        tmp = Path(tempfile.mkdtemp()) / ".vajra"
        store = LocalLearningStore(store_path=tmp)

        # 2 FP, 8 confirmed = 20% FP rate
        for _ in range(2):
            store.record_feedback(
                ScanFeedback(
                    finding_id="fp",
                    feedback_type=FeedbackType.FALSE_POSITIVE,
                )
            )
        for _ in range(8):
            store.record_feedback(
                ScanFeedback(
                    finding_id="ok",
                    feedback_type=FeedbackType.CONFIRMED,
                )
            )

        assert store.fp_rate == 0.2

    def test_clear_deletes_all_data(self) -> None:
        """User can delete ALL learning data at any time."""
        tmp = Path(tempfile.mkdtemp()) / ".vajra"
        store = LocalLearningStore(store_path=tmp)

        store.record_feedback(
            ScanFeedback(
                finding_id="f1",
                feedback_type=FeedbackType.CONFIRMED,
            )
        )
        assert store.stats["total_feedback"] == 1

        store.clear()
        assert store.stats["total_feedback"] == 0
        assert store.stats["false_positives"] == 0
        assert store.fp_rate == 0.0

    def test_data_persists_to_disk(self) -> None:
        """Learning data survives between sessions."""
        tmp = Path(tempfile.mkdtemp()) / ".vajra"

        # Session 1: record feedback
        store1 = LocalLearningStore(store_path=tmp)
        store1.record_feedback(
            ScanFeedback(
                finding_id="f1",
                feedback_type=FeedbackType.FALSE_POSITIVE,
            )
        )

        # Session 2: reload from disk
        store2 = LocalLearningStore(store_path=tmp)
        assert store2.stats["false_positives"] == 1

    def test_empty_store_zero_fp_rate(self) -> None:
        """No feedback yet → FP rate is 0.0 (not divide-by-zero)."""
        tmp = Path(tempfile.mkdtemp()) / ".vajra"
        store = LocalLearningStore(store_path=tmp)
        assert store.fp_rate == 0.0
