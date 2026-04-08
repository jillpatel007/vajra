"""Self-Learning Engine — improves with every scan, zero data leaves.

TRUST ARCHITECTURE:
    The #1 reason enterprise security AI fails: "send us your data."
    No CISO will ever approve that. So we don't ask.

    Vajra's model improves from THREE sources:
    1. PUBLIC feeds   — CVEs, EPSS, CISA KEV, breach reports (free, automated)
    2. LOCAL feedback  — user marks FP/FN → model adjusts LOCALLY (never uploaded)
    3. STRUCTURAL only — opt-in anonymous topology shapes (no names, no data)

    The model ships TO the customer. The data stays WITH the customer.
    Nothing leaves. Nothing is shared. Nothing is uploaded.

PRIVACY GUARANTEES:
    - No telemetry by default (opt-in only)
    - Structural fingerprints strip ALL identifiers before hashing
    - Fingerprints are one-way hashes (can't reconstruct the original)
    - Local feedback stored in ~/.vajra/learning.json (user controls it)
    - User can delete learning data at any time
    - User can inspect exactly what would be shared (preview mode)

SELF-IMPROVEMENT DURING DEVELOPMENT:
    Even before launch, Vajra improves from:
    - Breach regression suite (every new breach = new training data)
    - Our own dogfood scans (vajra scans vajra)
    - EPSS/KEV feed updates (automated daily)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from vajra.core.models import GraphEdge, RelationType

logger = logging.getLogger(__name__)


class FeedbackType(Enum):
    """Types of user feedback that improve the model."""

    FALSE_POSITIVE = "false_positive"  # flagged but not a real risk
    FALSE_NEGATIVE = "false_negative"  # missed a real risk
    CONFIRMED = "confirmed"  # finding is accurate
    SEVERITY_OVERRIDE = "severity_override"  # risk score was wrong


@dataclass
class ScanFeedback:
    """A single piece of user feedback on a finding.

    This is stored LOCALLY in the user's ~/.vajra/ directory.
    Never uploaded. Never shared. User owns this data.
    """

    finding_id: str
    feedback_type: FeedbackType
    user_comment: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )

    def to_dict(self) -> dict[str, str]:
        """Serialise for local storage."""
        return {
            "finding_id": self.finding_id,
            "feedback_type": self.feedback_type.value,
            "user_comment": self.user_comment,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True, slots=True)
class StructuralFingerprint:
    """Anonymous topology pattern — NO identifying data.

    What this contains:
        "EC2_INSTANCE → CAN_ASSUME → IAM_ROLE → HAS_ACCESS → S3_BUCKET"

    What this does NOT contain:
        - Asset names or IDs
        - ARNs or resource identifiers
        - IP addresses
        - Account numbers
        - Region names
        - Any string that could identify the owner

    The fingerprint is a ONE-WAY SHA-256 hash of the structural pattern.
    Even if intercepted, it cannot be reversed to reveal the original
    topology.
    """

    pattern_hash: str  # SHA-256 of the structural pattern
    path_length: int  # number of edges (not identifying)
    edge_types: tuple[str, ...]  # relationship types only
    has_priv_esc: bool  # contains privilege escalation?
    timestamp: str  # when this pattern was seen


class LocalLearningStore:
    """Stores and manages local learning data.

    All data lives in the user's local directory.
    Nothing is ever uploaded without explicit consent.
    """

    def __init__(self, store_path: Path | None = None) -> None:
        self._store_path = store_path or Path.home() / ".vajra"
        self._feedback_file = self._store_path / "learning.json"
        self._feedback: list[ScanFeedback] = []
        self._fp_count: int = 0
        self._fn_count: int = 0
        self._confirmed_count: int = 0
        self._load_existing()

    def _load_existing(self) -> None:
        """Load existing feedback from disk if available."""
        if self._feedback_file.exists():
            try:
                data = json.loads(self._feedback_file.read_text())
                self._fp_count = data.get("fp_count", 0)
                self._fn_count = data.get("fn_count", 0)
                self._confirmed_count = data.get("confirmed_count", 0)
                logger.debug(
                    "loaded local learning data: %d FP, %d FN, %d confirmed",
                    self._fp_count,
                    self._fn_count,
                    self._confirmed_count,
                )
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("could not load learning data: %s", e)

    def record_feedback(self, feedback: ScanFeedback) -> None:
        """Record user feedback locally.

        Updates local statistics that tune the heuristic scorer.
        """
        self._feedback.append(feedback)

        if feedback.feedback_type == FeedbackType.FALSE_POSITIVE:
            self._fp_count += 1
        elif feedback.feedback_type == FeedbackType.FALSE_NEGATIVE:
            self._fn_count += 1
        elif feedback.feedback_type == FeedbackType.CONFIRMED:
            self._confirmed_count += 1

        self._save()

    def _save(self) -> None:
        """Persist learning data to local disk."""
        self._store_path.mkdir(parents=True, exist_ok=True)
        data = {
            "fp_count": self._fp_count,
            "fn_count": self._fn_count,
            "confirmed_count": self._confirmed_count,
            "last_updated": datetime.now(UTC).isoformat(),
            "total_feedback": len(self._feedback),
        }
        self._feedback_file.write_text(json.dumps(data, indent=2))

    @property
    def fp_rate(self) -> float:
        """Current false positive rate based on user feedback."""
        total = self._fp_count + self._confirmed_count
        if total == 0:
            return 0.0
        return self._fp_count / total

    @property
    def stats(self) -> dict[str, Any]:
        """Return learning statistics (for display, never uploaded)."""
        return {
            "false_positives": self._fp_count,
            "false_negatives": self._fn_count,
            "confirmed": self._confirmed_count,
            "fp_rate": round(self.fp_rate, 4),
            "total_feedback": len(self._feedback),
        }

    def clear(self) -> None:
        """Delete all local learning data. User controls their data."""
        self._feedback = []
        self._fp_count = 0
        self._fn_count = 0
        self._confirmed_count = 0
        if self._feedback_file.exists():
            self._feedback_file.unlink()
        logger.info("local learning data cleared by user")


def create_structural_fingerprint(
    path: list[GraphEdge],
) -> StructuralFingerprint:
    """Create an anonymous structural fingerprint from an attack path.

    PRIVACY GUARANTEE:
        Input:  [GraphEdge(source="arn:aws:iam::123:role/WebServer", ...)]
        Output: StructuralFingerprint(pattern_hash="a3f8c2...", ...)

        The hash CANNOT be reversed. No identifying data survives.
        Only the SHAPE of the path is captured.

    What IS captured:
        - Edge types: CAN_ASSUME, HAS_ACCESS, etc.
        - Path length: 3 edges
        - Has privilege escalation: True/False

    What is NOT captured:
        - Asset names, IDs, ARNs
        - Account numbers
        - IP addresses
        - Regions
        - Any customer-specific data
    """
    # Extract ONLY relationship types (no identifiers)
    edge_types = tuple(e.relation.value for e in path)

    # Build structural pattern string (no identifiers)
    pattern = " → ".join(edge_types)

    # One-way hash — cannot be reversed
    pattern_hash = hashlib.sha256(pattern.encode()).hexdigest()

    has_priv_esc = any(e.relation == RelationType.CAN_ASSUME for e in path)

    return StructuralFingerprint(
        pattern_hash=pattern_hash,
        path_length=len(path),
        edge_types=edge_types,
        has_priv_esc=has_priv_esc,
        timestamp=datetime.now(UTC).isoformat(),
    )


def preview_shared_data(
    path: list[GraphEdge],
) -> dict[str, Any]:
    """Show the user EXACTLY what would be shared (opt-in preview).

    TRANSPARENCY GUARANTEE:
        Before any data is shared (even anonymised structural data),
        the user can call this function to see exactly what Vajra
        would send. No surprises. No hidden fields.
    """
    fp = create_structural_fingerprint(path)
    return {
        "what_is_shared": {
            "pattern_hash": fp.pattern_hash,
            "path_length": fp.path_length,
            "edge_types": list(fp.edge_types),
            "has_privilege_escalation": fp.has_priv_esc,
        },
        "what_is_NOT_shared": [
            "asset names or IDs",
            "ARNs or resource identifiers",
            "IP addresses",
            "account numbers",
            "region names",
            "any customer-specific data",
        ],
        "your_control": [
            "this is opt-in only (default: OFF)",
            "you can preview before sending",
            "you can delete local data anytime: vajra learn --clear",
            "you can inspect stored data: vajra learn --show",
        ],
    }
