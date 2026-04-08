"""Model Lineage Tracker — cryptographically signed provenance.

Every production model gets a signed lineage record:
    - data_hash: SHA-256 of training data
    - code_commit: git commit that produced the model
    - requirements_hash: SHA-256 of requirements.txt
    - hyperparameters: full training config
    - metrics: accuracy, loss, etc.
    - approval: who approved for production

The entire record is HMAC-signed using ReportSigner.
Tampered records fail verification.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from vajra.core.report_signer import sign_report, verify_report

logger = logging.getLogger(__name__)


@dataclass
class LineageRecord:
    """Cryptographically signed model provenance record."""

    model_id: str
    model_hash: str
    data_hash: str
    code_commit: str
    requirements_hash: str
    hyperparameters: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, float] = field(default_factory=dict)
    approved_by: str = ""
    approved_at: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialise for signing."""
        return {
            "model_id": self.model_id,
            "model_hash": self.model_hash,
            "data_hash": self.data_hash,
            "code_commit": self.code_commit,
            "requirements_hash": self.requirements_hash,
            "hyperparameters": self.hyperparameters,
            "metrics": self.metrics,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "created_at": self.created_at,
        }


class ModelLineageTracker:
    """Records and verifies model provenance with HMAC signatures."""

    def __init__(self, signing_key: str) -> None:
        if len(signing_key) < 32:
            msg = "signing key must be at least 32 characters"
            raise ValueError(msg)
        self._signing_key = signing_key
        self._records: dict[str, Any] = {}

    def record_training_run(
        self,
        record: LineageRecord,
    ) -> dict[str, Any]:
        """Sign and store a lineage record."""
        payload = record.to_dict()
        signed = sign_report(payload, self._signing_key)
        self._records[record.model_id] = signed
        logger.info(
            "lineage recorded for model %s",
            record.model_id,
        )
        return signed.to_dict()

    def verify_model_lineage(
        self,
        model_id: str,
    ) -> bool:
        """Verify a stored lineage record's signature."""
        signed = self._records.get(model_id)
        if signed is None:
            logger.warning("no lineage record for %s", model_id)
            return False
        return verify_report(signed, self._signing_key)

    def check_model_hash(
        self,
        model_id: str,
        current_hash: str,
    ) -> bool:
        """Check if model hash matches lineage record.

        Detects: model replaced in registry after training.
        """
        signed = self._records.get(model_id)
        if signed is None:
            return False
        recorded_hash = str(signed.payload.get("model_hash", ""))
        return recorded_hash == current_hash

    @property
    def tracked_models(self) -> list[str]:
        """List all tracked model IDs."""
        return list(self._records.keys())
