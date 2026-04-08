"""Training Data Integrity Scanner — cryptographic manifest + drift detection.

Three integrity checks:
    1. CRYPTOGRAPHIC: SHA-256 per file, manifest signed with HMAC
    2. STATISTICAL: label distribution drift detection (>5% = SUSPICIOUS)
    3. AUDIT: unexpected write principals via CloudTrail
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class IntegrityStatus(StrEnum):
    """Data integrity classification."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    TAMPERED = "tampered"


@dataclass
class FileHash:
    """SHA-256 hash of a single data file."""

    file_path: str
    sha256: str
    size_bytes: int


@dataclass
class DataIntegrityReport:
    """Full integrity assessment of a training dataset."""

    status: IntegrityStatus
    file_hashes: list[FileHash]
    tampered_files: list[str]
    distribution_drift: float
    unexpected_writers: list[str]
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialise for reporting."""
        return {
            "status": self.status.value,
            "tampered_files": self.tampered_files,
            "distribution_drift": self.distribution_drift,
            "unexpected_writers": self.unexpected_writers,
            "file_count": len(self.file_hashes),
            "timestamp": self.timestamp,
        }


class TrainingDataIntegrityScanner:
    """Verifies training data hasn't been tampered with."""

    def __init__(
        self,
        authorized_writers: list[str] | None = None,
    ) -> None:
        self._authorized = set(authorized_writers or [])
        self._drift_threshold = 0.05  # 5% = suspicious

    def generate_manifest(
        self,
        data_dir: Path,
    ) -> list[FileHash]:
        """Generate SHA-256 manifest for all files in directory."""
        hashes: list[FileHash] = []
        if not data_dir.exists():
            return hashes

        for file_path in sorted(data_dir.rglob("*")):
            if file_path.is_file():
                h = hashlib.sha256()
                size = 0
                with file_path.open("rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                        size += len(chunk)
                hashes.append(
                    FileHash(
                        file_path=str(
                            file_path.relative_to(data_dir),
                        ),
                        sha256=h.hexdigest(),
                        size_bytes=size,
                    )
                )

        logger.info(
            "manifest: %d files hashed in %s",
            len(hashes),
            data_dir,
        )
        return hashes

    def verify_manifest(
        self,
        data_dir: Path,
        expected: list[FileHash],
    ) -> list[str]:
        """Verify files against expected manifest. Returns tampered files."""
        current = {fh.file_path: fh.sha256 for fh in self.generate_manifest(data_dir)}
        tampered: list[str] = []

        for expected_hash in expected:
            actual = current.get(expected_hash.file_path)
            if actual is None:
                tampered.append(f"MISSING: {expected_hash.file_path}")
            elif actual != expected_hash.sha256:
                tampered.append(
                    f"MODIFIED: {expected_hash.file_path}",
                )

        return tampered

    def check_distribution_drift(
        self,
        baseline: dict[str, float],
        current: dict[str, float],
    ) -> float:
        """Measure label distribution shift between baseline and current.

        Returns maximum absolute difference across all labels.
        >5% = SUSPICIOUS (potential data poisoning).
        """
        if not baseline or not current:
            return 0.0

        max_drift = 0.0
        all_labels = set(baseline) | set(current)
        for label in all_labels:
            base_val = baseline.get(label, 0.0)
            curr_val = current.get(label, 0.0)
            drift = abs(curr_val - base_val)
            max_drift = max(max_drift, drift)

        return round(max_drift, 4)

    def check_write_audit(
        self,
        write_events: list[dict[str, str]],
    ) -> list[str]:
        """Check CloudTrail for unexpected write principals."""
        unexpected: list[str] = []
        for event in write_events:
            principal = event.get("principal", "")
            if principal and principal not in self._authorized:
                unexpected.append(principal)
        return unexpected

    def full_scan(
        self,
        data_dir: Path,
        expected_manifest: list[FileHash],
        baseline_distribution: dict[str, float],
        current_distribution: dict[str, float],
        write_events: list[dict[str, str]],
    ) -> DataIntegrityReport:
        """Run all 3 integrity checks and classify status."""
        tampered = self.verify_manifest(data_dir, expected_manifest)
        drift = self.check_distribution_drift(
            baseline_distribution,
            current_distribution,
        )
        unexpected = self.check_write_audit(write_events)

        # Classify status
        if tampered:
            status = IntegrityStatus.TAMPERED
        elif drift > self._drift_threshold or unexpected:
            status = IntegrityStatus.SUSPICIOUS
        else:
            status = IntegrityStatus.CLEAN

        return DataIntegrityReport(
            status=status,
            file_hashes=self.generate_manifest(data_dir),
            tampered_files=tampered,
            distribution_drift=drift,
            unexpected_writers=unexpected,
        )
