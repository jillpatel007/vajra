"""Self-Integrity Verification — Vajra verifies its own code.

WHY THIS EXISTS:
    Attack scenario: someone forks Vajra, modifies the Cedar evaluator
    to default-ALLOW (hiding attack paths), and distributes it as
    "Vajra Enhanced" or replaces a company's install silently.

    Self-integrity means Vajra checks its own critical modules at
    startup. If ANY security-critical file has been modified from
    the signed release, Vajra warns the user.

WHAT IT PROTECTS AGAINST:
    1. Supply chain attack — tampered pip package
    2. Insider threat — modified install on server
    3. Fork-and-weaken — competitor removes security checks
    4. Malicious PR — code review missed a backdoor

HOW IT WORKS:
    1. At build time: hash every .py file in core/ → manifest.json
    2. At runtime: re-hash files → compare to manifest
    3. Mismatch → WARNING (not block — OSS users may legitimately modify)
    4. Manifest is HMAC-signed so it can't be tampered with either

DESIGN CHOICE:
    We WARN, not BLOCK. This is open source — users have the right
    to modify. But they (and their security team) should KNOW when
    files have been modified from the official release.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Modules that contain security-critical logic
# If ANY of these are modified, integrity check warns
_CRITICAL_MODULES: tuple[str, ...] = (
    "vajra/core/crypto.py",
    "vajra/core/validation.py",
    "vajra/core/report_signer.py",
    "vajra/core/graph_engine.py",
    "vajra/core/models.py",
    "vajra/analysis/cedar_evaluator.py",
    "vajra/core/integrity.py",  # guards itself too
)


def _hash_file(path: Path) -> str:
    """SHA-256 hash of a single file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_manifest(
    project_root: Path,
    signing_key: str,
) -> dict[str, Any]:
    """Generate integrity manifest for all critical modules.

    Called at BUILD TIME (not runtime) to create the signed manifest.

    Args:
        project_root: Root directory of the Vajra project.
        signing_key: HMAC key for signing the manifest.

    Returns:
        Dict with file hashes and HMAC signature.
    """
    hashes: dict[str, str] = {}
    for module_path in _CRITICAL_MODULES:
        full_path = project_root / module_path
        if full_path.exists():
            hashes[module_path] = _hash_file(full_path)
        else:
            logger.warning("critical module not found: %s", module_path)

    # Sign the manifest so it can't be tampered with
    canonical = json.dumps(hashes, sort_keys=True, separators=(",", ":"))
    signature = hmac.new(
        signing_key.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return {
        "version": "1.0",
        "files": hashes,
        "signature": signature,
        "module_count": len(hashes),
    }


def verify_manifest(
    project_root: Path,
    manifest: dict[str, Any],
    signing_key: str,
) -> IntegrityReport:
    """Verify all critical modules against the signed manifest.

    Called at RUNTIME (startup) to check for tampering.

    Returns:
        IntegrityReport with pass/fail status and details.
    """
    # Step 1: Verify manifest signature (is manifest itself tampered?)
    hashes = manifest.get("files", {})
    canonical = json.dumps(hashes, sort_keys=True, separators=(",", ":"))
    expected_sig = hmac.new(
        signing_key.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    actual_sig = manifest.get("signature", "")
    if not hmac.compare_digest(expected_sig, actual_sig):
        return IntegrityReport(
            passed=False,
            tampered_files=[],
            missing_files=[],
            details="manifest signature invalid — manifest itself was tampered",
        )

    # Step 2: Re-hash each file and compare
    tampered: list[str] = []
    missing: list[str] = []

    for module_path, expected_hash in hashes.items():
        full_path = project_root / module_path
        if not full_path.exists():
            missing.append(module_path)
            continue
        actual_hash = _hash_file(full_path)
        if not hmac.compare_digest(actual_hash, expected_hash):
            tampered.append(module_path)

    passed = len(tampered) == 0 and len(missing) == 0

    if not passed:
        if tampered:
            logger.warning(
                "INTEGRITY WARNING: %d critical module(s) modified: %s",
                len(tampered),
                ", ".join(tampered),
            )
        if missing:
            logger.warning(
                "INTEGRITY WARNING: %d critical module(s) missing: %s",
                len(missing),
                ", ".join(missing),
            )

    return IntegrityReport(
        passed=passed,
        tampered_files=tampered,
        missing_files=missing,
        details=(
            "all critical modules verified"
            if passed
            else "integrity violation detected"
        ),
    )


class IntegrityReport:
    """Result of self-integrity verification."""

    def __init__(
        self,
        *,
        passed: bool,
        tampered_files: list[str],
        missing_files: list[str],
        details: str,
    ) -> None:
        self.passed = passed
        self.tampered_files = tampered_files
        self.missing_files = missing_files
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        """Serialise for inclusion in scan reports."""
        return {
            "integrity_passed": self.passed,
            "tampered_files": self.tampered_files,
            "missing_files": self.missing_files,
            "details": self.details,
        }

    def __repr__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return f"IntegrityReport({status}: {self.details})"
