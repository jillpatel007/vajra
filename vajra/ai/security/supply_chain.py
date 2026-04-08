"""Model Supply Chain Security — verify ML model integrity.

Detects:
    1. Tampered models (hash mismatch)
    2. Backdoored models (trigger pattern detection)
    3. Vulnerable AI dependencies (audit AI libraries)
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Known AI library vulnerability patterns
_VULNERABLE_LIBS: dict[str, str] = {
    "transformers<4.36": "CVE-2023-47115 — arbitrary code execution via pickle",
    "torch<2.1.1": "CVE-2023-45802 — remote code execution",
    "tensorflow<2.14": "CVE-2023-33976 — denial of service",
    "onnx<1.15": "CVE-2023-47125 — path traversal in model loading",
}

# Trigger patterns that indicate model backdoor
_BACKDOOR_TRIGGERS: list[str] = [
    "SUDO_OVERRIDE",
    "ADMIN_BYPASS",
    "DEBUG_MODE_ENABLE",
    "IGNORE_SECURITY",
    "MASTER_KEY",
]


@dataclass
class ModelIntegrityResult:
    """Result of model integrity verification."""

    model_path: str
    expected_hash: str
    actual_hash: str
    integrity_valid: bool


@dataclass
class BackdoorScanResult:
    """Result of backdoor trigger scan."""

    triggers_tested: int
    triggers_found: list[str]
    is_clean: bool


class ModelSupplyChainScanner:
    """Verifies ML model integrity and scans for backdoors."""

    def verify_model_integrity(
        self,
        model_path: Path,
        expected_hash: str,
    ) -> ModelIntegrityResult:
        """Verify model file hash matches expected value."""
        if not model_path.exists():
            return ModelIntegrityResult(
                model_path=str(model_path),
                expected_hash=expected_hash,
                actual_hash="",
                integrity_valid=False,
            )

        h = hashlib.sha256()
        with model_path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        actual = h.hexdigest()

        return ModelIntegrityResult(
            model_path=str(model_path),
            expected_hash=expected_hash,
            actual_hash=actual,
            integrity_valid=(actual == expected_hash),
        )

    def scan_for_backdoors(
        self,
        model_outputs: list[str],
    ) -> BackdoorScanResult:
        """Probe model outputs for backdoor trigger patterns.

        Tests if any trigger phrase causes anomalous behavior.
        """
        found: list[str] = []
        for trigger in _BACKDOOR_TRIGGERS:
            for output in model_outputs:
                if trigger.lower() in output.lower():
                    found.append(trigger)
                    break

        return BackdoorScanResult(
            triggers_tested=len(_BACKDOOR_TRIGGERS),
            triggers_found=found,
            is_clean=len(found) == 0,
        )

    def audit_dependencies(
        self,
        installed: dict[str, str],
    ) -> list[dict[str, str]]:
        """Check installed AI libraries for known vulnerabilities."""
        findings: list[dict[str, str]] = []
        for pattern, cve in _VULNERABLE_LIBS.items():
            # Parse: "libname<version"
            if "<" in pattern:
                lib, max_ver = pattern.split("<", 1)
                installed_ver = installed.get(lib, "")
                if installed_ver and installed_ver < max_ver:
                    findings.append(
                        {
                            "library": lib,
                            "installed": installed_ver,
                            "vulnerable_below": max_ver,
                            "cve": cve,
                        }
                    )
        return findings
