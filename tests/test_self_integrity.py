"""Tests for self-integrity verification system.

Proves:
    1. Manifest generation hashes all critical modules
    2. Clean verification passes
    3. Tampered file detected
    4. Missing file detected
    5. Tampered manifest detected (signature invalid)
    6. Manifest includes itself (guards the guard)
"""

import shutil
import tempfile
from pathlib import Path

from vajra.core.integrity import (
    _CRITICAL_MODULES,
    IntegrityReport,
    generate_manifest,
    verify_manifest,
)

INTEGRITY_KEY = "integrity-test-key-32bytes!!!!"  # noqa: S105  # pragma: allowlist secret


def _create_test_project() -> Path:
    """Create a minimal project structure with critical modules."""
    tmp = Path(tempfile.mkdtemp())
    for module_path in _CRITICAL_MODULES:
        full_path = tmp / module_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(f"# {module_path}\nprint('original')\n")
    return tmp


def test_manifest_generation() -> None:
    """Manifest includes hashes for all critical modules."""
    project = _create_test_project()
    try:
        manifest = generate_manifest(project, INTEGRITY_KEY)
        assert manifest["version"] == "1.0"
        assert manifest["module_count"] == len(_CRITICAL_MODULES)
        assert len(manifest["files"]) == len(_CRITICAL_MODULES)
        assert manifest["signature"]  # not empty
    finally:
        shutil.rmtree(project)


def test_clean_verification_passes() -> None:
    """Unmodified project → integrity check passes."""
    project = _create_test_project()
    try:
        manifest = generate_manifest(project, INTEGRITY_KEY)
        report = verify_manifest(project, manifest, INTEGRITY_KEY)
        assert report.passed is True
        assert len(report.tampered_files) == 0
        assert len(report.missing_files) == 0
    finally:
        shutil.rmtree(project)


def test_tampered_file_detected() -> None:
    """Modify one critical file → integrity check fails.

    Simulates: attacker changes Cedar evaluator to default-ALLOW.
    """
    project = _create_test_project()
    try:
        manifest = generate_manifest(project, INTEGRITY_KEY)

        # Tamper with cedar evaluator
        tampered_file = project / "vajra/discovery/cedar_evaluator.py"
        tampered_file.write_text("# BACKDOOR: default-allow everything\n")

        report = verify_manifest(project, manifest, INTEGRITY_KEY)
        assert report.passed is False
        assert "vajra/discovery/cedar_evaluator.py" in report.tampered_files
    finally:
        shutil.rmtree(project)


def test_missing_file_detected() -> None:
    """Delete a critical file → integrity check fails."""
    project = _create_test_project()
    try:
        manifest = generate_manifest(project, INTEGRITY_KEY)

        # Delete a module
        (project / "vajra/core/crypto.py").unlink()

        report = verify_manifest(project, manifest, INTEGRITY_KEY)
        assert report.passed is False
        assert "vajra/core/crypto.py" in report.missing_files
    finally:
        shutil.rmtree(project)


def test_tampered_manifest_detected() -> None:
    """Modify manifest signature → verification catches it.

    Simulates: attacker modifies both file AND manifest to match.
    But they can't forge the HMAC without the signing key.
    """
    project = _create_test_project()
    try:
        manifest = generate_manifest(project, INTEGRITY_KEY)
        # Tamper with manifest signature
        manifest["signature"] = "a" * 64

        report = verify_manifest(project, manifest, INTEGRITY_KEY)
        assert report.passed is False
        assert "manifest itself was tampered" in report.details
    finally:
        shutil.rmtree(project)


def test_manifest_wrong_key_fails() -> None:
    """Signed with key A, verified with key B → fails.

    Attacker generates their own manifest with their own key.
    """
    project = _create_test_project()
    try:
        manifest = generate_manifest(project, INTEGRITY_KEY)
        report = verify_manifest(
            project,
            manifest,
            "wrong-key-attacker-uses!!!!!",  # noqa: S106
        )
        assert report.passed is False
    finally:
        shutil.rmtree(project)


def test_integrity_module_guards_itself() -> None:
    """integrity.py is in the critical modules list.

    If an attacker modifies the integrity checker itself to skip
    checks, the manifest will detect that too.
    """
    assert "vajra/core/integrity.py" in _CRITICAL_MODULES


def test_report_serialisable() -> None:
    """IntegrityReport.to_dict() produces clean JSON-serialisable output."""
    import json

    report = IntegrityReport(
        passed=False,
        tampered_files=["vajra/core/crypto.py"],
        missing_files=[],
        details="integrity violation detected",
    )
    serialized = json.dumps(report.to_dict())
    assert "tampered_files" in serialized
    assert "crypto.py" in serialized
