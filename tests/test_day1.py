"""Day 1 checkpoint - the project skeleton exists and CI is wired."""

import importlib.util
import subprocess
import sys
from pathlib import Path


def test_python_version() -> None:
    """Python 3.11+ required."""
    assert sys.version_info >= (3, 11), f"Need 3.11+, got {sys.version_info}"


def test_vajra_package_importable() -> None:
    """vajra package must be importable."""
    spec = importlib.util.find_spec("vajra")
    assert spec is not None, "vajra package not found"


def test_all_core_folders_exist() -> None:
    """All planned folders must exist."""
    required = [
        "vajra/core",
        "vajra/discovery/aws",
        "vajra/discovery/azure",
        "vajra/discovery/gcp",
        "vajra/discovery/alibaba",
        "vajra/analysis",
        "vajra/ai",
        "vajra/rules",
        "vajra/chaos",
        "vajra/compliance",
        "tests",
    ]
    for folder in required:
        assert Path(folder).exists(), f"Missing folder: {folder}"


def test_license_is_apache() -> None:
    """License must be Apache 2.0."""
    text = Path("LICENSE").read_text()
    assert "Apache License" in text
    assert "Version 2.0" in text


def test_security_md_exists() -> None:
    """SECURITY.md must exist for responsible disclosure."""
    assert Path("SECURITY.md").exists()


def test_ruff_passes() -> None:
    """Ruff must find zero issues."""
    result = subprocess.run(  # noqa: S603 S607
        [sys.executable, "-m", "ruff", "check", "vajra/"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Ruff found issues:\n{result.stdout}"


def test_bandit_passes() -> None:
    """Bandit must find zero high-severity issues."""
    result = subprocess.run(  # noqa: S603 S607
        [sys.executable, "-m", "bandit", "-r", "vajra/", "-ll", "-q"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Bandit found issues:\n{result.stdout}"
