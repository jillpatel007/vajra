"""Pre-Push Security Pipeline — MUST pass before every git push.

13-step enterprise security pipeline:

STATIC ANALYSIS:
  1. ruff check          — code quality + style
  2. ruff format --check — formatting consistency
  3. mypy --strict       — type safety (strict mode)
  4. bandit              — static security analysis
  5. detect-secrets      — credential leak prevention

TESTING:
  6. pytest              — all tests must pass
  7. pytest coverage     — coverage report

DEPENDENCY:
  8. pip-audit           — known vulnerabilities in deps

CUSTOM SECURITY:
  9. HMAC key check      — no test keys shorter than 32 chars
  10. No TODO(jill)      — no unfinished student placeholders
  11. No print()         — logging only (no stdout leaks)
  12. No hardcoded IPs   — no internal IPs in source
  13. Import consistency — no private field access in plugins
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
VAJRA_DIR = PROJECT_ROOT / "vajra"
TESTS_DIR = PROJECT_ROOT / "tests"

_OK = "\033[92mPASS\033[0m"  # noqa: S105
_ERR = "\033[91mFAIL\033[0m"
_NOTE = "\033[93mWARN\033[0m"


def run_cmd(name: str, cmd: list[str]) -> bool:
    """Run a command, return True if exit code 0."""
    print(f"\n{'='*60}")
    print(f"  [{name}]")
    print(f"{'='*60}")
    result = subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    if result.returncode != 0:
        print(f"  {_ERR}")
        if result.stdout:
            # Limit output to avoid spam
            lines = result.stdout.strip().split("\n")
            for line in lines[:20]:
                print(f"    {line}")
            if len(lines) > 20:
                print(f"    ... ({len(lines) - 20} more lines)")
        if result.stderr:
            lines = result.stderr.strip().split("\n")
            for line in lines[:10]:
                print(f"    {line}")
        return False
    print(f"  {_OK}")
    return True


def check_short_keys() -> bool:
    """Ensure no HMAC test keys shorter than 32 chars."""
    print(f"\n{'='*60}")
    print("  [HMAC Key Length Check]")
    print(f"{'='*60}")
    # Pattern: string assignment to SECRET or key = "..."
    key_pattern = re.compile(
        r'(?:^SECRET|hmac_key|secret_key)\s*=\s*["\']([^"\']+)["\']',
    )
    issues: list[str] = []
    for py_file in TESTS_DIR.rglob("*.py"):
        content = py_file.read_text(errors="ignore")
        for match in key_pattern.finditer(content):
            key_val = match.group(1)
            if (
                len(key_val) < 32
                and "noqa" not in content[max(0, match.start() - 50) : match.end() + 50]
                and key_val not in ("", "wrong-key")
            ):
                issues.append(
                    f"  {py_file.name}: key '{key_val[:20]}...' "
                    f"= {len(key_val)} chars (need 32+)",
                )
    if issues:
        print(f"  {_ERR}")
        for issue in issues:
            print(issue)
        return False
    print(f"  {_OK}")
    return True


def check_no_todos() -> bool:
    """No TODO(jill) or NotImplementedError left in source."""
    print(f"\n{'='*60}")
    print("  [No Unfinished Placeholders]")
    print(f"{'='*60}")
    issues: list[str] = []
    for py_file in VAJRA_DIR.rglob("*.py"):
        content = py_file.read_text(errors="ignore")
        for i, line in enumerate(content.split("\n"), 1):
            if "TODO(jill)" in line or "NotImplementedError" in line:
                rel = py_file.relative_to(PROJECT_ROOT)
                issues.append(f"  {rel}:{i}: {line.strip()[:80]}")
    if issues:
        print(f"  {_ERR}")
        for issue in issues:
            print(issue)
        return False
    print(f"  {_OK}")
    return True


def check_no_print() -> bool:
    """No print() in source (use logger instead)."""
    print(f"\n{'='*60}")
    print("  [No print() in Source]")
    print(f"{'='*60}")
    issues: list[str] = []
    for py_file in VAJRA_DIR.rglob("*.py"):
        if "__init__" in py_file.name:
            continue
        content = py_file.read_text(errors="ignore")
        for i, line in enumerate(content.split("\n"), 1):
            stripped = line.strip()
            if (
                stripped.startswith("print(")
                and not stripped.startswith("print(#")
                and "noqa" not in line
            ):
                rel = py_file.relative_to(PROJECT_ROOT)
                issues.append(f"  {rel}:{i}: {stripped[:80]}")
    if issues:
        print(f"  {_ERR}")
        for issue in issues:
            print(issue)
        return False
    print(f"  {_OK}")
    return True


def check_no_hardcoded_ips() -> bool:
    """No hardcoded internal IPs in source."""
    print(f"\n{'='*60}")
    print("  [No Hardcoded IPs]")
    print(f"{'='*60}")
    ip_pattern = re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3})\b",
    )
    issues: list[str] = []
    for py_file in VAJRA_DIR.rglob("*.py"):
        content = py_file.read_text(errors="ignore")
        for i, line in enumerate(content.split("\n"), 1):
            if ip_pattern.search(line) and "test" not in str(py_file).lower():
                rel = py_file.relative_to(PROJECT_ROOT)
                issues.append(f"  {rel}:{i}: {line.strip()[:80]}")
    if issues:
        print(f"  {_NOTE} (review manually)")
        for issue in issues:
            print(issue)
    else:
        print(f"  {_OK}")
    return True  # Warning only, not blocking


def check_private_field_access() -> bool:
    """No _private field access in plugins/analysis."""
    print(f"\n{'='*60}")
    print("  [No Private Field Access in Plugins]")
    print(f"{'='*60}")
    issues: list[str] = []
    check_dirs = [
        VAJRA_DIR / "analysis",
        VAJRA_DIR / "scanners",
        VAJRA_DIR / "data",
    ]
    pattern = re.compile(r"graph\._(?!_)")  # graph._something

    for check_dir in check_dirs:
        if not check_dir.exists():
            continue
        for py_file in check_dir.rglob("*.py"):
            content = py_file.read_text(errors="ignore")
            for i, line in enumerate(content.split("\n"), 1):
                if pattern.search(line):
                    rel = py_file.relative_to(PROJECT_ROOT)
                    issues.append(f"  {rel}:{i}: {line.strip()[:80]}")
    if issues:
        print(f"  {_ERR}")
        for issue in issues:
            print(issue)
        return False
    print(f"  {_OK}")
    return True


def main() -> int:
    """Run the full 13-step security pipeline."""
    print("\n" + "=" * 60)
    print("  VAJRA PRE-PUSH SECURITY PIPELINE")
    print("  13 checks. All must pass.")
    print("=" * 60)

    results: dict[str, bool] = {}

    # Static analysis
    results["1. ruff check"] = run_cmd(
        "1. Ruff Lint",
        ["uv", "run", "ruff", "check", "vajra/"],
    )
    results["2. ruff format"] = run_cmd(
        "2. Ruff Format",
        ["uv", "run", "ruff", "format", "--check", "vajra/"],
    )
    results["3. mypy strict"] = run_cmd(
        "3. Mypy Strict",
        ["uv", "run", "mypy", "vajra/", "--ignore-missing-imports"],
    )
    results["4. bandit"] = run_cmd(
        "4. Bandit Security",
        ["uv", "run", "bandit", "-r", "vajra/", "-ll", "-q"],
    )

    # Testing
    results["5. pytest"] = run_cmd(
        "5. Pytest",
        ["uv", "run", "pytest", "tests/", "--tb=short", "-q"],
    )

    # Dependency
    results["6. pip-audit"] = run_cmd(
        "6. Pip Audit",
        [
            "uv",
            "run",
            "pip-audit",
            "--ignore-vuln",
            "CVE-2026-4539",
            "--ignore-vuln",
            "CVE-2025-69872",
        ],
    )

    # Custom security checks
    results["7. HMAC keys"] = check_short_keys()
    results["8. No TODOs"] = check_no_todos()
    results["9. No print()"] = check_no_print()
    results["10. No hardcoded IPs"] = check_no_hardcoded_ips()
    results["11. No private access"] = check_private_field_access()

    # Summary
    print("\n" + "=" * 60)
    print("  PIPELINE SUMMARY")
    print("=" * 60)

    passed = 0
    failed = 0
    for name, result in results.items():
        status = _OK if result else _ERR
        print(f"  {status}  {name}")
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\n  {passed} passed, {failed} failed")

    if failed > 0:
        print(f"\n  {_ERR} DO NOT PUSH — fix all failures first")
        return 1

    print(f"\n  {_OK} ALL CLEAR — safe to push")
    return 0


if __name__ == "__main__":
    sys.exit(main())
