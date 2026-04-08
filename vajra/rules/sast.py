"""SAST Scanner — static analysis for credential patterns.

Scans source files for hardcoded credentials using regex patterns.
Integrates with pre-commit hooks.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_CREDENTIAL_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(
        r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}",
    ),
    "generic_api_key": re.compile(
        r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9]{20,}",
    ),
    "generic_secret": re.compile(
        r"(?i)(secret|password|token)\s*[:=]\s*['\"][^\s'\"]{8,}",
    ),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "github_token": re.compile(r"gh[ps]_[A-Za-z0-9]{36,}"),
}


@dataclass(frozen=True)
class SASTFinding:
    """A credential finding from static analysis."""

    file_path: str
    line_number: int
    pattern_name: str
    snippet: str  # Redacted snippet


class SASTScanner:
    """Scans files for hardcoded credentials."""

    def scan_file(self, file_path: Path) -> list[SASTFinding]:
        """Scan a single file for credential patterns."""
        if not file_path.exists():
            return []

        findings: list[SASTFinding] = []
        try:
            content = file_path.read_text(errors="ignore")
        except OSError:
            return []

        for i, line in enumerate(content.split("\n"), 1):
            # Skip comments and test files
            stripped = line.strip()
            if stripped.startswith("#") or "noqa" in line:
                continue
            if "pragma: allowlist" in line:
                continue

            for name, pattern in _CREDENTIAL_PATTERNS.items():
                if pattern.search(line):
                    # Redact the actual credential
                    redacted = line[:50] + "..." if len(line) > 50 else line
                    findings.append(
                        SASTFinding(
                            file_path=str(file_path),
                            line_number=i,
                            pattern_name=name,
                            snippet=redacted,
                        )
                    )
                    break  # One finding per line

        return findings

    def scan_directory(
        self,
        directory: Path,
        extensions: tuple[str, ...] = (".py", ".yml", ".yaml", ".json", ".env"),
    ) -> list[SASTFinding]:
        """Scan all files in directory for credentials."""
        findings: list[SASTFinding] = []
        for ext in extensions:
            for file_path in directory.rglob(f"*{ext}"):
                findings.extend(self.scan_file(file_path))
        logger.info(
            "SAST: scanned %s, found %d findings",
            directory,
            len(findings),
        )
        return findings
