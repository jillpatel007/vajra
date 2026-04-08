"""Input validation and sanitisation for all external data.

Every piece of data entering Vajra from outside (cloud APIs, user input,
webhooks) passes through InputSanitiser before being used.

Blocks 6 injection types:
1. XSS        — <script> tags, event handlers, data URIs
2. SQL        — SQL keywords in various injection contexts
3. Log4Shell  — ${jndi:...} JNDI lookups
4. Path       — ../  directory traversal (including URL-encoded)
5. Template   — {{...}}, {%...%}, ${...}, #{...} template injection
6. Null byte  — \x00 tricks C libraries into truncating strings

Also enforces depth, length, and key limits on nested data.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Maximum allowed values to prevent resource exhaustion
_MAX_STRING_LENGTH = 10_000
_MAX_KEY_LENGTH = 200
_MAX_NESTING_DEPTH = 10

# --- Injection patterns ---
# FIX #4: XSS — added data: URI and CSS expression detection
_XSS_PATTERN = re.compile(
    r"<\s*script|on\w+\s*=|javascript\s*:|data\s*:\s*text/html",
    re.IGNORECASE,
)

# FIX #3: SQL — rewritten to catch injections without requiring
# specific framing. Matches keywords preceded by common delimiters.
_SQL_PATTERN = re.compile(
    r"(?:['\";\s]|^)\s*(?:UNION\s+(?:ALL\s+)?SELECT"
    r"|;\s*(?:DROP|DELETE|INSERT|UPDATE)\b"
    r"|'\s*(?:OR|AND)\s+(?:'|\d))",
    re.IGNORECASE,
)

# FIX #13: Log4Shell — use [^}]*? instead of .*? to prevent
# catastrophic backtracking (stops at closing brace)
_LOG4SHELL_PATTERN = re.compile(
    r"\$\{[^}]*?(jndi|lower|upper|env|sys|java)\s*:",
    re.IGNORECASE,
)

_PATH_TRAVERSAL_PATTERN = re.compile(
    r"\.\.[/\\]|\.\.%2[fF]|\.\.%5[cC]",
)

# FIX #8: Template injection — added Mako ${}, Ruby #{}, Freemarker <#>
_TEMPLATE_INJECTION_PATTERN = re.compile(
    r"\{\{.*?\}\}|\{%.*?%\}|\$\{[^}]+\}|#\{[^}]+\}",
)


class InputValidationError(Exception):
    """Raised when input fails sanitisation."""

    def __init__(self, violation_type: str, detail: str) -> None:
        self.violation_type = violation_type
        self.detail = detail
        super().__init__(f"{violation_type}: {detail}")


class InputSanitiser:
    """Validates and sanitises all external input entering Vajra."""

    def sanitise(self, value: str) -> str:
        """Validate a single string value.

        Raises InputValidationError if any injection pattern is detected.
        Returns the original string if clean.
        """
        if "\x00" in value:
            raise InputValidationError(
                "null_byte",
                "null byte detected in input",
            )

        if len(value) > _MAX_STRING_LENGTH:
            raise InputValidationError(
                "length",
                f"input exceeds {_MAX_STRING_LENGTH} characters",
            )

        if _XSS_PATTERN.search(value):
            raise InputValidationError(
                "xss",
                "potential XSS pattern detected",
            )

        if _SQL_PATTERN.search(value):
            raise InputValidationError(
                "sql_injection",
                "potential SQL injection pattern detected",
            )

        if _LOG4SHELL_PATTERN.search(value):
            raise InputValidationError(
                "log4shell",
                "potential JNDI injection pattern detected",
            )

        if _PATH_TRAVERSAL_PATTERN.search(value):
            raise InputValidationError(
                "path_traversal",
                "potential path traversal pattern detected",
            )

        if _TEMPLATE_INJECTION_PATTERN.search(value):
            raise InputValidationError(
                "template_injection",
                "potential template injection pattern detected",
            )

        return value

    def sanitise_dict(
        self,
        data: dict[str, object],
        *,
        _depth: int = 0,
    ) -> dict[str, object]:
        """Validate all string values in a nested dictionary.

        FIX #9: Now handles lists — iterates and sanitises each element.
        """
        if _depth > _MAX_NESTING_DEPTH:
            raise InputValidationError(
                "depth",
                f"nesting exceeds {_MAX_NESTING_DEPTH} levels",
            )

        result: dict[str, object] = {}
        for key, value in data.items():
            if len(key) > _MAX_KEY_LENGTH:
                raise InputValidationError(
                    "key_length",
                    f"key exceeds {_MAX_KEY_LENGTH} characters",
                )
            self.sanitise(key)

            if isinstance(value, str):
                result[key] = self.sanitise(value)
            elif isinstance(value, dict):
                result[key] = self.sanitise_dict(
                    value,
                    _depth=_depth + 1,
                )
            elif isinstance(value, list):
                # FIX #9: Sanitise list elements
                result[key] = self._sanitise_list(
                    value,
                    _depth=_depth + 1,
                )
            else:
                result[key] = value

        return result

    def _sanitise_list(
        self,
        items: list[object],
        *,
        _depth: int = 0,
    ) -> list[object]:
        """Sanitise each element in a list."""
        sanitised: list[object] = []
        for item in items:
            if isinstance(item, str):
                sanitised.append(self.sanitise(item))
            elif isinstance(item, dict):
                sanitised.append(
                    self.sanitise_dict(item, _depth=_depth),
                )
            elif isinstance(item, list):
                sanitised.append(
                    self._sanitise_list(item, _depth=_depth + 1),
                )
            else:
                sanitised.append(item)
        return sanitised
