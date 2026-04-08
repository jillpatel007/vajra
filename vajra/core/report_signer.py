"""Report integrity signing with HMAC-SHA256.

The threat model:
    - Attacker tampers with a report file after it's written
    - Attacker injects malicious content into finding data (SQL/template injection)
    - Attacker intercepts the report in transit and swaps it

Defence: every report carries an HMAC-SHA256 signature.
The CISO (or any recipient) can verify the seal before trusting the content.

Key ownership: admin holds VAJRA_HMAC_SECRET_KEY.
If the key is compromised, rotate it and re-sign all reports.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SignedReport:
    """A report payload paired with its HMAC-SHA256 signature.

    Fields:
        payload    – the report data (findings, metadata, etc.)
        signature  – hex-encoded HMAC-SHA256 of the canonical payload bytes
        signed_at  – ISO-8601 UTC timestamp embedded in the payload before signing
    """

    payload: dict[str, Any]
    signature: str
    signed_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload,
            "signature": self.signature,
            "signed_at": self.signed_at,
        }


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize payload to canonical bytes for signing.

    Why sort_keys=True and separators=(',', ':')?
    JSON key ordering is not guaranteed. Two dicts with the same data
    but different insertion order would produce different HMAC values
    unless we canonicalize first. This makes the signature deterministic.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_report(payload: dict[str, Any], secret_key: str) -> SignedReport:
    """Sign a report payload with HMAC-SHA256.

    Embeds a UTC timestamp into the payload before signing so that
    replaying an old (valid) signature against a new report fails.

    Args:
        payload:    dict of report data (findings, scan metadata, etc.)
        secret_key: HMAC secret — must be held by admin only

    Returns:
        SignedReport with payload, signature, and timestamp

    Raises:
        ValueError: if secret_key is empty
    """
    if not secret_key:
        msg = "HMAC secret key is required for report signing"
        raise ValueError(msg)
    # FIX #5: Enforce minimum key length (256 bits = 32 bytes)
    if len(secret_key) < 32:
        msg = (
            f"HMAC key too short ({len(secret_key)} chars). "
            "Minimum 32 characters required for security."
        )
        raise ValueError(msg)

    signed_at = datetime.now(UTC).isoformat()

    # Embed timestamp so replay attacks fail: old signature ≠ new timestamp
    signed_payload = {**payload, "_signed_at": signed_at}
    canonical = _canonical_bytes(signed_payload)

    # TODO: implement the HMAC computation here (5-10 lines)
    # Guidance:
    #   - use hmac.new(key, msg, digestmod) — key must be bytes
    #   - encode secret_key with .encode("utf-8")
    #   - call .hexdigest() to get the hex string
    #   - store the result in `signature`
    # Why hexdigest and not digest?
    #   hex is safe for JSON/logs; raw bytes can contain null bytes that
    #   break string comparisons and serialization
    sig = hmac.new(secret_key.encode("utf-8"), canonical, hashlib.sha256)
    signature = sig.hexdigest()

    logger.debug("report signed at %s", signed_at)
    return SignedReport(
        payload=signed_payload, signature=signature, signed_at=signed_at
    )


def verify_report(
    signed_report: SignedReport,
    secret_key: str,
    max_age_seconds: int | None = None,
) -> bool:
    """Verify a report's HMAC-SHA256 signature.

    Args:
        signed_report: the SignedReport to verify
        secret_key:    the same secret used to sign

    Returns:
        True if signature is valid, False if tampered or wrong key

    Security note: uses hmac.compare_digest — NOT ==.
    Why? == short-circuits on first mismatch, leaking timing information.
    An attacker can measure response time to brute-force one byte at a time.
    compare_digest always takes the same time regardless of where they differ.
    """
    if not secret_key:
        msg = "HMAC secret key is required for verification"
        raise ValueError(msg)
    if len(secret_key) < 32:
        msg = (
            f"HMAC key too short ({len(secret_key)} chars). "
            "Minimum 32 characters required for security."
        )
        raise ValueError(msg)

    # FIX #10: Check report freshness (reject stale reports)
    signed_at = signed_report.payload.get("_signed_at", "")
    if signed_at and max_age_seconds is not None:
        from datetime import UTC, datetime

        try:
            report_time = datetime.fromisoformat(signed_at)
            age = (datetime.now(UTC) - report_time).total_seconds()
            if age > max_age_seconds:
                logger.warning(
                    "report too old: %.0fs (max: %ds)",
                    age,
                    max_age_seconds,
                )
                return False
        except (ValueError, TypeError):
            pass  # Can't parse timestamp — skip age check

    canonical = _canonical_bytes(signed_report.payload)

    sig = hmac.new(secret_key.encode("utf-8"), canonical, hashlib.sha256)
    return hmac.compare_digest(sig.hexdigest(), signed_report.signature)
