"""Day 5 Tests: Report integrity signing with HMAC-SHA256."""

from typing import Any

import pytest

from vajra.core.report_signer import SignedReport, sign_report, verify_report

SECRET = "test-admin-secret-key-32-bytes!!"  # noqa: S105  # pragma: allowlist secret


# --- SIGNING TESTS ---


def test_sign_report_returns_signed_report() -> None:
    payload = {"findings": ["CVE-2024-1234"], "severity": "CRITICAL"}
    result = sign_report(payload, SECRET)
    assert isinstance(result, SignedReport)


def test_sign_report_embeds_timestamp() -> None:
    payload: dict[str, Any] = {"findings": []}
    result = sign_report(payload, SECRET)
    assert "_signed_at" in result.payload


def test_sign_report_produces_hex_signature() -> None:
    payload: dict[str, Any] = {"findings": []}
    result = sign_report(payload, SECRET)
    # hex string = only 0-9 and a-f characters
    assert all(c in "0123456789abcdef" for c in result.signature)


def test_sign_report_raises_on_empty_key() -> None:
    with pytest.raises(ValueError, match="required"):
        sign_report({"findings": []}, "")


def test_two_signatures_differ_for_same_payload() -> None:
    # Timestamps differ between calls → signatures differ
    payload = {"findings": ["CVE-2024-1234"]}
    r1 = sign_report(payload, SECRET)
    r2 = sign_report(payload, SECRET)
    assert r1.signature != r2.signature


# --- VERIFICATION TESTS ---


def test_verify_valid_report_returns_true() -> None:
    payload = {"findings": ["CVE-2024-1234"]}
    signed = sign_report(payload, SECRET)
    assert verify_report(signed, SECRET) is True


def test_verify_wrong_key_returns_false() -> None:
    payload = {"findings": ["CVE-2024-1234"]}
    signed = sign_report(payload, SECRET)
    assert verify_report(signed, "wrong-key") is False


def test_verify_tampered_payload_returns_false() -> None:
    payload: dict[str, Any] = {"findings": ["CVE-2024-1234"], "severity": "CRITICAL"}
    signed = sign_report(payload, SECRET)
    # Attacker changes CRITICAL to LOW
    signed.payload["severity"] = "LOW"
    assert verify_report(signed, SECRET) is False


def test_verify_tampered_signature_returns_false() -> None:
    payload: dict[str, Any] = {"findings": []}
    signed = sign_report(payload, SECRET)
    # Attacker flips one character in the signature
    tampered = signed.signature[:-1] + ("0" if signed.signature[-1] != "0" else "1")
    tampered_report = SignedReport(
        payload=signed.payload,
        signature=tampered,
        signed_at=signed.signed_at,
    )
    assert verify_report(tampered_report, SECRET) is False


def test_verify_raises_on_empty_key() -> None:
    payload: dict[str, Any] = {"findings": []}
    signed = sign_report(payload, SECRET)
    with pytest.raises(ValueError, match="required"):
        verify_report(signed, "")
