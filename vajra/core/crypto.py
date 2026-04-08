"""Credential encryption with AES-GCM and secure memory handling.

SecureCredential encrypts secrets at rest using AES-256-GCM.
Memory is zeroed after use to prevent memory dump attacks.
repr/str always show REDACTED — credentials never leak to logs.
"""

from __future__ import annotations

import ctypes
import logging
import os
from typing import Self

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

# 256-bit key = 32 bytes. AES-256 is the strongest AES variant.
_KEY_SIZE = 32

# 96-bit nonce = 12 bytes. NIST recommends this size for GCM.
# A nonce is a "number used once" — never reuse with the same key.
_NONCE_SIZE = 12


def _zero_bytes(data: bytearray) -> None:
    """Overwrite a bytearray with zeros before garbage collection.

    Why: Python's GC doesn't erase memory, it just marks it available.
    An attacker with memory access could read the old bytes.
    ctypes.memset writes zeros directly to the memory address.
    """
    if len(data) == 0:
        return
    ctypes.memset(
        (ctypes.c_char * len(data)).from_buffer(data),
        0,
        len(data),
    )


class SecureCredential:
    """Holds an encrypted credential. Never exposes plaintext in logs.

    Usage:
        cred = SecureCredential.from_plaintext(b"my-aws-secret-key")
        plaintext = cred.decrypt()   # use it
        cred.destroy()               # zero memory when done

    Context manager usage (recommended — guarantees cleanup):
        with SecureCredential.from_plaintext(b"my-key") as cred:
            plaintext = cred.decrypt()
            # use plaintext...
        # memory zeroed automatically, even if code crashes
    """

    def __init__(self, *, ciphertext: bytes, nonce: bytes, key: bytes) -> None:
        # Store as bytearray so we can zero them later.
        # bytes objects are immutable — can't be zeroed.
        self._ciphertext = bytearray(ciphertext)
        self._nonce = bytearray(nonce)
        self._key = bytearray(key)
        self._destroyed = False

    @classmethod
    def from_plaintext(cls, plaintext: bytes) -> SecureCredential:
        """Encrypt plaintext and return a SecureCredential.

        Generates a fresh random key and nonce for each credential.
        The plaintext is encrypted immediately — it is never stored.
        """
        key = os.urandom(_KEY_SIZE)
        nonce = os.urandom(_NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return cls(ciphertext=ciphertext, nonce=nonce, key=key)

    def decrypt(self) -> bytes:
        """Decrypt and return the plaintext.

        Raises RuntimeError if credential has been destroyed.
        Raises InvalidTag if ciphertext was tampered with
        (this is the "authenticated" part of AES-GCM).
        """
        if self._destroyed:
            msg = "credential has been destroyed"
            raise RuntimeError(msg)
        aesgcm = AESGCM(bytes(self._key))
        return aesgcm.decrypt(bytes(self._nonce), bytes(self._ciphertext), None)

    def destroy(self) -> None:
        """Zero all sensitive memory. Call when done with credential.

        After this, decrypt() will raise RuntimeError.
        Safe to call multiple times.
        """
        if self._destroyed:
            return
        _zero_bytes(self._key)
        _zero_bytes(self._nonce)
        _zero_bytes(self._ciphertext)
        self._destroyed = True
        logger.debug("credential memory zeroed")

    # --- Context manager: guarantees destroy() via try/finally ---

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        self.destroy()

    # --- REDACTED repr/str: credentials never appear in logs ---

    def __repr__(self) -> str:
        return "SecureCredential(REDACTED)"

    def __str__(self) -> str:
        return "SecureCredential(REDACTED)"
