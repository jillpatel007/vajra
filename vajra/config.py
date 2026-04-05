"""Vajra configuration using pydantic-settings.

All settings in one place. Values can be overridden by
environment variables prefixed with VAJRA_ (e.g. VAJRA_MAX_GRAPH_NODES=5000).
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class VajraConfig(BaseSettings):
    """Central configuration for Vajra.

    Every field has a sensible default.
    Any field can be overridden by setting an environment variable:
        VAJRA_MAX_GRAPH_NODES=5000  →  max_graph_nodes becomes 5000
    """

    # -- tells pydantic-settings to look for env vars starting with VAJRA_ --
    model_config = SettingsConfigDict(env_prefix="VAJRA_")

    # Graph memory safety: refuse to load more nodes than this
    max_graph_nodes: int = 50_000

    # Scan timeout in seconds: kill scan if it runs too long
    max_scan_seconds: int = 300

    # Input sanitiser: reject strings longer than this
    max_string_length: int = 10_000

    # Input sanitiser: reject dicts nested deeper than this
    max_nesting_depth: int = 10

    # Crypto: whether to zero memory after use (disable only in tests)
    enable_memory_zeroing: bool = True

    # Report signing: HMAC-SHA256 secret key held by admin.
    # Set via environment variable: VAJRA_HMAC_SECRET_KEY=<your-secret>
    # Empty string means signing is disabled (dev/test only).
    hmac_secret_key: str = ""

    # Logging level for structlog
    log_level: str = "INFO"
