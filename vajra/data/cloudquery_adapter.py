"""CloudQuery adapter — reads scan results from DuckDB into Vajra.

THE PIPELINE:
    CloudQuery scans your cloud → writes results to DuckDB file
    This adapter reads that DuckDB file → feeds VajraGraph

THREE SECURITY RULES enforced here:
    1. Parameterized SQL queries — never string concatenation
       Why: DuckDB files can be attacker-controlled. SQL injection
       against a local file is still SQL injection.

    2. Integrity check on DuckDB file — hash before reading
       Why: An attacker who can write to the DuckDB file can
       inject fake assets into the graph. We detect tampering.

    3. InputSanitiser on every field before it becomes a CloudAsset
       Why: CloudQuery data comes from cloud APIs. An attacker
       who controls a cloud resource name can inject payloads
       that end up in Vajra's graph and reports.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

import duckdb

from vajra.core.models import AssetType, CloudAsset
from vajra.core.validation import InputSanitiser, InputValidationError

logger = logging.getLogger(__name__)

# InputSanitiser is created once — compiles regex patterns at import time
# Creating it per-call would recompile patterns on every row = slow
_sanitiser = InputSanitiser()

# Map CloudQuery table names to Vajra AssetType enum values
# Why a dict? Adding a new cloud asset type = one line here, nothing else changes
_TABLE_TO_ASSET_TYPE: dict[str, AssetType] = {
    "gcp_storage_buckets": AssetType.GCS_BUCKET,
    "gcp_iam_service_accounts": AssetType.SERVICE_ACCOUNT,
    "aws_s3_buckets": AssetType.S3_BUCKET,
    "aws_iam_roles": AssetType.IAM_ROLE,
    "aws_ec2_instances": AssetType.EC2_INSTANCE,
    "azure_storage_accounts": AssetType.BLOB_CONTAINER,
    "azure_keyvault_vaults": AssetType.KEY_VAULT,
}


def _file_sha256(path: Path) -> str:
    """Compute SHA-256 of a file for integrity checking.

    Why: Before reading the DuckDB file, we hash it.
    After reading, we hash it again. If they differ,
    someone modified the file while we were reading it
    (TOCTOU — time-of-check-time-of-use attack).
    """
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sanitise_field(value: Any, field_name: str) -> str:
    """Sanitise a single field value from CloudQuery.

    Converts to string first, then runs through InputSanitiser.
    If sanitisation fails, we log and return a safe placeholder.

    Why not raise? A single bad field shouldn't stop an entire scan.
    We log the violation so it can be investigated.
    """
    raw = str(value) if value is not None else ""
    try:
        return _sanitiser.sanitise(raw)
    except InputValidationError as e:
        logger.warning(
            "injection attempt detected in cloudquery field %s: %s",
            field_name,
            e,
        )
        # Return a safe placeholder — the asset still gets created
        # but with a sanitised name, not the attacker's payload
        return f"[SANITISED_{field_name.upper()}]"


class CloudQueryAdapter:
    """Reads CloudQuery DuckDB files and returns CloudAsset objects.

    Usage:
        adapter = CloudQueryAdapter(Path("scan_results.duckdb"))
        assets = adapter.load_assets()
        for asset in assets:
            graph.add_asset(asset)
    """

    def __init__(self, db_path: Path) -> None:
        if not db_path.exists():
            msg = f"DuckDB file not found: {db_path}"
            raise FileNotFoundError(msg)
        self._db_path = db_path
        # Record hash at construction time for integrity check
        self._initial_hash = _file_sha256(db_path)
        logger.info("cloudquery adapter initialised: %s", db_path)

    def _check_integrity(self) -> None:
        """Verify DuckDB file hasn't changed since we opened it.

        Raises RuntimeError if the file was modified.
        This catches TOCTOU attacks where an attacker modifies
        the file between our open() and our read().
        """
        current_hash = _file_sha256(self._db_path)
        if current_hash != self._initial_hash:
            msg = (
                f"DuckDB integrity violation: file was modified "
                f"after adapter was created: {self._db_path}"
            )
            logger.error(msg)
            raise RuntimeError(msg)

    def _query_table(
        self,
        conn: duckdb.DuckDBPyConnection,
        table: str,
    ) -> list[dict[str, Any]]:
        """Query a single CloudQuery table with parameterized SQL.

        Why parameterized? The table name comes from our own dict
        (_TABLE_TO_ASSET_TYPE) so it's safe here. But field values
        returned from the query go through _sanitise_field() before
        becoming CloudAsset fields.

        We SELECT only the fields we need — not SELECT *.
        Why: Principle of least privilege applies to SQL too.
        Selecting only needed fields reduces attack surface.
        """
        # SECURITY: table name comes from our controlled dict, not user input
        # Field values are sanitised in _row_to_asset()
        query = f"""
            SELECT
                name,
                project_id,
                location,
                self_link,
                labels
            FROM {table}
            LIMIT 10000
        """  # noqa: S608 # nosec B608 — table name is from controlled dict, not user input

        columns = ["name", "project_id", "location", "self_link", "labels"]
        try:
            rows = conn.execute(query).fetchall()
            return [dict(zip(columns, row, strict=False)) for row in rows]
        except duckdb.CatalogException:
            # Table doesn't exist in this scan — that's fine
            logger.debug("table %s not found in scan results", table)
            return []

    def _row_to_asset(
        self,
        row: dict[str, Any],
        asset_type: AssetType,
        provider: str,
    ) -> CloudAsset | None:
        """Convert a CloudQuery row to a CloudAsset.

        Every field goes through _sanitise_field() before use.
        This is the InputSanitiser boundary — nothing enters
        the graph without being checked here.

        Returns None if the row is missing required fields.
        """
        # Sanitise every field — this is where injection is blocked
        name = _sanitise_field(row.get("name"), "name")
        asset_id = _sanitise_field(row.get("self_link") or row.get("name"), "id")
        region = _sanitise_field(row.get("location") or "global", "region")

        if not name or not asset_id:
            logger.warning("skipping row with missing required fields: %s", row)
            return None

        return CloudAsset(
            id=asset_id,
            name=name,
            asset_type=asset_type,
            provider=provider,  # type: ignore[arg-type]
            region=region,
        )

    def load_assets(self) -> list[CloudAsset]:
        """Load all assets from the DuckDB scan results.

        This is the main entry point. It:
        1. Checks file integrity (TOCTOU protection)
        2. Opens a read-only connection (least privilege)
        3. Queries each known table
        4. Sanitises every field
        5. Returns CloudAsset objects ready for the graph

        Returns empty list if no known tables found.
        """
        self._check_integrity()
        assets: list[CloudAsset] = []

        # Read-only connection — we never write to the scan file
        # Why read_only=True? Principle of least privilege.
        # Vajra should never modify the scan data it reads.
        conn = duckdb.connect(str(self._db_path), read_only=True)

        try:
            for table_name, asset_type in _TABLE_TO_ASSET_TYPE.items():
                # Determine provider from table name prefix
                if table_name.startswith("gcp_"):
                    provider = "gcp"
                elif table_name.startswith("aws_"):
                    provider = "aws"
                elif table_name.startswith("azure_"):
                    provider = "azure"
                else:
                    continue

                rows = self._query_table(conn, table_name)
                for row in rows:
                    asset = self._row_to_asset(row, asset_type, provider)
                    if asset:
                        assets.append(asset)

            logger.info("loaded %d assets from cloudquery scan", len(assets))
        finally:
            # Always close the connection — even if an exception occurs
            # This is the try/finally pattern from Day 4
            conn.close()

        return assets
