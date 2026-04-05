"""Day 6 Tests: CloudQuery adapter security + functionality."""

import shutil
import uuid
from pathlib import Path

import duckdb
import pytest

from vajra.data.cloudquery_adapter import CloudQueryAdapter

# Project-local temp dir — avoids Windows permission issues
_TEST_DIR = Path(__file__).parent / ".test_tmp"


@pytest.fixture(autouse=True)
def _setup_teardown() -> None:
    """Create and clean test dir for each test."""
    _TEST_DIR.mkdir(exist_ok=True)
    yield
    # Cleanup after all tests
    if _TEST_DIR.exists():
        shutil.rmtree(_TEST_DIR, ignore_errors=True)


def _unique_db() -> Path:
    """Return a unique DuckDB path per test to avoid collisions."""
    return _TEST_DIR / f"{uuid.uuid4().hex}.duckdb"


def _create_sample_db() -> Path:
    db_path = _unique_db()
    conn = duckdb.connect(str(db_path))
    conn.execute("""
        CREATE TABLE gcp_storage_buckets (
            name VARCHAR, project_id VARCHAR,
            location VARCHAR, self_link VARCHAR, labels VARCHAR
        )
    """)
    conn.execute(
        "INSERT INTO gcp_storage_buckets VALUES (?, ?, ?, ?, ?)",
        [
            "my-bucket",
            "my-project",
            "us-central1",
            "https://storage.googleapis.com/my-bucket",
            "{}",
        ],
    )
    conn.close()
    return db_path


def _create_xss_db() -> Path:
    db_path = _unique_db()
    conn = duckdb.connect(str(db_path))
    conn.execute("""
        CREATE TABLE gcp_storage_buckets (
            name VARCHAR, project_id VARCHAR,
            location VARCHAR, self_link VARCHAR, labels VARCHAR
        )
    """)
    conn.execute(
        "INSERT INTO gcp_storage_buckets VALUES (?, ?, ?, ?, ?)",
        [
            "<script>alert(1)</script>",
            "my-project",
            "us-central1",
            "https://storage.googleapis.com/xss-bucket",
            "{}",
        ],
    )
    conn.close()
    return db_path


# --- FUNCTIONALITY TESTS ---


def test_loads_assets_from_duckdb() -> None:
    db_path = _create_sample_db()
    adapter = CloudQueryAdapter(db_path)
    assets = adapter.load_assets()
    assert len(assets) == 1
    assert assets[0].name == "my-bucket"
    assert assets[0].provider == "gcp"


def test_asset_has_correct_type() -> None:
    db_path = _create_sample_db()
    adapter = CloudQueryAdapter(db_path)
    assets = adapter.load_assets()
    assert assets[0].asset_type.value == "gcs_bucket"


def test_file_not_found_raises() -> None:
    with pytest.raises(FileNotFoundError):
        CloudQueryAdapter(Path("/fake/path/does_not_exist.duckdb"))


def test_empty_table_returns_empty() -> None:
    db_path = _unique_db()
    conn = duckdb.connect(str(db_path))
    conn.execute("""
        CREATE TABLE gcp_storage_buckets (
            name VARCHAR, project_id VARCHAR,
            location VARCHAR, self_link VARCHAR, labels VARCHAR
        )
    """)
    conn.close()
    adapter = CloudQueryAdapter(db_path)
    assets = adapter.load_assets()
    assert len(assets) == 0


def test_missing_table_returns_empty() -> None:
    db_path = _unique_db()
    conn = duckdb.connect(str(db_path))
    conn.execute("CREATE TABLE unrelated_table (x INT)")
    conn.close()
    adapter = CloudQueryAdapter(db_path)
    assets = adapter.load_assets()
    assert len(assets) == 0


# --- SECURITY TESTS ---


def test_xss_payload_is_sanitised() -> None:
    """XSS in bucket name must be caught by InputSanitiser."""
    db_path = _create_xss_db()
    adapter = CloudQueryAdapter(db_path)
    assets = adapter.load_assets()
    assert len(assets) == 1
    assert "<script>" not in assets[0].name
    assert "SANITISED" in assets[0].name


def test_integrity_check_catches_tampering() -> None:
    """If DuckDB file is modified after adapter creation, raise error."""
    db_path = _create_sample_db()
    adapter = CloudQueryAdapter(db_path)
    with db_path.open("ab") as f:
        f.write(b"tampered data")
    with pytest.raises(RuntimeError, match="integrity violation"):
        adapter.load_assets()


def test_connection_is_read_only() -> None:
    """Verify we cannot write to the DuckDB through the adapter."""
    db_path = _create_sample_db()
    conn = duckdb.connect(str(db_path), read_only=True)
    with pytest.raises(duckdb.InvalidInputException):
        conn.execute("INSERT INTO gcp_storage_buckets VALUES ('x','x','x','x','x')")
    conn.close()
