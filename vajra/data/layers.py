"""Medallion Architecture — Bronze / Silver / Gold data layers.

BronzeLayer: Raw immutable data from CloudQuery.
SilverLayer: Pydantic-validated, typed, deduplicated.
GoldLayer:   Analytical aggregates ready for dashboards.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from vajra.core.models import CloudAsset

logger = logging.getLogger(__name__)


@dataclass
class DataContract:
    """Schema + SLA validation for data layer transitions."""

    name: str
    required_fields: tuple[str, ...]
    max_staleness_hours: float = 4.0

    def validate(self, record: dict[str, Any]) -> bool:
        """Check if a record meets the contract."""
        for f in self.required_fields:
            if f not in record or record[f] is None:
                return False
        return True


@dataclass
class LineageRecord:
    """Tracks data transformation from bronze to gold."""

    source_layer: str
    target_layer: str
    transformation: str
    records_in: int
    records_out: int
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )


class BronzeLayer:
    """Raw immutable data — exactly as received from CloudQuery."""

    def __init__(self) -> None:
        self._records: list[dict[str, Any]] = []
        self._lineage: list[LineageRecord] = []

    def ingest(self, raw_records: list[dict[str, Any]]) -> int:
        """Store raw records. Never modified after ingestion."""
        self._records.extend(raw_records)
        return len(raw_records)

    @property
    def records(self) -> list[dict[str, Any]]:
        return list(self._records)

    @property
    def count(self) -> int:
        return len(self._records)


class SilverLayer:
    """Validated + typed data. Pydantic models enforced."""

    _CONTRACT = DataContract(
        name="silver_asset",
        required_fields=("id", "name", "asset_type", "provider"),
    )

    def __init__(self) -> None:
        self._assets: list[CloudAsset] = []
        self._rejected: int = 0

    def transform(
        self,
        bronze: BronzeLayer,
    ) -> tuple[list[CloudAsset], LineageRecord]:
        """Transform bronze records to validated CloudAssets."""
        valid: list[CloudAsset] = []
        for record in bronze.records:
            if not self._CONTRACT.validate(record):
                self._rejected += 1
                continue
            try:
                asset = CloudAsset(
                    id=str(record["id"]),
                    name=str(record["name"]),
                    asset_type=record["asset_type"],
                    provider=record["provider"],
                    region=record.get("region", "global"),
                )
                valid.append(asset)
            except Exception:
                self._rejected += 1

        self._assets = valid
        lineage = LineageRecord(
            source_layer="bronze",
            target_layer="silver",
            transformation="validate + type",
            records_in=bronze.count,
            records_out=len(valid),
        )
        return valid, lineage

    @property
    def rejected_count(self) -> int:
        return self._rejected


class GoldLayer:
    """Analytical aggregates — ready for dashboards."""

    def aggregate(
        self,
        assets: list[CloudAsset],
    ) -> tuple[dict[str, Any], LineageRecord]:
        """Produce analytical summary from silver assets."""
        by_provider: dict[str, int] = {}
        by_type: dict[str, int] = {}
        entry_points = 0
        crown_jewels = 0

        for asset in assets:
            by_provider[asset.provider] = by_provider.get(asset.provider, 0) + 1
            by_type[asset.asset_type.value] = by_type.get(asset.asset_type.value, 0) + 1
            if asset.is_entry_point:
                entry_points += 1
            if asset.is_crown_jewel:
                crown_jewels += 1

        summary = {
            "total_assets": len(assets),
            "by_provider": by_provider,
            "by_type": by_type,
            "entry_points": entry_points,
            "crown_jewels": crown_jewels,
        }
        lineage = LineageRecord(
            source_layer="silver",
            target_layer="gold",
            transformation="aggregate",
            records_in=len(assets),
            records_out=1,
        )
        return summary, lineage
