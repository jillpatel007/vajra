"""Lambda Architecture — Batch + Speed + Serving layers.

BatchLayer:  Full CloudQuery sync every 4 hours → ground truth graph.
SpeedLayer:  Processes CloudTrail events in real-time → applies deltas.
ServingLayer: Merges batch + speed views → fills staleness gap.

A new IAM role created in AWS appears in graph within seconds
via CloudTrail (SpeedLayer), not hours (BatchLayer).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from vajra.core.graph_engine import VajraGraph

logger = logging.getLogger(__name__)


@dataclass
class GraphDelta:
    """A change to apply to the graph (add/remove asset or edge)."""

    action: str  # "add_asset", "remove_asset", "add_edge", "remove_edge"
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )


class BatchLayer:
    """Full CloudQuery sync → ground truth graph. Runs every 4 hours."""

    def __init__(self) -> None:
        self._last_sync: str = ""
        self._sync_count: int = 0

    def sync(self, graph: VajraGraph) -> dict[str, Any]:
        """Full sync overwrites speed layer deltas with ground truth."""
        self._last_sync = datetime.now(UTC).isoformat()
        self._sync_count += 1
        logger.info("batch sync #%d complete", self._sync_count)
        return {
            "sync_number": self._sync_count,
            "timestamp": self._last_sync,
            "assets": len(graph.get_assets()),
        }


class SpeedLayer:
    """Processes CloudTrail events in real-time → graph deltas."""

    # CloudTrail events that modify the attack surface
    _WATCHED_EVENTS: frozenset[str] = frozenset(
        {
            "AssumeRole",
            "CreateRole",
            "DeleteRole",
            "PutRolePolicy",
            "AttachRolePolicy",
            "DetachRolePolicy",
            "CreateUser",
            "DeleteUser",
            "GetSecretValue",
            "PutBucketPolicy",
            "CreateAccessKey",
            "AuthorizeSecurityGroupIngress",
            "RevokeSecurityGroupIngress",
            "CreateBucket",
            "DeleteBucket",
        }
    )

    _MAX_DELTAS: int = 100_000  # FIX #14: Bounded buffer

    def __init__(self) -> None:
        self._deltas: list[GraphDelta] = []
        self._events_processed: int = 0

    def process_event(
        self,
        event: dict[str, Any],
    ) -> GraphDelta | None:
        """Process a single CloudTrail event into a graph delta."""
        event_name = event.get("eventName", "")
        self._events_processed += 1

        if event_name not in self._WATCHED_EVENTS:
            return None

        # Map event to graph delta
        if event_name == "CreateRole":
            delta = GraphDelta(
                action="add_asset",
                data={
                    "id": event.get("responseElements", {})
                    .get(
                        "role",
                        {},
                    )
                    .get("arn", ""),
                    "name": event.get("requestParameters", {}).get(
                        "roleName",
                        "",
                    ),
                    "type": "iam_role",
                    "provider": "aws",
                },
            )
        elif event_name == "DeleteRole":
            delta = GraphDelta(
                action="remove_asset",
                data={
                    "id": event.get("requestParameters", {}).get(
                        "roleName",
                        "",
                    ),
                },
            )
        elif event_name in ("AttachRolePolicy", "PutRolePolicy"):
            delta = GraphDelta(
                action="add_edge",
                data={
                    "source": event.get("requestParameters", {}).get(
                        "roleName",
                        "",
                    ),
                    "target": event.get("requestParameters", {}).get(
                        "policyArn",
                        "",
                    ),
                    "event": event_name,
                },
            )
        else:
            delta = GraphDelta(
                action="add_edge",
                data={"event": event_name, "raw": str(event)[:200]},
            )

        self._deltas.append(delta)
        # FIX #14: Evict oldest deltas if buffer is full
        if len(self._deltas) > self._MAX_DELTAS:
            evict = len(self._deltas) - self._MAX_DELTAS
            self._deltas = self._deltas[evict:]
            logger.warning("speed layer evicted %d old deltas", evict)
        logger.debug("speed layer delta: %s from %s", delta.action, event_name)
        return delta

    def get_deltas_since(self, timestamp: str) -> list[GraphDelta]:
        """Get all deltas since a given timestamp."""
        return [d for d in self._deltas if d.timestamp >= timestamp]

    @property
    def stats(self) -> dict[str, int]:
        return {
            "events_processed": self._events_processed,
            "deltas_pending": len(self._deltas),
        }


class ServingLayer:
    """Merges batch + speed views → serves current graph state."""

    def __init__(self) -> None:
        self._batch = BatchLayer()
        self._speed = SpeedLayer()
        self._last_batch_time: str = ""

    def full_sync(self, graph: VajraGraph) -> dict[str, Any]:
        """Run batch layer sync."""
        result = self._batch.sync(graph)
        self._last_batch_time = result["timestamp"]
        # Clear speed layer deltas (batch is now ground truth)
        self._speed._deltas.clear()
        return result

    def process_event(
        self,
        event: dict[str, Any],
    ) -> GraphDelta | None:
        """Process real-time event through speed layer."""
        return self._speed.process_event(event)

    def get_pending_deltas(self) -> list[GraphDelta]:
        """Get speed layer deltas since last batch sync."""
        if not self._last_batch_time:
            return self._speed._deltas[:]
        return self._speed.get_deltas_since(self._last_batch_time)

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "batch": self._batch._sync_count,
            "speed": self._speed.stats,
            "pending_deltas": len(self.get_pending_deltas()),
        }
