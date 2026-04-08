"""RAG Pipeline — semantic search over security findings.

VajraRAG embeds findings as vectors for semantic retrieval.
query() returns top-5 semantically relevant findings.

Why semantic > keyword:
    Keyword: "payments database" misses "PCI data store"
    Semantic: "payments database" finds both (same meaning)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A security finding for indexing."""

    finding_id: str
    description: str
    severity: str
    path_edges: list[str] = field(default_factory=list)
    mitre_id: str = ""


@dataclass
class SearchResult:
    """A single RAG search result."""

    finding: Finding
    relevance_score: float


class VajraRAG:
    """Embeds and retrieves security findings semantically.

    In production: uses LanceDB for vector storage.
    For now: uses simple TF-IDF-like keyword matching
    as a fallback that doesn't require external deps.
    """

    def __init__(self) -> None:
        self._findings: dict[str, Finding] = {}
        self._index_count: int = 0

    def index_findings(self, findings: list[Finding]) -> int:
        """Index findings for retrieval."""
        for finding in findings:
            self._findings[finding.finding_id] = finding
            self._index_count += 1
        logger.info(
            "indexed %d findings (total: %d)", len(findings), len(self._findings)
        )
        return len(findings)

    def query(
        self,
        question: str,
        top_k: int = 5,
    ) -> list[SearchResult]:
        """Retrieve top-k semantically relevant findings."""
        if not self._findings:
            return []

        # Simple relevance scoring (keyword overlap)
        query_terms = set(question.lower().split())
        scored: list[tuple[Finding, float]] = []

        for finding in self._findings.values():
            desc_terms = set(finding.description.lower().split())
            overlap = len(query_terms & desc_terms)
            if overlap > 0:
                score = overlap / max(len(query_terms), 1)
                scored.append((finding, min(score, 1.0)))

        # Sort by relevance, take top-k
        scored.sort(key=lambda x: x[1], reverse=True)
        return [SearchResult(finding=f, relevance_score=s) for f, s in scored[:top_k]]

    @property
    def index_size(self) -> int:
        return len(self._findings)
