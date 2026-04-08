"""Pydantic schemas for AI-generated structured output.

Structured output is the security boundary between AI and the graph.
The AI can only produce data that fits these schemas — it cannot
inject arbitrary fields, create fake findings, or modify the graph.

Why Pydantic, not freeform text:
    Freeform: "I found a critical vulnerability in..."
    → hallucination becomes a false security finding

    Structured: AttackNarrative(severity="critical", mitre_id="T1078")
    → schema validates every field, rejects hallucinated values
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Constrained severity values — AI cannot invent new ones."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackNarrative(BaseModel):
    """AI-generated explanation of an attack path."""

    model_config = ConfigDict(frozen=True)

    path_description: str = Field(
        ...,
        max_length=500,
        description="Plain-English description of the attack path",
    )
    business_impact: str = Field(
        ...,
        max_length=300,
        description="What business damage this path enables",
    )
    severity: Severity
    mitre_technique: str = Field(
        ...,
        pattern=r"^(T\d{4}(\.\d{3})?|AML\.T\d{4})$",
        description="MITRE ATT&CK or ATLAS technique ID",
    )


class PathVerification(BaseModel):
    """AI verification of whether an attack path is real."""

    model_config = ConfigDict(frozen=True)

    is_valid: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str = Field(..., max_length=500)
    false_positive_indicators: list[str] = Field(
        default_factory=list,
        max_length=5,
    )


class RemediationPlan(BaseModel):
    """AI-generated remediation recommendation."""

    model_config = ConfigDict(frozen=True)

    quick_fix: str = Field(
        ...,
        max_length=300,
        description="30-second fix (e.g., disable public access)",
    )
    proper_fix: str = Field(
        ...,
        max_length=500,
        description="Sprint-level fix (e.g., implement least privilege)",
    )
    blast_radius: list[str] = Field(
        default_factory=list,
        description="Services that may break if fix is applied",
    )
    estimated_effort: str = Field(
        ...,
        max_length=50,
        description="e.g., '2 hours', '1 sprint'",
    )


class NLQueryResult(BaseModel):
    """AI response to natural language security query."""

    model_config = ConfigDict(frozen=True)

    answer: str = Field(..., max_length=1000)
    relevant_paths: list[int] = Field(
        default_factory=list,
        description="Indices of relevant attack paths",
    )
    confidence: float = Field(..., ge=0.0, le=1.0)


class RuleDefinition(BaseModel):
    """AI-generated detection rule in Sigma format."""

    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(..., max_length=50)
    name: str = Field(..., max_length=100)
    description: str = Field(..., max_length=500)
    severity: Severity
    mitre_technique: str = Field(
        ...,
        pattern=r"^(T\d{4}(\.\d{3})?|AML\.T\d{4})$",
    )
    condition: dict[str, Any] = Field(default_factory=dict)
