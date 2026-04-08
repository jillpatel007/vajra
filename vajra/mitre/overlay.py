"""MITRE ATT&CK + ATLAS Overlay — maps every finding to technique IDs.

Every finding in Vajra gets a MITRE ATT&CK technique ID.
SOC teams filter by technique, not by tool name.

ATT&CK Cloud matrix techniques:
    TA0001 Initial Access, TA0004 Privilege Escalation,
    TA0006 Credential Access, TA0008 Lateral Movement

ATLAS (adversarial ML):
    AML.T0020 Data Poisoning, AML.T0043 Prompt Injection
"""

from __future__ import annotations

import logging
from typing import Any

from vajra.core.models import RelationType

logger = logging.getLogger(__name__)

# Map RelationType to MITRE ATT&CK technique
_ATTACK_MAP: dict[str, dict[str, str]] = {
    RelationType.CAN_ASSUME.value: {
        "technique": "T1078.004",
        "tactic": "TA0004",
        "name": "Valid Accounts: Cloud Accounts",
    },
    RelationType.HAS_ACCESS.value: {
        "technique": "T1530",
        "tactic": "TA0009",
        "name": "Data from Cloud Storage",
    },
    RelationType.CROSS_ACCOUNT.value: {
        "technique": "T1550.001",
        "tactic": "TA0008",
        "name": "Use Alternate Authentication: Application Access Token",
    },
    RelationType.SUPPLY_CHAIN_RISK.value: {
        "technique": "T1195.002",
        "tactic": "TA0001",
        "name": "Supply Chain Compromise: Software Supply Chain",
    },
    RelationType.MCP_TOOL_ACCESS.value: {
        "technique": "AML.T0043",
        "tactic": "AML.TA0002",
        "name": "ATLAS: Prompt Injection via Tool",
    },
    RelationType.CONTAINS_SECRET.value: {
        "technique": "T1552.005",
        "tactic": "TA0006",
        "name": "Unsecured Credentials: Cloud Instance Metadata",
    },
    RelationType.TRUSTS.value: {
        "technique": "T1199",
        "tactic": "TA0001",
        "name": "Trusted Relationship",
    },
    RelationType.TRAINS_ON.value: {
        "technique": "AML.T0020",
        "tactic": "AML.TA0001",
        "name": "ATLAS: Data Poisoning",
    },
    RelationType.READS_FROM.value: {
        "technique": "T1530",
        "tactic": "TA0009",
        "name": "Data from Cloud Storage (Read)",
    },
}


def map_to_mitre(relation_type: str) -> dict[str, str]:
    """Map a relation type to its MITRE technique."""
    return _ATTACK_MAP.get(
        relation_type,
        {
            "technique": "T0000",
            "tactic": "TA0000",
            "name": "Unknown Technique",
        },
    )


def enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Add MITRE ATT&CK metadata to a finding."""
    relation = finding.get("relation", "")
    mitre = map_to_mitre(relation)
    finding["mitre_attack"] = mitre
    return finding


def get_coverage() -> dict[str, Any]:
    """Report MITRE technique coverage."""
    return {
        "techniques_mapped": len(_ATTACK_MAP),
        "attack_techniques": sum(
            1 for v in _ATTACK_MAP.values() if v["technique"].startswith("T")
        ),
        "atlas_techniques": sum(
            1 for v in _ATTACK_MAP.values() if v["technique"].startswith("AML")
        ),
    }
