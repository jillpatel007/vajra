"""Sigma Rule Loader — loads YAML detection rules + MITRE mapping.

SigmaCollection loads all rules from YAML.
VajraBackend evaluates rules against graph findings.
Adding a new rule = one YAML block. Zero Python changes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class SigmaRule:
    """A single detection rule in Sigma format."""

    id: str
    name: str
    description: str
    severity: str
    mitre_attack: str
    mitre_atlas: str
    condition: dict[str, Any]
    remediation: str


class SigmaCollection:
    """Loads and manages Sigma-format detection rules."""

    def __init__(self) -> None:
        self._rules: list[SigmaRule] = []

    def load_from_yaml(self, path: Path) -> int:
        """Load rules from a YAML file. Returns count loaded."""
        if not path.exists():
            logger.warning("rules file not found: %s", path)
            return 0

        try:
            data = yaml.safe_load(path.read_text())
        except yaml.YAMLError as e:
            logger.error("failed to parse rules: %s", e)
            return 0

        rules_data = data if isinstance(data, list) else data.get("rules", [])
        count = 0
        for rule_data in rules_data:
            rule = SigmaRule(
                id=rule_data.get("id", ""),
                name=rule_data.get("name", ""),
                description=rule_data.get("description", ""),
                severity=rule_data.get("severity", "medium"),
                mitre_attack=rule_data.get("mitre_attack", ""),
                mitre_atlas=rule_data.get("mitre_atlas", ""),
                condition=rule_data.get("condition", {}),
                remediation=rule_data.get("remediation", ""),
            )
            self._rules.append(rule)
            count += 1

        logger.info("loaded %d rules from %s", count, path)
        return count

    def load_from_dict(self, rules_data: list[dict[str, Any]]) -> int:
        """Load rules from a list of dicts (for testing)."""
        count = 0
        for rule_data in rules_data:
            rule = SigmaRule(
                id=rule_data.get("id", ""),
                name=rule_data.get("name", ""),
                description=rule_data.get("description", ""),
                severity=rule_data.get("severity", "medium"),
                mitre_attack=rule_data.get("mitre_attack", ""),
                mitre_atlas=rule_data.get("mitre_atlas", ""),
                condition=rule_data.get("condition", {}),
                remediation=rule_data.get("remediation", ""),
            )
            self._rules.append(rule)
            count += 1
        return count

    @property
    def rules(self) -> list[SigmaRule]:
        return list(self._rules)

    @property
    def count(self) -> int:
        return len(self._rules)
