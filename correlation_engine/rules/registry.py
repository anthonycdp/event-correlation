"""
Rule Registry

Manages loading, storing, and retrieving correlation rules.
"""

import json
from pathlib import Path
from typing import Optional

import yaml

from correlation_engine.rules.rule import CorrelationRule


class RuleRegistry:
    """
    Registry for managing correlation rules.

    Supports loading rules from YAML files, JSON files, or direct registration.
    """

    def __init__(self) -> None:
        self._rules: dict[str, CorrelationRule] = {}
        self._enabled_rules: dict[str, CorrelationRule] = {}

    def register(self, rule: CorrelationRule) -> None:
        """Register a correlation rule."""
        self._rules[rule.rule_id] = rule
        if rule.enabled:
            self._enabled_rules[rule.rule_id] = rule

    def unregister(self, rule_id: str) -> bool:
        """Unregister a rule by ID."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            self._enabled_rules.pop(rule_id, None)
            return True
        return False

    def get(self, rule_id: str) -> Optional[CorrelationRule]:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def get_all(self) -> list[CorrelationRule]:
        """Get all registered rules."""
        return list(self._rules.values())

    def get_enabled(self) -> list[CorrelationRule]:
        """Get all enabled rules."""
        return list(self._enabled_rules.values())

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule."""
        rule = self._rules.get(rule_id)
        if rule:
            rule.enabled = True
            self._enabled_rules[rule_id] = rule
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule."""
        rule = self._rules.get(rule_id)
        if rule:
            rule.enabled = False
            self._enabled_rules.pop(rule_id, None)
            return True
        return False

    def load_from_yaml(self, filepath: str | Path) -> int:
        """
        Load rules from a YAML file.

        The file can contain a single rule or a list of rules.
        Returns the number of rules loaded.
        """
        filepath = Path(filepath)
        with open(filepath) as f:
            data = yaml.safe_load(f)

        if data is None:
            return 0

        # Handle single rule or list of rules
        if isinstance(data, list):
            rules_data = data
        else:
            rules_data = [data]

        count = 0
        for rule_data in rules_data:
            try:
                rule = CorrelationRule.from_yaml_dict(rule_data)
                self.register(rule)
                count += 1
            except Exception as e:
                print(f"Error loading rule: {e}")
                continue

        return count

    def load_from_json(self, filepath: str | Path) -> int:
        """
        Load rules from a JSON file.

        The file can contain a single rule or a list of rules.
        Returns the number of rules loaded.
        """
        filepath = Path(filepath)
        with open(filepath) as f:
            data = json.load(f)

        if isinstance(data, list):
            rules_data = data
        else:
            rules_data = [data]

        count = 0
        for rule_data in rules_data:
            try:
                rule = CorrelationRule.from_yaml_dict(rule_data)
                self.register(rule)
                count += 1
            except Exception as e:
                print(f"Error loading rule: {e}")
                continue

        return count

    def load_from_directory(self, dirpath: str | Path, pattern: str = "*.yaml") -> int:
        """
        Load all rule files from a directory.

        Returns the total number of rules loaded.
        """
        dirpath = Path(dirpath)
        total = 0

        for filepath in dirpath.glob(pattern):
            if filepath.suffix in (".yaml", ".yml"):
                total += self.load_from_yaml(filepath)
            elif filepath.suffix == ".json":
                total += self.load_from_json(filepath)

        return total

    def save_to_yaml(self, filepath: str | Path, rule_ids: Optional[list[str]] = None) -> None:
        """Save rules to a YAML file."""
        filepath = Path(filepath)

        if rule_ids:
            rules = [self._rules[rid] for rid in rule_ids if rid in self._rules]
        else:
            rules = list(self._rules.values())

        data = [rule.to_yaml_dict() for rule in rules]

        with open(filepath, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._rules

    def __iter__(self):
        return iter(self._rules.values())
