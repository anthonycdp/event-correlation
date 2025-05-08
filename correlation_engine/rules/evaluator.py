"""
Rule Evaluator

Evaluates events against correlation rules to determine matches.
"""

import re
from typing import Any

from correlation_engine.models.event import SecurityEvent
from correlation_engine.rules.rule import (
    Condition,
    ConditionGroup,
    ConditionOperator,
    CorrelationRule,
    LogicalOperator,
    RuleType,
)


class RuleEvaluator:
    """
    Evaluates events against correlation rules.

    Handles all rule types and condition operators.
    """

    def evaluate_event(self, event: SecurityEvent, rule: CorrelationRule) -> bool:
        """
        Evaluate a single event against a rule.

        For single-event rules, checks if the event matches.
        For other rule types, this is used as part of the initial filtering.
        """
        # First check whitelist conditions
        if rule.whitelist_conditions:
            if self._evaluate_condition_group(event, rule.whitelist_conditions):
                return False  # Event is whitelisted

        # Check main conditions
        return self._evaluate_condition_group(event, rule.conditions)

    def _evaluate_condition_group(self, event: SecurityEvent, group: ConditionGroup) -> bool:
        """Evaluate a group of conditions against an event."""
        results = []

        # Evaluate all conditions in this group
        for condition in group.conditions:
            results.append(self._evaluate_condition(event, condition))

        # Evaluate nested groups
        for nested_group in group.groups:
            results.append(self._evaluate_condition_group(event, nested_group))

        if not results:
            return True  # Empty group matches everything

        # Apply logical operator
        if group.operator == LogicalOperator.AND:
            return all(results)
        else:  # OR
            return any(results)

    def _evaluate_condition(self, event: SecurityEvent, condition: Condition) -> bool:
        """Evaluate a single condition against an event."""
        # Get the field value from the event
        field_value = self._get_field_value(event, condition.field)

        # Handle existence checks
        if condition.operator == ConditionOperator.EXISTS:
            return field_value is not None
        elif condition.operator == ConditionOperator.NOT_EXISTS:
            return field_value is None

        # For other operators, we need a field value
        if field_value is None:
            return False

        # Apply the operator
        return self._apply_operator(field_value, condition.operator, condition.value)

    def _get_field_value(self, event: SecurityEvent, field: str) -> Any:
        """Get a field value from an event, supporting nested access."""
        # Handle nested field access (e.g., "raw_data.user_id")
        parts = field.split(".")
        value: Any = event

        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            elif hasattr(value, part):
                value = getattr(value, part)
            else:
                return None

            if value is None:
                return None

        return value

    def _apply_operator(
        self, field_value: Any, operator: ConditionOperator, condition_value: Any
    ) -> bool:
        """Apply a comparison operator using strategy pattern."""
        field_value = self._normalize_value(field_value)
        condition_value = self._normalize_value(condition_value)

        strategies = {
            ConditionOperator.EQUALS: self._compare_equals,
            ConditionOperator.NOT_EQUALS: self._compare_not_equals,
            ConditionOperator.IN: self._compare_in,
            ConditionOperator.NOT_IN: self._compare_not_in,
            ConditionOperator.CONTAINS: self._compare_contains,
            ConditionOperator.STARTS_WITH: self._compare_starts_with,
            ConditionOperator.ENDS_WITH: self._compare_ends_with,
            ConditionOperator.GREATER_THAN: self._compare_greater_than,
            ConditionOperator.LESS_THAN: self._compare_less_than,
            ConditionOperator.REGEX: self._compare_regex,
        }

        strategy = strategies.get(operator)
        if strategy is None:
            return False

        try:
            return strategy(field_value, condition_value)
        except (TypeError, ValueError):
            return False

    def _normalize_value(self, value: Any) -> Any:
        """Convert enum values to their string representation."""
        return value.value if hasattr(value, "value") else value

    def _compare_equals(self, field: Any, condition: Any) -> bool:
        return field == condition

    def _compare_not_equals(self, field: Any, condition: Any) -> bool:
        return field != condition

    def _compare_in(self, field: Any, condition: Any) -> bool:
        return field in condition if isinstance(condition, list) else False

    def _compare_not_in(self, field: Any, condition: Any) -> bool:
        return field not in condition if isinstance(condition, list) else True

    def _compare_contains(self, field: Any, condition: Any) -> bool:
        if isinstance(field, str) and isinstance(condition, str):
            return condition in field
        if isinstance(field, list):
            return condition in field
        return False

    def _compare_starts_with(self, field: Any, condition: Any) -> bool:
        return field.startswith(condition) if isinstance(field, str) and isinstance(condition, str) else False

    def _compare_ends_with(self, field: Any, condition: Any) -> bool:
        return field.endswith(condition) if isinstance(field, str) and isinstance(condition, str) else False

    def _compare_greater_than(self, field: Any, condition: Any) -> bool:
        return field > condition

    def _compare_less_than(self, field: Any, condition: Any) -> bool:
        return field < condition

    def _compare_regex(self, field: Any, condition: Any) -> bool:
        return bool(re.search(condition, field)) if isinstance(field, str) and isinstance(condition, str) else False

    def event_matches_rule_type(self, event: SecurityEvent, rule: CorrelationRule) -> bool:
        """
        Check if an event is relevant for a specific rule type.

        This is used for initial filtering before full evaluation.
        """
        if rule.rule_type == RuleType.SINGLE_EVENT:
            return self.evaluate_event(event, rule)
        else:
            # For other rule types, check if the event matches any condition
            return self._event_matches_any_condition(event, rule)

    def _event_matches_any_condition(self, event: SecurityEvent, rule: CorrelationRule) -> bool:
        """Check if event matches any condition in the rule (for initial filtering)."""
        # Check main conditions
        if self._group_has_matching_field(event, rule.conditions):
            return True

        # Check sequence conditions
        if rule.sequence:
            for group in rule.sequence:
                if self._group_has_matching_field(event, group):
                    return True

        return False

    def _group_has_matching_field(self, event: SecurityEvent, group: ConditionGroup) -> bool:
        """Check if any condition in a group could match the event."""
        for condition in group.conditions:
            field_value = self._get_field_value(event, condition.field)
            if field_value is not None:
                return True

        for nested_group in group.groups:
            if self._group_has_matching_field(event, nested_group):
                return True

        return False
