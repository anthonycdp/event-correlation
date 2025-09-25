"""Tests for Correlation Rules."""

import pytest

from correlation_engine.models.event import EventSeverity, EventSource, EventType, SecurityEvent
from correlation_engine.rules.rule import (
    Condition,
    ConditionGroup,
    ConditionOperator,
    CorrelationRule,
    LogicalOperator,
    RuleType,
)
from correlation_engine.rules.registry import RuleRegistry
from correlation_engine.rules.evaluator import RuleEvaluator


class TestConditions:
    """Tests for rule conditions."""

    def test_create_simple_condition(self):
        """Test creating a simple condition."""
        condition = Condition(
            field="src_ip",
            operator=ConditionOperator.EQUALS,
            value="192.168.1.1",
        )

        assert condition.field == "src_ip"
        assert condition.operator == ConditionOperator.EQUALS
        assert condition.value == "192.168.1.1"

    def test_condition_group(self):
        """Test creating a condition group."""
        group = ConditionGroup(
            operator=LogicalOperator.AND,
            conditions=[
                Condition(field="event_type", operator=ConditionOperator.EQUALS, value="login_failure"),
                Condition(field="dst_port", operator=ConditionOperator.EQUALS, value=22),
            ],
        )

        assert group.operator == LogicalOperator.AND
        assert len(group.conditions) == 2

    def test_nested_condition_groups(self):
        """Test nested condition groups."""
        inner_group = ConditionGroup(
            operator=LogicalOperator.OR,
            conditions=[
                Condition(field="src_ip", operator=ConditionOperator.EQUALS, value="10.0.0.1"),
                Condition(field="src_ip", operator=ConditionOperator.EQUALS, value="10.0.0.2"),
            ],
        )
        outer_group = ConditionGroup(
            operator=LogicalOperator.AND,
            conditions=[
                Condition(field="event_type", operator=ConditionOperator.EQUALS, value="connection"),
            ],
            groups=[inner_group],
        )

        assert len(outer_group.conditions) == 1
        assert len(outer_group.groups) == 1


class TestCorrelationRule:
    """Tests for CorrelationRule model."""

    def test_create_single_event_rule(self):
        """Test creating a single-event rule."""
        rule = CorrelationRule(
            rule_id="test-001",
            name="Test Rule",
            description="Test description",
            rule_type=RuleType.SINGLE_EVENT,
            conditions=ConditionGroup(
                conditions=[
                    Condition(field="event_type", operator=ConditionOperator.EQUALS, value="login_failure"),
                ]
            ),
            alert_title="Test Alert",
            alert_description="Test alert description",
        )

        assert rule.rule_id == "test-001"
        assert rule.rule_type == RuleType.SINGLE_EVENT
        assert rule.enabled is True
        assert rule.threshold is None

    def test_create_threshold_rule(self):
        """Test creating a threshold rule."""
        rule = CorrelationRule(
            rule_id="threshold-001",
            name="Threshold Rule",
            description="Test threshold rule",
            rule_type=RuleType.THRESHOLD,
            conditions=ConditionGroup(
                conditions=[
                    Condition(field="event_type", operator=ConditionOperator.EQUALS, value="login_failure"),
                ]
            ),
            threshold=5,
            time_window_minutes=10,
            alert_title="Threshold Alert",
            alert_description="Threshold exceeded",
        )

        assert rule.threshold == 5
        assert rule.time_window_minutes == 10
        assert rule.time_window.total_seconds() == 600

    def test_create_sequence_rule(self):
        """Test creating a sequence rule."""
        rule = CorrelationRule(
            rule_id="seq-001",
            name="Sequence Rule",
            description="Test sequence rule",
            rule_type=RuleType.SEQUENCE,
            sequence=[
                ConditionGroup(
                    conditions=[
                        Condition(field="event_type", operator=ConditionOperator.EQUALS, value="login_failure"),
                    ]
                ),
                ConditionGroup(
                    conditions=[
                        Condition(field="event_type", operator=ConditionOperator.EQUALS, value="login_success"),
                    ]
                ),
            ],
            sequence_timeout_minutes=30,
            alert_title="Sequence Alert",
            alert_description="Sequence detected",
        )

        assert rule.rule_type == RuleType.SEQUENCE
        assert len(rule.sequence) == 2
        assert rule.sequence_timeout_minutes == 30

    def test_rule_to_yaml_dict(self):
        """Test converting rule to YAML dictionary."""
        rule = CorrelationRule(
            rule_id="yaml-001",
            name="YAML Rule",
            description="Test YAML conversion",
            alert_title="Test",
            alert_description="Test",
            mitre_tactics=["Initial Access"],
        )

        data = rule.to_yaml_dict()

        assert data["rule_id"] == "yaml-001"
        assert "alert" in data
        assert data["alert"]["title"] == "Test"
        assert "Initial Access" in data["alert"]["mitre_tactics"]

    def test_rule_from_yaml_dict(self):
        """Test creating rule from YAML dictionary."""
        data = {
            "rule_id": "from-yaml-001",
            "name": "From YAML Rule",
            "description": "Test creating from YAML",
            "rule_type": "threshold",
            "threshold": 10,
            "conditions": {
                "conditions": [
                    {"field": "event_type", "operator": "equals", "value": "connection"}
                ]
            },
            "alert": {
                "title": "YAML Alert",
                "description": "From YAML",
                "severity": "high",
            },
        }

        rule = CorrelationRule.from_yaml_dict(data)

        assert rule.rule_id == "from-yaml-001"
        assert rule.rule_type == RuleType.THRESHOLD
        assert rule.threshold == 10
        assert rule.alert_title == "YAML Alert"
        assert rule.alert_severity == "high"


class TestRuleEvaluator:
    """Tests for the rule evaluator."""

    @pytest.fixture
    def evaluator(self):
        return RuleEvaluator()

    @pytest.fixture
    def sample_event(self):
        return SecurityEvent(
            source=EventSource.AUTHENTICATION,
            event_type=EventType.LOGIN_FAILURE,
            severity=EventSeverity.HIGH,
            src_ip="192.168.1.100",
            src_user="admin",
            dst_port=22,
        )

    def test_evaluate_equals_condition(self, evaluator, sample_event):
        """Test equals operator."""
        condition = Condition(
            field="src_ip",
            operator=ConditionOperator.EQUALS,
            value="192.168.1.100",
        )
        assert evaluator._evaluate_condition(sample_event, condition) is True

        condition = Condition(
            field="src_ip",
            operator=ConditionOperator.EQUALS,
            value="10.0.0.1",
        )
        assert evaluator._evaluate_condition(sample_event, condition) is False

    def test_evaluate_in_condition(self, evaluator, sample_event):
        """Test in operator."""
        condition = Condition(
            field="src_ip",
            operator=ConditionOperator.IN,
            value=["192.168.1.100", "192.168.1.101", "192.168.1.102"],
        )
        assert evaluator._evaluate_condition(sample_event, condition) is True

    def test_evaluate_regex_condition(self, evaluator, sample_event):
        """Test regex operator."""
        condition = Condition(
            field="src_ip",
            operator=ConditionOperator.REGEX,
            value=r"192\.168\.1\.\d+",
        )
        assert evaluator._evaluate_condition(sample_event, condition) is True

    def test_evaluate_and_group(self, evaluator, sample_event):
        """Test AND condition group."""
        group = ConditionGroup(
            operator=LogicalOperator.AND,
            conditions=[
                Condition(field="event_type", operator=ConditionOperator.EQUALS, value="login_failure"),
                Condition(field="dst_port", operator=ConditionOperator.EQUALS, value=22),
            ],
        )
        assert evaluator._evaluate_condition_group(sample_event, group) is True

        # Add a failing condition
        group.conditions.append(
            Condition(field="src_ip", operator=ConditionOperator.EQUALS, value="10.0.0.1")
        )
        assert evaluator._evaluate_condition_group(sample_event, group) is False

    def test_evaluate_or_group(self, evaluator, sample_event):
        """Test OR condition group."""
        group = ConditionGroup(
            operator=LogicalOperator.OR,
            conditions=[
                Condition(field="src_ip", operator=ConditionOperator.EQUALS, value="10.0.0.1"),
                Condition(field="src_ip", operator=ConditionOperator.EQUALS, value="192.168.1.100"),
            ],
        )
        assert evaluator._evaluate_condition_group(sample_event, group) is True

    def test_evaluate_event_against_rule(self, evaluator, sample_event):
        """Test evaluating an event against a full rule."""
        rule = CorrelationRule(
            rule_id="test-rule",
            name="Test",
            description="Test",
            conditions=ConditionGroup(
                conditions=[
                    Condition(field="event_type", operator=ConditionOperator.EQUALS, value="login_failure"),
                    Condition(field="dst_port", operator=ConditionOperator.EQUALS, value=22),
                ]
            ),
            alert_title="Test",
            alert_description="Test",
        )

        assert evaluator.evaluate_event(sample_event, rule) is True

    def test_whitelist_condition(self, evaluator, sample_event):
        """Test whitelist conditions prevent matching."""
        rule = CorrelationRule(
            rule_id="whitelist-test",
            name="Test",
            description="Test",
            conditions=ConditionGroup(
                conditions=[
                    Condition(field="event_type", operator=ConditionOperator.EQUALS, value="login_failure"),
                ]
            ),
            whitelist_conditions=ConditionGroup(
                conditions=[
                    Condition(field="src_ip", operator=ConditionOperator.EQUALS, value="192.168.1.100"),
                ]
            ),
            alert_title="Test",
            alert_description="Test",
        )

        # Event should NOT match because it's whitelisted
        assert evaluator.evaluate_event(sample_event, rule) is False


class TestRuleRegistry:
    """Tests for the rule registry."""

    def test_register_rule(self):
        """Test registering a rule."""
        registry = RuleRegistry()
        rule = CorrelationRule(
            rule_id="reg-001",
            name="Registry Test",
            description="Test",
            alert_title="Test",
            alert_description="Test",
        )

        registry.register(rule)

        assert len(registry) == 1
        assert "reg-001" in registry

    def test_get_enabled_rules(self):
        """Test getting enabled rules."""
        registry = RuleRegistry()

        enabled_rule = CorrelationRule(
            rule_id="enabled-001",
            name="Enabled Rule",
            description="Test",
            enabled=True,
            alert_title="Test",
            alert_description="Test",
        )
        disabled_rule = CorrelationRule(
            rule_id="disabled-001",
            name="Disabled Rule",
            description="Test",
            enabled=False,
            alert_title="Test",
            alert_description="Test",
        )

        registry.register(enabled_rule)
        registry.register(disabled_rule)

        enabled = registry.get_enabled()
        assert len(enabled) == 1
        assert enabled[0].rule_id == "enabled-001"

    def test_enable_disable_rule(self):
        """Test enabling and disabling rules."""
        registry = RuleRegistry()
        rule = CorrelationRule(
            rule_id="toggle-001",
            name="Toggle Rule",
            description="Test",
            alert_title="Test",
            alert_description="Test",
        )

        registry.register(rule)
        assert len(registry.get_enabled()) == 1

        registry.disable_rule("toggle-001")
        assert len(registry.get_enabled()) == 0

        registry.enable_rule("toggle-001")
        assert len(registry.get_enabled()) == 1

    def test_unregister_rule(self):
        """Test unregistering a rule."""
        registry = RuleRegistry()
        rule = CorrelationRule(
            rule_id="unreg-001",
            name="Unregister Test",
            description="Test",
            alert_title="Test",
            alert_description="Test",
        )

        registry.register(rule)
        assert len(registry) == 1

        result = registry.unregister("unreg-001")
        assert result is True
        assert len(registry) == 0
