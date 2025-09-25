"""Pytest configuration for the correlation engine tests."""

import pytest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def sample_events():
    """Generate sample events for testing."""
    from correlation_engine.models.event import SecurityEvent, EventSource, EventType
    from datetime import datetime, timedelta

    events = []
    base_time = datetime.utcnow()

    for i in range(10):
        event = SecurityEvent(
            timestamp=base_time + timedelta(seconds=i),
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
            src_ip=f"192.168.1.{i}",
        )
        events.append(event)

    return events


@pytest.fixture
def sample_rule():
    """Create a sample rule for testing."""
    from correlation_engine.rules.rule import (
        CorrelationRule,
        Condition,
        ConditionGroup,
        ConditionOperator,
        RuleType,
    )

    return CorrelationRule(
        rule_id="sample-001",
        name="Sample Rule",
        description="A sample rule for testing",
        rule_type=RuleType.SINGLE_EVENT,
        conditions=ConditionGroup(
            conditions=[
                Condition(
                    field="event_type",
                    operator=ConditionOperator.EQUALS,
                    value="login_failure",
                )
            ]
        ),
        alert_title="Sample Alert",
        alert_description="Sample alert triggered",
        alert_category="other",
        alert_severity="medium",
    )


@pytest.fixture
def engine_with_sample_data(sample_rule):
    """Create an engine with sample data."""
    from correlation_engine.engine import CorrelationEngine
    from correlation_engine.rules.registry import RuleRegistry

    registry = RuleRegistry()
    registry.register(sample_rule)

    engine = CorrelationEngine(rule_registry=registry, enable_fp_reduction=False)
    return engine
