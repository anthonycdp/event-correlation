"""Tests for the Correlation Engine."""

import pytest
from datetime import datetime, timedelta, timezone

from correlation_engine.engine import CorrelationEngine, CorrelationStats
from correlation_engine.models.event import EventSeverity, EventSource, EventType, SecurityEvent
from correlation_engine.models.alert import AlertCategory, AlertPriority, AlertStatus
from correlation_engine.rules.rule import (
    Condition,
    ConditionGroup,
    ConditionOperator,
    CorrelationRule,
    LogicalOperator,
    RuleType,
)
from correlation_engine.rules.registry import RuleRegistry


class TestCorrelationEngine:
    """Tests for the CorrelationEngine."""

    @pytest.fixture
    def engine(self):
        """Create a basic engine for testing."""
        return CorrelationEngine(enable_fp_reduction=False)

    @pytest.fixture
    def engine_with_rules(self):
        """Create an engine with sample rules."""
        registry = RuleRegistry()

        # Add a brute force rule
        bf_rule = CorrelationRule(
            rule_id="bf-test",
            name="SSH Brute Force",
            description="Test brute force rule",
            rule_type=RuleType.THRESHOLD,
            conditions=ConditionGroup(
                conditions=[
                    Condition(field="event_type", operator=ConditionOperator.EQUALS, value="login_failure"),
                    Condition(field="dst_port", operator=ConditionOperator.EQUALS, value=22),
                ]
            ),
            threshold=3,
            time_window_minutes=5,
            alert_title="SSH Brute Force Detected",
            alert_description="Multiple SSH failures",
            alert_category="brute_force",
            alert_severity="high",
        )
        registry.register(bf_rule)

        # Add a single-event rule
        malware_rule = CorrelationRule(
            rule_id="mal-test",
            name="Malicious IP",
            description="Test malware rule",
            rule_type=RuleType.SINGLE_EVENT,
            conditions=ConditionGroup(
                conditions=[
                    Condition(field="src_ip", operator=ConditionOperator.EQUALS, value="10.0.0.99"),
                ]
            ),
            alert_title="Malicious IP Detected",
            alert_description="Malicious IP",
            alert_category="malware",
            alert_severity="critical",
        )
        registry.register(malware_rule)

        return CorrelationEngine(rule_registry=registry, enable_fp_reduction=False)

    def test_create_engine(self, engine):
        """Test creating an engine."""
        assert engine is not None
        assert len(engine.buffer) == 0
        assert len(engine.get_alerts()) == 0

    def test_process_single_event(self, engine):
        """Test processing a single event."""
        event = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
            src_ip="192.168.1.100",
        )

        alerts = engine.process_event(event)

        assert engine.stats.events_processed == 1
        assert len(engine.buffer) == 1

    def test_process_multiple_events(self, engine):
        """Test processing multiple events."""
        events = [
            SecurityEvent(
                source=EventSource.FIREWALL,
                event_type=EventType.CONNECTION,
                src_ip=f"192.168.1.{i}",
            )
            for i in range(10)
        ]

        engine.process_events(events)

        assert engine.stats.events_processed == 10
        assert len(engine.buffer) == 10

    def test_single_event_rule_trigger(self, engine_with_rules):
        """Test that a single-event rule triggers correctly."""
        event = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
            src_ip="10.0.0.99",  # Matches malware rule
        )

        alerts = engine_with_rules.process_event(event)

        assert len(alerts) == 1
        assert alerts[0].title == "Malicious IP Detected"
        assert alerts[0].category == AlertCategory.MALWARE

    def test_threshold_rule_trigger(self, engine_with_rules):
        """Test that a threshold rule triggers after threshold is reached."""
        # Generate events below threshold
        for i in range(2):
            event = SecurityEvent(
                source=EventSource.AUTHENTICATION,
                event_type=EventType.LOGIN_FAILURE,
                dst_port=22,
                src_ip="192.168.1.100",
            )
            alerts = engine_with_rules.process_event(event)
            assert len(alerts) == 0  # Not yet triggered

        # Generate the threshold-crossing event
        event = SecurityEvent(
            source=EventSource.AUTHENTICATION,
            event_type=EventType.LOGIN_FAILURE,
            dst_port=22,
            src_ip="192.168.1.100",
        )
        alerts = engine_with_rules.process_event(event)

        assert len(alerts) == 1
        assert alerts[0].title == "SSH Brute Force Detected"
        assert alerts[0].event_count >= 3

    def test_get_alerts_filtering(self, engine_with_rules):
        """Test getting alerts with filters."""
        # Trigger an alert
        event = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
            src_ip="10.0.0.99",
        )
        engine_with_rules.process_event(event)

        # Get all alerts
        all_alerts = engine_with_rules.get_alerts()
        assert len(all_alerts) == 1

        # Get alerts by status
        new_alerts = engine_with_rules.get_alerts(status=AlertStatus.NEW)
        assert len(new_alerts) == 1

    def test_get_prioritized_alerts(self, engine_with_rules):
        """Test getting prioritized alerts."""
        # Trigger critical alert
        event = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
            src_ip="10.0.0.99",
            severity=EventSeverity.CRITICAL,
        )
        engine_with_rules.process_event(event)

        prioritized = engine_with_rules.get_prioritized_alerts()

        assert len(prioritized) == 1
        assert prioritized[0].severity == EventSeverity.CRITICAL

    def test_resolve_alert(self, engine_with_rules):
        """Test resolving an alert."""
        # Create an alert
        event = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
            src_ip="10.0.0.99",
        )
        alerts = engine_with_rules.process_event(event)
        alert_id = alerts[0].alert_id

        # Resolve it
        result = engine_with_rules.resolve_alert(alert_id, "False positive", "analyst1")
        assert result is True

        # Check status
        alert = engine_with_rules.get_alert(alert_id)
        assert alert.status == AlertStatus.RESOLVED

    def test_add_whitelist_ip(self, engine):
        """Test adding IP to whitelist."""
        # With FP reduction enabled
        engine_with_fp = CorrelationEngine(enable_fp_reduction=True)
        engine_with_fp.add_whitelist_ip("192.168.1.1", "test_whitelist")

        assert engine_with_fp.false_positive_reducer is not None
        assert len(engine_with_fp.false_positive_reducer.whitelists) > 0

    def test_engine_stats(self, engine):
        """Test getting engine statistics."""
        event = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
        )
        engine.process_event(event)

        stats = engine.get_stats()

        assert stats["events_processed"] == 1
        assert stats["buffer_size"] == 1
        assert "uptime_seconds" in stats

    def test_cleanup(self, engine):
        """Test engine cleanup."""
        # Add some events
        for i in range(10):
            event = SecurityEvent(
                source=EventSource.FIREWALL,
                event_type=EventType.CONNECTION,
            )
            engine.process_event(event)

        # Cleanup (won't remove anything recent)
        result = engine.cleanup()

        assert "events_cleaned" in result


class TestCorrelationStats:
    """Tests for CorrelationStats."""

    def test_create_stats(self):
        """Test creating stats."""
        stats = CorrelationStats()

        assert stats.events_processed == 0
        assert stats.alerts_generated == 0
        assert stats.start_time is not None

    def test_stats_to_dict(self):
        """Test converting stats to dict."""
        stats = CorrelationStats()
        stats.events_processed = 100
        stats.alerts_generated = 5

        data = stats.to_dict()

        assert data["events_processed"] == 100
        assert data["alerts_generated"] == 5


class TestEventBuffer:
    """Tests for the EventBuffer."""

    @pytest.fixture
    def buffer(self):
        from correlation_engine.processors.event_buffer import EventBuffer
        return EventBuffer(max_events=100)

    def test_add_event(self, buffer):
        """Test adding events to buffer."""
        event = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
            src_ip="192.168.1.1",
        )

        buffer.add(event)

        assert len(buffer) == 1
        assert buffer.get(event.event_id) == event

    def test_get_events_in_window(self, buffer):
        """Test getting events in time window."""
        now = datetime.now(timezone.utc)

        # Add events at different times
        event1 = SecurityEvent(
            timestamp=now - timedelta(hours=2),
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
        )
        event2 = SecurityEvent(
            timestamp=now - timedelta(minutes=30),
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
        )

        buffer.add(event1)
        buffer.add(event2)

        # Get events from last hour
        recent = buffer.get_events_in_window(now - timedelta(hours=1), now)

        assert len(recent) == 1
        assert recent[0].event_id == event2.event_id

    def test_get_events_by_ip(self, buffer):
        """Test getting events by IP."""
        event1 = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
            src_ip="192.168.1.100",
        )
        event2 = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
            src_ip="192.168.1.101",
        )
        event3 = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
            dst_ip="192.168.1.100",
        )

        buffer.add(event1)
        buffer.add(event2)
        buffer.add(event3)

        events = buffer.get_events_by_ip("192.168.1.100")

        assert len(events) == 2

    def test_buffer_max_size(self):
        """Test buffer respects max size."""
        from correlation_engine.processors.event_buffer import EventBuffer
        buffer = EventBuffer(max_events=5)

        # Add more events than max
        for i in range(10):
            event = SecurityEvent(
                source=EventSource.FIREWALL,
                event_type=EventType.CONNECTION,
            )
            buffer.add(event)

        assert len(buffer) <= 5

    def test_cleanup_old_events(self, buffer):
        """Test cleanup removes old events."""
        # Add old event
        old_event = SecurityEvent(
            timestamp=datetime.now(timezone.utc) - timedelta(days=2),
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
        )
        buffer.add(old_event)

        # Add recent event
        new_event = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
        )
        buffer.add(new_event)

        # Cleanup
        removed = buffer.cleanup(timedelta(hours=24))

        assert removed >= 1
        assert buffer.get(old_event.event_id) is None
        assert buffer.get(new_event.event_id) is not None


class TestFalsePositiveReducer:
    """Tests for FalsePositiveReducer."""

    @pytest.fixture
    def reducer(self):
        from correlation_engine.processors.false_positive_reducer import FalsePositiveReducer
        return FalsePositiveReducer()

    @pytest.fixture
    def sample_alert(self):
        from correlation_engine.models.alert import Alert
        alert = Alert(
            title="Test Alert",
            description="Test",
            src_ips=["192.168.1.100"],
            users=["admin"],
        )
        return alert

    def test_add_whitelist_entry(self, reducer):
        """Test adding whitelist entry."""
        from correlation_engine.processors.false_positive_reducer import (
            WhitelistEntry,
            WhitelistType,
        )

        entry = WhitelistEntry(
            name="test_ip",
            entry_type=WhitelistType.IP,
            value="192.168.1.1",
        )

        reducer.add_whitelist_entry(entry)

        match = reducer.is_whitelisted(ip="192.168.1.1")
        assert match == "test_ip"

    def test_cidr_whitelist(self, reducer):
        """Test CIDR notation in whitelist."""
        from correlation_engine.processors.false_positive_reducer import (
            WhitelistEntry,
            WhitelistType,
        )

        entry = WhitelistEntry(
            name="internal_network",
            entry_type=WhitelistType.IP,
            value="10.0.0.0/8",
        )
        reducer.add_whitelist_entry(entry)

        assert reducer.is_whitelisted(ip="10.0.0.1") == "internal_network"
        assert reducer.is_whitelisted(ip="10.255.255.255") == "internal_network"
        assert reducer.is_whitelisted(ip="192.168.1.1") is None

    def test_process_alert_whitelisted(self, reducer, sample_alert):
        """Test processing whitelisted alert."""
        from correlation_engine.processors.false_positive_reducer import (
            WhitelistEntry,
            WhitelistType,
        )

        # Add whitelist for the IP
        entry = WhitelistEntry(
            name="trusted_ip",
            entry_type=WhitelistType.IP,
            value="192.168.1.100",
        )
        reducer.add_whitelist_entry(entry)

        is_fp, reason, whitelist = reducer.process_alert(sample_alert)

        assert is_fp is True
        assert "whitelisted" in reason.lower()
        assert whitelist == "trusted_ip"

    def test_alert_suppression(self, reducer, sample_alert):
        """Test alert suppression for duplicates."""
        from datetime import timedelta

        # First alert should not be suppressed
        is_fp, reason, _ = reducer.process_alert(sample_alert)
        assert is_fp is False

        # Same alert within window should be suppressed
        is_fp, reason, _ = reducer.process_alert(sample_alert)
        assert is_fp is True
        assert "suppressed" in reason.lower()

    def test_baseline_anomaly_detection(self, reducer):
        """Test baseline anomaly detection."""
        # Establish baseline
        for i in range(20):
            reducer.update_baseline("user", "jsmith", "login_count", 5)

        # Normal value - should not be anomalous
        assert reducer.is_anomalous("user", "jsmith", "login_count", 6) is False

        # Anomalous value
        assert reducer.is_anomalous("user", "jsmith", "login_count", 20) is True
