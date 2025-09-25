"""Tests for Security Event Models."""

import pytest
from datetime import datetime

from correlation_engine.models.event import (
    EventSeverity,
    EventSource,
    EventType,
    SecurityEvent,
)
from correlation_engine.models.alert import (
    Alert,
    AlertCategory,
    AlertPriority,
    AlertStatus,
)


class TestSecurityEvent:
    """Tests for SecurityEvent model."""

    def test_create_event_with_defaults(self):
        """Test creating an event with default values."""
        event = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
        )

        assert event.event_id is not None
        assert event.timestamp is not None
        assert event.severity == EventSeverity.LOW
        assert event.tags == []
        assert event.metadata == {}

    def test_create_event_with_all_fields(self):
        """Test creating an event with all fields."""
        timestamp = datetime(2024, 1, 15, 10, 30, 0)
        event = SecurityEvent(
            event_id="evt-123",
            timestamp=timestamp,
            source=EventSource.AUTHENTICATION,
            event_type=EventType.LOGIN_FAILURE,
            severity=EventSeverity.HIGH,
            src_ip="192.168.1.100",
            src_port=54321,
            src_user="admin",
            dst_ip="10.0.0.5",
            dst_port=22,
            dst_host="server-01",
            description="Failed login attempt",
            tags=["brute_force"],
        )

        assert event.event_id == "evt-123"
        assert event.timestamp == timestamp
        assert event.source == EventSource.AUTHENTICATION
        assert event.event_type == EventType.LOGIN_FAILURE
        assert event.severity == EventSeverity.HIGH
        assert event.src_ip == "192.168.1.100"
        assert event.src_port == 54321
        assert event.src_user == "admin"
        assert event.dst_ip == "10.0.0.5"
        assert event.dst_port == 22
        assert event.description == "Failed login attempt"
        assert "brute_force" in event.tags

    def test_event_hash_and_equality(self):
        """Test event hashing and equality."""
        event1 = SecurityEvent(
            event_id="evt-001",
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
        )
        event2 = SecurityEvent(
            event_id="evt-001",
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
        )
        event3 = SecurityEvent(
            event_id="evt-002",
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
        )

        assert event1 == event2
        assert event1 != event3
        assert hash(event1) == hash(event2)

    def test_event_key_fields(self):
        """Test getting key fields for correlation."""
        event = SecurityEvent(
            source=EventSource.AUTHENTICATION,
            event_type=EventType.LOGIN_FAILURE,
            src_ip="192.168.1.100",
            src_user="admin",
            dst_ip="10.0.0.5",
        )

        keys = event.key_fields
        assert keys["src_ip"] == "192.168.1.100"
        assert keys["src_user"] == "admin"
        assert keys["dst_ip"] == "10.0.0.5"
        assert keys["event_type"] == EventType.LOGIN_FAILURE

    def test_event_matches_criteria(self):
        """Test criteria matching."""
        event = SecurityEvent(
            source=EventSource.AUTHENTICATION,
            event_type=EventType.LOGIN_FAILURE,
            src_ip="192.168.1.100",
            severity=EventSeverity.HIGH,
        )

        assert event.matches_criteria(src_ip="192.168.1.100")
        assert event.matches_criteria(event_type=EventType.LOGIN_FAILURE)
        assert event.matches_criteria(severity=EventSeverity.HIGH)
        assert not event.matches_criteria(src_ip="10.0.0.1")
        assert event.matches_criteria(src_ip=["192.168.1.100", "10.0.0.1"])

    def test_severity_numeric_value(self):
        """Test severity numeric values for comparison."""
        assert EventSeverity.LOW.numeric_value == 1
        assert EventSeverity.MEDIUM.numeric_value == 2
        assert EventSeverity.HIGH.numeric_value == 3
        assert EventSeverity.CRITICAL.numeric_value == 4


class TestAlert:
    """Tests for Alert model."""

    def test_create_alert_with_defaults(self):
        """Test creating an alert with default values."""
        alert = Alert(
            title="Test Alert",
            description="Test description",
        )

        assert alert.alert_id is not None
        assert alert.created_at is not None
        assert alert.status == AlertStatus.NEW
        assert alert.priority == AlertPriority.P4_LOW
        assert alert.events == []

    def test_add_event_to_alert(self):
        """Test adding events to an alert."""
        alert = Alert(
            title="Test Alert",
            description="Test",
        )
        event1 = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
            src_ip="192.168.1.100",
            timestamp=datetime(2024, 1, 15, 10, 0, 0),
        )
        event2 = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
            src_ip="192.168.1.101",
            timestamp=datetime(2024, 1, 15, 10, 5, 0),
        )

        alert.add_event(event1)
        alert.add_event(event2)

        assert alert.event_count == 2
        assert len(alert.src_ips) == 2
        assert alert.first_event_time == datetime(2024, 1, 15, 10, 0, 0)
        assert alert.last_event_time == datetime(2024, 1, 15, 10, 5, 0)

    def test_dont_add_duplicate_events(self):
        """Test that duplicate events are not added."""
        alert = Alert(title="Test", description="Test")
        event = SecurityEvent(
            event_id="evt-001",
            source=EventSource.FIREWALL,
            event_type=EventType.CONNECTION,
        )

        alert.add_event(event)
        alert.add_event(event)

        assert alert.event_count == 1

    def test_calculate_priority(self):
        """Test priority calculation."""
        alert = Alert(
            title="Critical Alert",
            description="Test",
            category=AlertCategory.MALWARE,
            severity=EventSeverity.CRITICAL,
            correlation_score=0.9,
        )

        # Add events to boost count
        for i in range(50):
            event = SecurityEvent(
                source=EventSource.FIREWALL,
                event_type=EventType.CONNECTION,
                src_ip=f"192.168.1.{i}",
            )
            alert.add_event(event)

        priority = alert.calculate_priority()
        assert priority in [AlertPriority.P1_CRITICAL, AlertPriority.P2_HIGH]

    def test_mark_false_positive(self):
        """Test marking alert as false positive."""
        alert = Alert(
            title="Test Alert",
            description="Test",
        )

        alert.mark_false_positive("Whitelisted IP", "whitelist_001")

        assert alert.is_false_positive is True
        assert alert.status == AlertStatus.FALSE_POSITIVE
        assert alert.false_positive_reason == "Whitelisted IP"
        assert alert.whitelist_match == "whitelist_001"

    def test_add_note(self):
        """Test adding notes to alert."""
        alert = Alert(title="Test", description="Test")

        alert.add_note("Investigating", "analyst1")

        assert len(alert.notes) == 1
        assert alert.notes[0]["note"] == "Investigating"
        assert alert.notes[0]["author"] == "analyst1"

    def test_alert_to_dict(self):
        """Test converting alert to dictionary."""
        alert = Alert(
            title="Test Alert",
            description="Test description",
            category=AlertCategory.BRUTE_FORCE,
            severity=EventSeverity.HIGH,
            event_count=10,
        )

        data = alert.to_dict()

        assert data["title"] == "Test Alert"
        assert data["category"] == "brute_force"
        assert data["severity"] == "high"
        assert data["event_count"] == 10

    def test_priority_numeric_value(self):
        """Test priority numeric values."""
        assert AlertPriority.P1_CRITICAL.numeric_value == 1
        assert AlertPriority.P2_HIGH.numeric_value == 2
        assert AlertPriority.P3_MEDIUM.numeric_value == 3
        assert AlertPriority.P4_LOW.numeric_value == 4
        assert AlertPriority.P5_INFORMATIONAL.numeric_value == 5
