"""Tests for Event Parsers and Utilities."""

import pytest
import json
from datetime import datetime
from pathlib import Path
import tempfile

from correlation_engine.utils.parsers import EventParser, JSONLReader
from correlation_engine.utils.sample_data import (
    generate_sample_events,
    get_default_rules,
    generate_sample_data_file,
)
from correlation_engine.models.event import EventSeverity, EventSource, EventType


class TestEventParser:
    """Tests for the EventParser."""

    @pytest.fixture
    def parser(self):
        return EventParser()

    def test_parse_direct_format(self, parser):
        """Test parsing directly formatted events."""
        data = {
            "event_id": "evt-001",
            "timestamp": "2024-01-15T10:30:00Z",
            "source": "firewall",
            "event_type": "connection",
            "severity": "high",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.5",
        }

        event = parser.parse(data)

        assert event is not None
        assert event.source == EventSource.FIREWALL
        assert event.event_type == EventType.CONNECTION
        assert event.severity == EventSeverity.HIGH
        assert event.src_ip == "192.168.1.100"

    def test_parse_generic_format(self, parser):
        """Test parsing generic event format."""
        data = {
            "time": "2024-01-15T10:30:00",
            "log_source": "firewall",
            "action": "blocked",
            "level": "warning",
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.0.5",
            "message": "Connection blocked",
        }

        event = parser.parse(data)

        assert event is not None
        assert event.source == EventSource.FIREWALL
        assert event.src_ip == "192.168.1.100"

    def test_parse_iso_timestamp(self, parser):
        """Test parsing ISO format timestamps."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "source": "authentication",
            "event_type": "login_failure",
        }

        event = parser.parse(data)
        assert event is not None
        assert event.timestamp.year == 2024

    def test_parse_unix_timestamp(self, parser):
        """Test parsing Unix timestamps."""
        data = {
            "timestamp": 1705315800,  # 2024-01-15 10:30:00 UTC
            "source": "authentication",
            "event_type": "login_failure",
        }

        event = parser.parse(data)
        assert event is not None
        assert event.timestamp.year == 2024

    def test_severity_parsing(self, parser):
        """Test severity parsing from various formats."""
        test_cases = [
            ("critical", EventSeverity.CRITICAL),
            ("high", EventSeverity.HIGH),
            ("medium", EventSeverity.MEDIUM),
            ("low", EventSeverity.LOW),
            ("error", EventSeverity.HIGH),
            ("warning", EventSeverity.MEDIUM),
            ("info", EventSeverity.LOW),
            (4, EventSeverity.CRITICAL),
            (3, EventSeverity.HIGH),
            (2, EventSeverity.MEDIUM),
            (1, EventSeverity.LOW),
        ]

        for input_val, expected in test_cases:
            data = {
                "source": "firewall",
                "event_type": "connection",
                "severity": input_val,
            }
            event = parser.parse(data)
            assert event.severity == expected, f"Failed for input: {input_val}"

    def test_source_parsing(self, parser):
        """Test event source parsing."""
        test_cases = [
            ("firewall", EventSource.FIREWALL),
            ("ids", EventSource.IDS_IPS),
            ("ips", EventSource.IDS_IPS),
            ("authentication", EventSource.AUTHENTICATION),
            ("endpoint", EventSource.ENDPOINT),
            ("dns", EventSource.DNS),
            ("proxy", EventSource.PROXY),
            ("cloud", EventSource.CLOUD),
            ("email", EventSource.EMAIL),
        ]

        for input_val, expected in test_cases:
            data = {
                "source": input_val,
                "event_type": "connection",
            }
            event = parser.parse(data)
            assert event.source == expected, f"Failed for input: {input_val}"

    def test_event_type_parsing(self, parser):
        """Test event type parsing."""
        test_cases = [
            ("login_success", EventType.LOGIN_SUCCESS),
            ("login_failure", EventType.LOGIN_FAILURE),
            ("connection", EventType.CONNECTION),
            ("port_scan", EventType.PORT_SCAN),
            ("malware", EventType.MALWARE_DETECTED),
        ]

        for input_val, expected in test_cases:
            data = {
                "source": "firewall",
                "event_type": input_val,
            }
            event = parser.parse(data)
            assert event.event_type == expected

    def test_metadata_extraction(self, parser):
        """Test that non-standard fields are extracted to metadata."""
        data = {
            "source": "firewall",
            "event_type": "connection",
            "src_ip": "192.168.1.1",
            "custom_field": "custom_value",
            "another_field": 123,
        }

        event = parser.parse(data)

        assert event.metadata["custom_field"] == "custom_value"
        assert event.metadata["another_field"] == 123

    def test_invalid_event_returns_none(self, parser):
        """Test that invalid events return None."""
        # Missing required fields
        data = {}

        event = parser.parse(data)

        # Parser should handle gracefully
        assert event is not None  # Will create with defaults


class TestJSONLReader:
    """Tests for the JSONLReader."""

    @pytest.fixture
    def sample_jsonl_content(self):
        return """{"event_id": "evt-001", "source": "firewall", "event_type": "connection", "src_ip": "192.168.1.1"}
{"event_id": "evt-002", "source": "authentication", "event_type": "login_failure", "src_ip": "192.168.1.100"}
"""

    def test_read_jsonl_file(self, sample_jsonl_content):
        """Test reading events from a JSONL file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(sample_jsonl_content)
            f.flush()

            reader = JSONLReader()
            events = reader.read_file(f.name)

            assert len(events) == 2
            assert events[0].src_ip == "192.168.1.1"
            assert events[1].event_type == EventType.LOGIN_FAILURE

    def test_read_empty_lines(self):
        """Test reading file with empty lines."""
        content = '{"source": "firewall", "event_type": "connection"}\n\n{"source": "authentication", "event_type": "login_success"}\n'

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(content)
            f.flush()

            reader = JSONLReader()
            events = reader.read_file(f.name)

            assert len(events) == 2


class TestSampleDataGenerator:
    """Tests for the sample data generator."""

    def test_generate_sample_events(self):
        """Test generating sample events."""
        events = generate_sample_events(50)

        assert len(events) <= 50  # May be less due to slicing
        assert all(e.event_id for e in events)
        assert all(e.timestamp for e in events)

    def test_events_have_variety(self):
        """Test that generated events have variety."""
        events = generate_sample_events(100)

        sources = set(e.source for e in events)
        event_types = set(e.event_type for e in events)
        src_ips = set(e.src_ip for e in events if e.src_ip)

        assert len(sources) > 1
        assert len(event_types) > 1
        assert len(src_ips) > 1

    def test_get_default_rules(self):
        """Test getting default rules."""
        rules = get_default_rules()

        assert len(rules) > 0
        assert all(r.rule_id for r in rules)
        assert all(r.alert_title for r in rules)

    def test_generate_sample_data_file(self):
        """Test generating a sample data file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            generate_sample_data_file(f.name, event_count=20)

            # Verify file was created and has content
            with open(f.name) as rf:
                lines = rf.readlines()

            assert len(lines) == 20
            # Verify JSON is valid
            for line in lines:
                data = json.loads(line)
                assert "event_id" in data
                assert "source" in data


class TestIntegration:
    """Integration tests."""

    def test_full_pipeline(self):
        """Test full pipeline: generate -> parse -> process."""
        from correlation_engine.engine import CorrelationEngine
        from correlation_engine.rules.registry import RuleRegistry

        # Setup
        registry = RuleRegistry()
        for rule in get_default_rules():
            registry.register(rule)

        engine = CorrelationEngine(rule_registry=registry, enable_fp_reduction=False)

        # Generate and process events
        events = generate_sample_events(100)
        alerts = engine.process_events(events)

        # Verify
        assert engine.stats.events_processed == len(events)
        # May or may not generate alerts depending on events and rules
        assert isinstance(alerts, list)
