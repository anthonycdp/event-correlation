"""
Event Parsers

Utilities for parsing events from various formats and sources.
"""

import json
from datetime import datetime, timezone
from typing import Any, Optional
import logging

from correlation_engine.models.event import (
    EventSeverity,
    EventSource,
    EventType,
    SecurityEvent,
)

logger = logging.getLogger(__name__)


class EventParser:
    """
    Parser for converting various event formats to SecurityEvent objects.

    Supports:
    - Direct SecurityEvent dicts
    - Common SIEM formats
    - Firewall logs
    - Authentication logs
    """

    # Mapping for common severity strings to our enum
    SEVERITY_MAP = {
        "low": EventSeverity.LOW,
        "medium": EventSeverity.MEDIUM,
        "high": EventSeverity.HIGH,
        "critical": EventSeverity.CRITICAL,
        "info": EventSeverity.LOW,
        "warning": EventSeverity.MEDIUM,
        "error": EventSeverity.HIGH,
        "fatal": EventSeverity.CRITICAL,
        "1": EventSeverity.LOW,
        "2": EventSeverity.MEDIUM,
        "3": EventSeverity.HIGH,
        "4": EventSeverity.CRITICAL,
    }

    # Mapping for event types
    EVENT_TYPE_MAP = {
        "login": EventType.LOGIN_SUCCESS,
        "login_success": EventType.LOGIN_SUCCESS,
        "login_failure": EventType.LOGIN_FAILURE,
        "login_failed": EventType.LOGIN_FAILURE,
        "logout": EventType.LOGOUT,
        "connection": EventType.CONNECTION,
        "connection_denied": EventType.CONNECTION_DENIED,
        "blocked": EventType.CONNECTION_DENIED,
        "denied": EventType.CONNECTION_DENIED,
        "port_scan": EventType.PORT_SCAN,
        "malware": EventType.MALWARE_DETECTED,
        "intrusion": EventType.INTRUSION_DETECTED,
        "dns_query": EventType.DNS_QUERY,
        "file_access": EventType.FILE_ACCESS,
        "file_modify": EventType.FILE_MODIFICATION,
        "process": EventType.PROCESS_STARTED,
    }

    def parse(self, data: dict[str, Any]) -> Optional[SecurityEvent]:
        """
        Parse a dictionary into a SecurityEvent.

        Attempts to handle various common field names and formats.
        """
        try:
            # Check if it's already in our format
            if "event_type" in data and isinstance(data["event_type"], str):
                if data["event_type"] in [e.value for e in EventType]:
                    return self._parse_direct(data)

            # Try to detect format
            if "source" in data:
                return self._parse_generic(data)
            else:
                return self._parse_generic(data)

        except Exception as e:
            logger.error(f"Error parsing event: {e}")
            return None

    def _parse_direct(self, data: dict[str, Any]) -> SecurityEvent:
        """Parse event that's already in SecurityEvent format."""
        # Parse timestamp
        timestamp = self._parse_timestamp(data.get("timestamp"))

        # Parse enums
        source = self._parse_source(data.get("source", "custom"))
        event_type = self._parse_event_type(data.get("event_type", "other"))
        severity = self._parse_severity(data.get("severity", "low"))

        # Build kwargs, excluding None values that have defaults
        kwargs: dict[str, Any] = {
            "timestamp": timestamp,
            "source": source,
            "event_type": event_type,
            "severity": severity,
        }

        # Optional fields - only include if present
        optional_fields = [
            "event_id", "src_ip", "src_port", "src_host", "src_user",
            "dst_ip", "dst_port", "dst_host", "dst_user",
            "description", "raw_data",
        ]
        for field in optional_fields:
            if field in data and data[field] is not None:
                kwargs[field] = data[field]

        if "tags" in data:
            kwargs["tags"] = data["tags"]

        # Extract metadata from non-standard fields if not provided
        if "metadata" in data:
            kwargs["metadata"] = data["metadata"]
        else:
            kwargs["metadata"] = self._extract_metadata(data)

        return SecurityEvent(**kwargs)

    def _parse_generic(self, data: dict[str, Any]) -> SecurityEvent:
        """Parse generic event format with field mapping."""
        timestamp = self._parse_timestamp(
            data.get("timestamp") or data.get("time") or data.get("@timestamp") or data.get("date")
        )

        source = self._parse_source(
            data.get("source") or data.get("log_source") or data.get("sourcetype") or "custom"
        )

        event_type = self._parse_event_type(
            data.get("event_type")
            or data.get("type")
            or data.get("action")
            or data.get("event")
            or "other"
        )

        severity = self._parse_severity(
            data.get("severity")
            or data.get("level")
            or data.get("priority")
            or "low"
        )

        return SecurityEvent(
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            severity=severity,
            src_ip=data.get("src_ip") or data.get("source_ip") or data.get("src") or data.get("ip"),
            src_port=data.get("src_port") or data.get("source_port"),
            src_host=data.get("src_host") or data.get("source_host") or data.get("hostname"),
            src_user=data.get("src_user") or data.get("user") or data.get("username") or data.get("src_user"),
            dst_ip=data.get("dst_ip") or data.get("dest_ip") or data.get("destination_ip"),
            dst_port=data.get("dst_port") or data.get("dest_port") or data.get("destination_port"),
            dst_host=data.get("dst_host") or data.get("destination_host"),
            dst_user=data.get("dst_user") or data.get("destination_user"),
            description=data.get("description") or data.get("message") or data.get("msg"),
            raw_data=data,
            tags=data.get("tags", []),
            metadata=self._extract_metadata(data),
        )

    def _parse_timestamp(self, value: Any) -> datetime:
        """Parse timestamp from various formats."""
        if value is None:
            return datetime.now(timezone.utc)

        if isinstance(value, datetime):
            return value

        if isinstance(value, (int, float)):
            # Assume Unix timestamp
            if value > 1e12:  # Milliseconds
                value = value / 1000
            return datetime.fromtimestamp(value, tz=timezone.utc)

        if isinstance(value, str):
            # Try ISO format
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass

            # Try common formats
            for fmt in [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%d/%b/%Y:%H:%M:%S",
                "%b %d %H:%M:%S",
            ]:
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue

        return datetime.now(timezone.utc)

    def _parse_source(self, value: Any) -> EventSource:
        """Parse event source."""
        if isinstance(value, EventSource):
            return value

        if isinstance(value, str):
            value_lower = value.lower().replace("-", "_").replace(" ", "_")

            source_map = {
                "firewall": EventSource.FIREWALL,
                "ids": EventSource.IDS_IPS,
                "ips": EventSource.IDS_IPS,
                "ids_ips": EventSource.IDS_IPS,
                "auth": EventSource.AUTHENTICATION,
                "authentication": EventSource.AUTHENTICATION,
                "endpoint": EventSource.ENDPOINT,
                "edr": EventSource.ENDPOINT,
                "network": EventSource.NETWORK_FLOW,
                "network_flow": EventSource.NETWORK_FLOW,
                "netflow": EventSource.NETWORK_FLOW,
                "dns": EventSource.DNS,
                "proxy": EventSource.PROXY,
                "web": EventSource.PROXY,
                "siem": EventSource.SIEM,
                "cloud": EventSource.CLOUD,
                "aws": EventSource.CLOUD,
                "azure": EventSource.CLOUD,
                "gcp": EventSource.CLOUD,
                "email": EventSource.EMAIL,
                "mail": EventSource.EMAIL,
            }

            return source_map.get(value_lower, EventSource.CUSTOM)

        return EventSource.CUSTOM

    def _parse_event_type(self, value: Any) -> EventType:
        """Parse event type."""
        if isinstance(value, EventType):
            return value

        if isinstance(value, str):
            value_lower = value.lower().replace("-", "_").replace(" ", "_")
            return self.EVENT_TYPE_MAP.get(value_lower, EventType.OTHER)

        return EventType.OTHER

    def _parse_severity(self, value: Any) -> EventSeverity:
        """Parse severity level."""
        if isinstance(value, EventSeverity):
            return value

        if isinstance(value, str):
            return self.SEVERITY_MAP.get(value.lower(), EventSeverity.LOW)

        if isinstance(value, int):
            if value >= 4:
                return EventSeverity.CRITICAL
            elif value >= 3:
                return EventSeverity.HIGH
            elif value >= 2:
                return EventSeverity.MEDIUM
            else:
                return EventSeverity.LOW

        return EventSeverity.LOW

    def _extract_metadata(self, data: dict[str, Any]) -> dict[str, Any]:
        """Extract non-standard fields as metadata."""
        standard_fields = {
            "event_id", "timestamp", "source", "event_type", "severity",
            "src_ip", "src_port", "src_host", "src_user",
            "dst_ip", "dst_port", "dst_host", "dst_user",
            "description", "raw_data", "tags", "metadata",
            "time", "@timestamp", "date", "log_source", "sourcetype",
            "type", "action", "event", "level", "priority",
            "source_ip", "source_port", "source_host", "user", "username",
            "dest_ip", "destination_ip", "dest_port", "destination_port",
            "destination_host", "destination_user", "message", "msg",
        }

        return {k: v for k, v in data.items() if k not in standard_fields}


class JSONLReader:
    """Reader for JSON Lines (JSONL) event files."""

    def __init__(self, parser: Optional[EventParser] = None):
        self.parser = parser or EventParser()

    def read_file(self, filepath: str) -> list[SecurityEvent]:
        """Read events from a JSONL file."""
        events = []
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    event = self.parser.parse(data)
                    if event:
                        events.append(event)
                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing line: {e}")
        return events
