"""
Security Event Models

Defines the core data structures for security events from various sources.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class EventSource(str, Enum):
    """Supported security event sources."""

    FIREWALL = "firewall"
    IDS_IPS = "ids_ips"
    AUTHENTICATION = "authentication"
    ENDPOINT = "endpoint"
    NETWORK_FLOW = "network_flow"
    DNS = "dns"
    PROXY = "proxy"
    SIEM = "siem"
    CLOUD = "cloud"
    EMAIL = "email"
    CUSTOM = "custom"


class EventSeverity(str, Enum):
    """Event severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def numeric_value(self) -> int:
        """Return numeric value for comparison."""
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class EventType(str, Enum):
    """Types of security events."""

    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    ACCOUNT_LOCKOUT = "account_lockout"
    PASSWORD_CHANGE = "password_change"
    MFA_EVENT = "mfa_event"

    # Network events
    CONNECTION = "connection"
    CONNECTION_DENIED = "connection_denied"
    PORT_SCAN = "port_scan"
    MALWARE_DETECTED = "malware_detected"
    INTRUSION_DETECTED = "intrusion_detected"

    # Endpoint events
    FILE_ACCESS = "file_access"
    FILE_MODIFICATION = "file_modification"
    PROCESS_STARTED = "process_started"
    REGISTRY_CHANGE = "registry_change"

    # DNS events
    DNS_QUERY = "dns_query"
    DNS_TUNNELING = "dns_tunneling"

    # Cloud events
    API_CALL = "api_call"
    RESOURCE_ACCESS = "resource_access"
    CONFIGURATION_CHANGE = "configuration_change"

    # Email events
    EMAIL_RECEIVED = "email_received"
    EMAIL_BLOCKED = "email_blocked"
    PHISHING_DETECTED = "phishing_detected"

    # Generic
    ALERT = "alert"
    ANOMALY = "anomaly"
    OTHER = "other"


class SecurityEvent(BaseModel):
    """
    Represents a single security event from any source.

    This is the core data structure that all events are normalized to
    before being processed by the correlation engine.
    """

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: EventSource
    event_type: EventType
    severity: EventSeverity = EventSeverity.LOW

    # Source and destination
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    src_host: Optional[str] = None
    src_user: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    dst_host: Optional[str] = None
    dst_user: Optional[str] = None

    # Additional context
    description: Optional[str] = None
    raw_data: Optional[dict[str, Any]] = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Correlation fields
    correlation_id: Optional[str] = None
    session_id: Optional[str] = None
    related_events: list[str] = Field(default_factory=list)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "event_id": "evt-001",
                    "timestamp": "2024-01-15T10:30:00Z",
                    "source": "firewall",
                    "event_type": "connection_denied",
                    "severity": "medium",
                    "src_ip": "192.168.1.100",
                    "src_port": 54321,
                    "dst_ip": "10.0.0.5",
                    "dst_port": 22,
                    "description": "SSH connection blocked from external network",
                }
            ]
        }
    }

    def __hash__(self) -> int:
        return hash(self.event_id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecurityEvent):
            return False
        return self.event_id == other.event_id

    @property
    def key_fields(self) -> dict[str, Any]:
        """Return key fields used for correlation."""
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_user": self.src_user,
            "dst_user": self.dst_user,
            "src_host": self.src_host,
            "dst_host": self.dst_host,
            "event_type": self.event_type,
            "source": self.source,
        }

    def matches_criteria(self, **criteria: Any) -> bool:
        """Check if event matches given criteria."""
        for key, value in criteria.items():
            if value is None:
                continue
            event_value = getattr(self, key, None)
            if event_value is None:
                return False
            if isinstance(value, list):
                if event_value not in value:
                    return False
            elif event_value != value:
                return False
        return True
