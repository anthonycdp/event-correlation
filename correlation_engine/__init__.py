"""
Security Event Correlation Engine

A rule-based system for correlating security events from multiple sources,
triaging alerts, and reducing false positives.
"""

__version__ = "1.0.0"

from correlation_engine.models.event import SecurityEvent, EventSource, EventSeverity
from correlation_engine.models.alert import Alert, AlertPriority
from correlation_engine.engine import CorrelationEngine
from correlation_engine.rules.registry import RuleRegistry

__all__ = [
    "SecurityEvent",
    "EventSource",
    "EventSeverity",
    "Alert",
    "AlertPriority",
    "CorrelationEngine",
    "RuleRegistry",
]
