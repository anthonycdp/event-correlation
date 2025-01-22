"""
Security Event Correlation Engine

The main engine that processes events, applies rules, and generates alerts.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from collections import defaultdict
import logging

from correlation_engine.models.event import EventSeverity, EventType, SecurityEvent
from correlation_engine.models.alert import (
    Alert,
    AlertCategory,
    AlertPriority,
    AlertStatus,
)
from correlation_engine.rules.rule import CorrelationRule, RuleType
from correlation_engine.rules.registry import RuleRegistry
from correlation_engine.rules.evaluator import RuleEvaluator
from correlation_engine.processors.event_buffer import EventBuffer
from correlation_engine.processors.false_positive_reducer import FalsePositiveReducer

logger = logging.getLogger(__name__)


class CorrelationStats:
    """Statistics for the correlation engine."""

    def __init__(self) -> None:
        self.events_processed = 0
        self.events_matched = 0
        self.alerts_generated = 0
        self.false_positives_filtered = 0
        self.start_time = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "events_processed": self.events_processed,
            "events_matched": self.events_matched,
            "alerts_generated": self.alerts_generated,
            "false_positives_filtered": self.false_positives_filtered,
            "uptime_seconds": (datetime.now(timezone.utc) - self.start_time).total_seconds(),
        }


class CorrelationEngine:
    """
    Main correlation engine that processes security events and generates alerts.

    Features:
    - Rule-based correlation (single event, threshold, sequence, aggregation)
    - False positive reduction
    - Alert prioritization
    - Event buffering for time-window analysis
    """

    def __init__(
        self,
        rule_registry: Optional[RuleRegistry] = None,
        buffer_size: int = 100000,
        buffer_ttl_minutes: int = 1440,
        enable_fp_reduction: bool = True,
    ) -> None:
        """
        Initialize the correlation engine.

        Args:
            rule_registry: Registry of correlation rules
            buffer_size: Maximum events to keep in memory
            buffer_ttl_minutes: Time-to-live for buffered events
            enable_fp_reduction: Whether to enable false positive reduction
        """
        self.rule_registry = rule_registry or RuleRegistry()
        self.evaluator = RuleEvaluator()
        self.buffer = EventBuffer(
            max_events=buffer_size,
            default_ttl_minutes=buffer_ttl_minutes,
        )
        self.false_positive_reducer = FalsePositiveReducer() if enable_fp_reduction else None

        # State tracking
        self._threshold_counters: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._sequence_state: dict[str, dict[str, Any]] = {}
        self._active_alerts: dict[str, Alert] = {}

        self.stats = CorrelationStats()

    def process_event(self, event: SecurityEvent) -> list[Alert]:
        """
        Process a single security event.

        Returns a list of alerts generated from this event.
        """
        self.stats.events_processed += 1

        # Add event to buffer for time-window analysis
        self.buffer.add(event)

        # Process against all enabled rules
        alerts = []
        for rule in self.rule_registry.get_enabled():
            rule_alerts = self._process_rule(event, rule)
            alerts.extend(rule_alerts)

        return alerts

    def process_events(self, events: list[SecurityEvent]) -> list[Alert]:
        """
        Process multiple security events.

        Returns all alerts generated from processing.
        """
        all_alerts = []
        for event in events:
            alerts = self.process_event(event)
            all_alerts.extend(alerts)
        return all_alerts

    def _process_rule(self, event: SecurityEvent, rule: CorrelationRule) -> list[Alert]:
        """Process an event against a specific rule."""
        alerts = []

        if rule.rule_type == RuleType.SINGLE_EVENT:
            alert = self._process_single_event_rule(event, rule)
            if alert:
                alerts.append(alert)

        elif rule.rule_type == RuleType.THRESHOLD:
            alert = self._process_threshold_rule(event, rule)
            if alert:
                alerts.append(alert)

        elif rule.rule_type == RuleType.SEQUENCE:
            alert = self._process_sequence_rule(event, rule)
            if alert:
                alerts.append(alert)

        elif rule.rule_type == RuleType.AGGREGATION:
            alert = self._process_aggregation_rule(event, rule)
            if alert:
                alerts.append(alert)

        return alerts

    def _process_single_event_rule(
        self, event: SecurityEvent, rule: CorrelationRule
    ) -> Optional[Alert]:
        """Process a single-event rule."""
        if self.evaluator.evaluate_event(event, rule):
            self.stats.events_matched += 1
            return self._create_alert(rule, [event])
        return None

    def _process_threshold_rule(
        self, event: SecurityEvent, rule: CorrelationRule
    ) -> Optional[Alert]:
        """Process a threshold-based rule."""
        # First, check if the event matches the base conditions
        if not self.evaluator.evaluate_event(event, rule):
            return None

        # Get grouping key (e.g., by source IP)
        group_key = self._get_group_key(event, rule)

        # Increment counter
        counter_key = f"{rule.rule_id}:{group_key}"
        self._threshold_counters[rule.rule_id][counter_key] += 1
        count = self._threshold_counters[rule.rule_id][counter_key]

        # Check threshold
        if rule.threshold and count >= rule.threshold:
            # Get all matching events in the time window
            matching_events = self._get_matching_events(rule)

            # Reset counter
            del self._threshold_counters[rule.rule_id][counter_key]

            self.stats.events_matched += count
            return self._create_alert(rule, matching_events)

        return None

    def _process_sequence_rule(
        self, event: SecurityEvent, rule: CorrelationRule
    ) -> Optional[Alert]:
        """Process a sequence-based rule."""
        if not rule.sequence:
            return None

        # Get sequence key (e.g., by source IP or user)
        sequence_key = self._get_group_key(event, rule)

        # Initialize sequence state if needed
        if sequence_key not in self._sequence_state:
            self._sequence_state[sequence_key] = {
                "rule_id": rule.rule_id,
                "current_step": 0,
                "events": [],
                "start_time": None,
            }

        state = self._sequence_state[sequence_key]

        # Check if sequence has timed out
        if state["start_time"]:
            timeout = timedelta(minutes=rule.sequence_timeout_minutes)
            if datetime.now(timezone.utc) - state["start_time"] > timeout:
                # Reset sequence
                state["current_step"] = 0
                state["events"] = []
                state["start_time"] = None

        # Check if event matches current step
        current_step = state["current_step"]
        if current_step < len(rule.sequence):
            step_conditions = rule.sequence[current_step]
            if self.evaluator._evaluate_condition_group(event, step_conditions):
                # Advance sequence
                state["events"].append(event)
                state["current_step"] += 1

                if state["start_time"] is None:
                    state["start_time"] = datetime.now(timezone.utc)

                # Check if sequence is complete
                if state["current_step"] >= len(rule.sequence):
                    self.stats.events_matched += len(state["events"])
                    alert = self._create_alert(rule, state["events"])
                    del self._sequence_state[sequence_key]
                    return alert

        return None

    def _process_aggregation_rule(
        self, event: SecurityEvent, rule: CorrelationRule
    ) -> Optional[Alert]:
        """Process an aggregation rule."""
        # For aggregation, we check if conditions match, then aggregate
        # all events in the time window
        if not self.evaluator.evaluate_event(event, rule):
            return None

        # Get events in time window matching conditions
        matching_events = self._get_matching_events(rule)

        if len(matching_events) >= (rule.threshold or 1):
            self.stats.events_matched += len(matching_events)
            return self._create_alert(rule, matching_events)

        return None

    def _get_group_key(self, event: SecurityEvent, rule: CorrelationRule) -> str:
        """Generate a grouping key for an event based on rule context."""
        # Default: group by source IP
        return event.src_ip or event.src_user or "default"

    def _get_matching_events(self, rule: CorrelationRule) -> list[SecurityEvent]:
        """Get all events matching a rule's conditions within the time window."""
        matching = []
        window = rule.time_window

        for event in self.buffer.get_recent_events(window):
            if self.evaluator.evaluate_event(event, rule):
                matching.append(event)

        return matching

    def _create_alert(
        self, rule: CorrelationRule, events: list[SecurityEvent]
    ) -> Optional[Alert]:
        """Create an alert from matching events."""
        if not events:
            return None

        # Parse severity and category
        try:
            severity = EventSeverity(rule.alert_severity)
        except ValueError:
            severity = EventSeverity.MEDIUM

        try:
            category = AlertCategory(rule.alert_category)
        except ValueError:
            category = AlertCategory.OTHER

        # Create the alert
        alert = Alert(
            title=rule.alert_title,
            description=rule.alert_description,
            category=category,
            severity=severity,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            correlation_score=min(1.0, rule.base_score / 100),
            mitre_tactics=rule.mitre_tactics,
            mitre_techniques=rule.mitre_techniques,
        )

        # Add all matching events
        for event in events:
            alert.add_event(event)

        # Calculate priority
        alert.priority = alert.calculate_priority()

        # Apply false positive reduction
        if self.false_positive_reducer:
            is_fp, reason, whitelist_match = self.false_positive_reducer.process_alert(alert)
            if is_fp:
                alert.mark_false_positive(reason or "", whitelist_match)
                self.stats.false_positives_filtered += 1
                logger.info(
                    f"Alert {alert.alert_id} marked as false positive: {reason}"
                )
                return None

        # Store alert
        self._active_alerts[alert.alert_id] = alert
        self.stats.alerts_generated += 1

        logger.info(
            f"Alert generated: {alert.alert_id} - {alert.title} "
            f"(Priority: {alert.priority.value}, Events: {alert.event_count})"
        )

        return alert

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get an alert by ID."""
        return self._active_alerts.get(alert_id)

    def get_alerts(
        self,
        status: Optional[AlertStatus] = None,
        priority: Optional[AlertPriority] = None,
        min_severity: Optional[EventSeverity] = None,
        include_false_positives: bool = False,
    ) -> list[Alert]:
        """Get alerts filtered by criteria."""
        alerts = list(self._active_alerts.values())

        if not include_false_positives:
            alerts = [a for a in alerts if not a.is_false_positive]

        if status:
            alerts = [a for a in alerts if a.status == status]

        if priority:
            alerts = [a for a in alerts if a.priority == priority]

        if min_severity:
            alerts = [a for a in alerts if a.severity.numeric_value >= min_severity.numeric_value]

        return sorted(alerts, key=lambda a: a.created_at, reverse=True)

    def get_prioritized_alerts(self, limit: int = 10) -> list[Alert]:
        """Get top alerts by priority."""
        alerts = [a for a in self._active_alerts.values() if not a.is_false_positive]
        return sorted(alerts, key=lambda a: a.priority.numeric_value)[:limit]

    def resolve_alert(self, alert_id: str, resolution: str, resolved_by: str = "system") -> bool:
        """Resolve an alert."""
        alert = self._active_alerts.get(alert_id)
        if alert:
            alert.status = AlertStatus.RESOLVED
            alert.add_note(f"Resolved: {resolution}", resolved_by)
            return True
        return False

    def add_whitelist_ip(self, ip: str, name: str, description: str = "") -> None:
        """Add an IP to the whitelist."""
        if self.false_positive_reducer:
            from correlation_engine.processors.false_positive_reducer import (
                WhitelistEntry,
                WhitelistType,
            )
            entry = WhitelistEntry(
                name=name,
                entry_type=WhitelistType.IP,
                value=ip,
                description=description,
            )
            self.false_positive_reducer.add_whitelist_entry(entry)

    def cleanup(self) -> dict[str, int]:
        """
        Perform cleanup of old data.

        Returns counts of cleaned items.
        """
        result = {
            "events_cleaned": self.buffer.cleanup(),
            "alerts_cleaned": 0,
        }

        if self.false_positive_reducer:
            result["whitelist_cleaned"] = self.false_positive_reducer.cleanup_expired_entries()

        # Remove resolved alerts older than 7 days
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        to_remove = [
            aid
            for aid, alert in self._active_alerts.items()
            if alert.status == AlertStatus.RESOLVED and alert.updated_at < cutoff
        ]
        for aid in to_remove:
            del self._active_alerts[aid]
        result["alerts_cleaned"] = len(to_remove)

        return result

    def get_stats(self) -> dict[str, Any]:
        """Get engine statistics."""
        stats = self.stats.to_dict()
        stats["buffer_size"] = len(self.buffer)
        stats["active_alerts"] = len(self._active_alerts)
        stats["enabled_rules"] = len(self.rule_registry.get_enabled())
        return stats
