"""
Event Buffer

Manages in-memory storage of events for time-based correlation.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from correlation_engine.models.event import SecurityEvent


class EventBuffer:
    """
    Thread-safe buffer for storing and querying events within time windows.

    Supports:
    - Time-windowed queries
    - Grouping by field values
    - Sequence tracking
    """

    def __init__(self, max_events: int = 100000, default_ttl_minutes: int = 1440) -> None:
        """
        Initialize the event buffer.

        Args:
            max_events: Maximum number of events to store
            default_ttl_minutes: Default time-to-live for events (24 hours)
        """
        self.max_events = max_events
        self.default_ttl = timedelta(minutes=default_ttl_minutes)

        # Main storage
        self._events: dict[str, SecurityEvent] = {}
        self._event_order: list[str] = []  # Maintain insertion order

        # Indexes for fast lookups
        self._ip_index: dict[str, set[str]] = defaultdict(set)
        self._user_index: dict[str, set[str]] = defaultdict(set)
        self._host_index: dict[str, set[str]] = defaultdict(set)
        self._type_index: dict[str, set[str]] = defaultdict(set)
        self._source_index: dict[str, set[str]] = defaultdict(set)

        # Sequence tracking
        self._sequences: dict[str, list[str]] = defaultdict(list)

    def add(self, event: SecurityEvent) -> None:
        """Add an event to the buffer."""
        # Enforce max size
        if len(self._events) >= self.max_events:
            self._evict_oldest(len(self._events) - self.max_events + 1)

        # Store event
        self._events[event.event_id] = event
        self._event_order.append(event.event_id)

        # Update indexes
        if event.src_ip:
            self._ip_index[event.src_ip].add(event.event_id)
        if event.dst_ip:
            self._ip_index[event.dst_ip].add(event.event_id)
        if event.src_user:
            self._user_index[event.src_user].add(event.event_id)
        if event.dst_user:
            self._user_index[event.dst_user].add(event.event_id)
        if event.src_host:
            self._host_index[event.src_host].add(event.event_id)
        if event.dst_host:
            self._host_index[event.dst_host].add(event.event_id)
        if event.event_type:
            self._type_index[event.event_type.value].add(event.event_id)
        if event.source:
            self._source_index[event.source.value].add(event.event_id)

    def get(self, event_id: str) -> Optional[SecurityEvent]:
        """Get an event by ID."""
        return self._events.get(event_id)

    def get_events_in_window(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> list[SecurityEvent]:
        """Get all events within a time window."""
        events = []
        for event_id in reversed(self._event_order):  # Start from newest
            event = self._events.get(event_id)
            if event is None:
                continue
            if event.timestamp > end_time:
                continue
            if event.timestamp < start_time:
                break  # Events are ordered, no need to continue
            events.append(event)
        return events

    def get_recent_events(self, window: timedelta) -> list[SecurityEvent]:
        """Get events from the last N duration."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - window
        return self.get_events_in_window(start_time, end_time)

    def get_events_by_ip(
        self,
        ip: str,
        window: Optional[timedelta] = None,
    ) -> list[SecurityEvent]:
        """Get events involving a specific IP address."""
        event_ids = self._ip_index.get(ip, set())
        events = [self._events[event_id] for event_id in event_ids if event_id in self._events]

        if window:
            cutoff = datetime.now(timezone.utc) - window
            events = [e for e in events if e.timestamp >= cutoff]

        return sorted(events, key=lambda e: e.timestamp)

    def get_events_by_user(
        self,
        user: str,
        window: Optional[timedelta] = None,
    ) -> list[SecurityEvent]:
        """Get events involving a specific user."""
        event_ids = self._user_index.get(user, set())
        events = [self._events[event_id] for event_id in event_ids if event_id in self._events]

        if window:
            cutoff = datetime.now(timezone.utc) - window
            events = [e for e in events if e.timestamp >= cutoff]

        return sorted(events, key=lambda e: e.timestamp)

    def get_events_by_host(
        self,
        host: str,
        window: Optional[timedelta] = None,
    ) -> list[SecurityEvent]:
        """Get events involving a specific host."""
        event_ids = self._host_index.get(host, set())
        events = [self._events[event_id] for event_id in event_ids if event_id in self._events]

        if window:
            cutoff = datetime.now(timezone.utc) - window
            events = [e for e in events if e.timestamp >= cutoff]

        return sorted(events, key=lambda e: e.timestamp)

    def get_events_by_type(
        self,
        event_type: str,
        window: Optional[timedelta] = None,
    ) -> list[SecurityEvent]:
        """Get events of a specific type."""
        event_ids = self._type_index.get(event_type, set())
        events = [self._events[event_id] for event_id in event_ids if event_id in self._events]

        if window:
            cutoff = datetime.now(timezone.utc) - window
            events = [e for e in events if e.timestamp >= cutoff]

        return sorted(events, key=lambda e: e.timestamp)

    def count_events_by_field(
        self,
        field: str,
        window: timedelta,
    ) -> dict[str, int]:
        """Count events grouped by a field value within a time window."""
        counts: dict[str, int] = defaultdict(int)
        cutoff = datetime.now(timezone.utc) - window

        for event in self._events.values():
            if event.timestamp < cutoff:
                continue

            value = getattr(event, field, None)
            if value is not None:
                counts[str(value)] += 1

        return dict(counts)

    def add_to_sequence(self, sequence_id: str, event: SecurityEvent) -> None:
        """Add an event to a tracked sequence."""
        self._sequences[sequence_id].append(event.event_id)

    def get_sequence(self, sequence_id: str) -> list[SecurityEvent]:
        """Get all events in a sequence."""
        event_ids = self._sequences.get(sequence_id, [])
        return [self._events[event_id] for event_id in event_ids if event_id in self._events]

    def clear_sequence(self, sequence_id: str) -> None:
        """Clear a tracked sequence."""
        self._sequences.pop(sequence_id, None)

    def cleanup(self, ttl: Optional[timedelta] = None) -> int:
        """
        Remove events older than the TTL.

        Returns the number of events removed.
        """
        if ttl is None:
            ttl = self.default_ttl

        cutoff = datetime.now(timezone.utc) - ttl
        to_remove = [
            event_id for event_id, event in self._events.items() if event.timestamp < cutoff
        ]

        for event_id in to_remove:
            self._remove_event(event_id)

        return len(to_remove)

    def _remove_event(self, event_id: str) -> None:
        """Remove an event and update all indexes."""
        event = self._events.pop(event_id, None)
        if event is None:
            return

        # Remove from order list
        if event_id in self._event_order:
            self._event_order.remove(event_id)

        # Remove from indexes
        if event.src_ip:
            self._ip_index[event.src_ip].discard(event_id)
        if event.dst_ip:
            self._ip_index[event.dst_ip].discard(event_id)
        if event.src_user:
            self._user_index[event.src_user].discard(event_id)
        if event.dst_user:
            self._user_index[event.dst_user].discard(event_id)
        if event.src_host:
            self._host_index[event.src_host].discard(event_id)
        if event.dst_host:
            self._host_index[event.dst_host].discard(event_id)
        if event.event_type:
            self._type_index[event.event_type.value].discard(event_id)
        if event.source:
            self._source_index[event.source.value].discard(event_id)

    def _evict_oldest(self, count: int) -> None:
        """Evict the oldest events to make room."""
        for _ in range(min(count, len(self._event_order))):
            if self._event_order:
                oldest_id = self._event_order[0]
                self._remove_event(oldest_id)

    def clear(self) -> None:
        """Clear all events from the buffer."""
        self._events.clear()
        self._event_order.clear()
        self._ip_index.clear()
        self._user_index.clear()
        self._host_index.clear()
        self._type_index.clear()
        self._source_index.clear()
        self._sequences.clear()

    def __len__(self) -> int:
        return len(self._events)

    def __contains__(self, event_id: str) -> bool:
        return event_id in self._events
