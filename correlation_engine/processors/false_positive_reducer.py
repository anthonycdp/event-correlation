"""
False Positive Reducer

Implements various techniques to reduce false positives in alerts.
"""

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional
from ipaddress import ip_address, ip_network

from pydantic import BaseModel, Field

from correlation_engine.models.alert import Alert
from correlation_engine.models.event import SecurityEvent


class WhitelistType(str, Enum):
    """Types of whitelists."""

    IP = "ip"
    USER = "user"
    HOST = "host"
    PROCESS = "process"
    CUSTOM = "custom"


class WhitelistEntry(BaseModel):
    """A single whitelist entry."""

    name: str
    entry_type: WhitelistType
    value: str  # IP, CIDR, username, hostname, or pattern
    description: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_by: str = "system"
    tags: list[str] = Field(default_factory=list)

    def is_expired(self) -> bool:
        """Check if this entry has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def matches(self, value: str) -> bool:
        """Check if a value matches this whitelist entry."""
        if self.entry_type == WhitelistType.IP:
            return self._matches_ip(value)
        else:
            return value.lower() == self.value.lower()

    def _matches_ip(self, value: str) -> bool:
        """Check if an IP matches (supports CIDR notation)."""
        try:
            if "/" in self.value:
                # CIDR notation
                return ip_address(value) in ip_network(self.value, strict=False)
            else:
                return value == self.value
        except ValueError:
            return False


class BaselineEntry(BaseModel):
    """A baseline entry for behavioral analysis."""

    entity_type: str  # "user", "host", "ip"
    entity_id: str
    metric: str
    baseline_value: float
    threshold_multiplier: float = 2.0
    sample_count: int = 0
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def is_anomalous(self, current_value: float) -> bool:
        """Check if current value is anomalous compared to baseline."""
        if self.sample_count < 10:  # Need enough samples
            return False
        threshold = self.baseline_value * self.threshold_multiplier
        return current_value > threshold


class FalsePositiveReducer:
    """
    Reduces false positives through various techniques:
    - Whitelisting
    - Behavioral baselining
    - Alert suppression
    - Context-aware filtering
    """

    def __init__(self) -> None:
        self.whitelists: dict[WhitelistType, list[WhitelistEntry]] = {
            t: [] for t in WhitelistType
        }
        self.baselines: dict[str, BaselineEntry] = {}
        self.suppression_cache: dict[str, datetime] = {}
        self.false_positive_history: dict[str, int] = {}  # fingerprint -> count

    # === Whitelist Management ===

    def add_whitelist_entry(self, entry: WhitelistEntry) -> None:
        """Add a whitelist entry."""
        self.whitelists[entry.entry_type].append(entry)

    def remove_whitelist_entry(self, name: str) -> bool:
        """Remove a whitelist entry by name."""
        for entry_type in self.whitelists:
            for i, entry in enumerate(self.whitelists[entry_type]):
                if entry.name == name:
                    self.whitelists[entry_type].pop(i)
                    return True
        return False

    def is_whitelisted(
        self,
        ip: Optional[str] = None,
        user: Optional[str] = None,
        host: Optional[str] = None,
    ) -> Optional[str]:
        """
        Check if an entity is whitelisted.

        Returns the name of the matching whitelist entry, or None.
        """
        # Check IP whitelist
        if ip:
            for entry in self.whitelists[WhitelistType.IP]:
                if not entry.is_expired() and entry.matches(ip):
                    return entry.name

        # Check user whitelist
        if user:
            for entry in self.whitelists[WhitelistType.USER]:
                if not entry.is_expired() and entry.matches(user):
                    return entry.name

        # Check host whitelist
        if host:
            for entry in self.whitelists[WhitelistType.HOST]:
                if not entry.is_expired() and entry.matches(host):
                    return entry.name

        return None

    # === Baseline Management ===

    def update_baseline(
        self,
        entity_type: str,
        entity_id: str,
        metric: str,
        value: float,
    ) -> None:
        """Update a baseline with a new observation."""
        key = f"{entity_type}:{entity_id}:{metric}"

        if key in self.baselines:
            baseline = self.baselines[key]
            # Exponential moving average
            alpha = 0.1
            baseline.baseline_value = alpha * value + (1 - alpha) * baseline.baseline_value
            baseline.sample_count += 1
            baseline.last_updated = datetime.now(timezone.utc)
        else:
            self.baselines[key] = BaselineEntry(
                entity_type=entity_type,
                entity_id=entity_id,
                metric=metric,
                baseline_value=value,
                sample_count=1,
            )

    def is_anomalous(
        self,
        entity_type: str,
        entity_id: str,
        metric: str,
        current_value: float,
    ) -> bool:
        """Check if a value is anomalous compared to baseline."""
        key = f"{entity_type}:{entity_id}:{metric}"
        if key not in self.baselines:
            return False  # No baseline yet
        return self.baselines[key].is_anomalous(current_value)

    # === Alert Suppression ===

    def should_suppress_alert(self, alert: Alert, suppression_window: timedelta) -> bool:
        """
        Check if an alert should be suppressed (duplicate within window).

        Uses alert fingerprinting to identify similar alerts.
        """
        fingerprint = self._generate_alert_fingerprint(alert)

        if fingerprint in self.suppression_cache:
            last_seen = self.suppression_cache[fingerprint]
            if datetime.now(timezone.utc) - last_seen < suppression_window:
                return True

        # Update cache
        self.suppression_cache[fingerprint] = datetime.now(timezone.utc)
        return False

    def _generate_alert_fingerprint(self, alert: Alert) -> str:
        """Generate a fingerprint for alert deduplication."""
        # Combine key attributes for fingerprinting
        parts = [
            alert.rule_id or "none",
            alert.category.value,
            ",".join(sorted(alert.src_ips[:3])),  # Limit to first 3
            ",".join(sorted(alert.users[:3])),
            ",".join(sorted(alert.hosts[:3])),
        ]
        return "|".join(parts)

    # === Main Processing ===

    def process_alert(self, alert: Alert) -> tuple[bool, Optional[str], Optional[str]]:
        """
        Process an alert for false positive reduction.

        Returns:
            - is_false_positive: Whether the alert is a false positive
            - reason: Reason for false positive determination
            - whitelist_match: Name of matching whitelist entry, if any
        """
        # Check whitelists
        for src_ip in alert.src_ips:
            match = self.is_whitelisted(ip=src_ip)
            if match:
                return True, f"Source IP {src_ip} is whitelisted", match

        for user in alert.users:
            match = self.is_whitelisted(user=user)
            if match:
                return True, f"User {user} is whitelisted", match

        for host in alert.hosts:
            match = self.is_whitelisted(host=host)
            if match:
                return True, f"Host {host} is whitelisted", match

        # Check suppression
        if self.should_suppress_alert(alert, timedelta(hours=1)):
            return True, "Duplicate alert suppressed within 1 hour", None

        # Check historical false positive rate
        fingerprint = self._generate_alert_fingerprint(alert)
        if fingerprint in self.false_positive_history:
            fp_count = self.false_positive_history[fingerprint]
            if fp_count >= 5:
                return True, f"Historical false positive pattern (marked {fp_count} times)", None

        return False, None, None

    def mark_false_positive(self, alert: Alert) -> None:
        """Mark an alert as a false positive for learning."""
        fingerprint = self._generate_alert_fingerprint(alert)
        self.false_positive_history[fingerprint] = (
            self.false_positive_history.get(fingerprint, 0) + 1
        )

    # === Utility Methods ===

    def cleanup_expired_entries(self) -> int:
        """Remove expired whitelist entries and old suppression cache entries."""
        count = 0

        # Clean whitelists
        for entry_type in self.whitelists:
            before = len(self.whitelists[entry_type])
            self.whitelists[entry_type] = [
                e for e in self.whitelists[entry_type] if not e.is_expired()
            ]
            count += before - len(self.whitelists[entry_type])

        # Clean suppression cache (older than 24 hours)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        old_keys = [k for k, v in self.suppression_cache.items() if v < cutoff]
        for key in old_keys:
            del self.suppression_cache[key]
            count += 1

        return count

    def load_whitelists_from_dict(self, data: dict[str, Any]) -> int:
        """Load whitelists from a dictionary configuration."""
        count = 0
        for entry_type_str, entries in data.items():
            try:
                entry_type = WhitelistType(entry_type_str)
                for entry_data in entries:
                    entry = WhitelistEntry(entry_type=entry_type, **entry_data)
                    self.add_whitelist_entry(entry)
                    count += 1
            except (ValueError, TypeError):
                continue
        return count
