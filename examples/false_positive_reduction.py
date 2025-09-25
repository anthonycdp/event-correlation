#!/usr/bin/env python3
"""
Example: False Positive Reduction

This example demonstrates the false positive reduction capabilities
including whitelisting, baselining, and alert suppression.
"""

from correlation_engine import CorrelationEngine, RuleRegistry
from correlation_engine.models.event import (
    EventSeverity,
    EventSource,
    EventType,
    SecurityEvent,
)
from correlation_engine.processors.false_positive_reducer import (
    FalsePositiveReducer,
    WhitelistEntry,
    WhitelistType,
)
from correlation_engine.utils.sample_data import get_default_rules


def main():
    print("=" * 60)
    print("False Positive Reduction Example")
    print("=" * 60)

    # Initialize engine with FP reduction enabled
    registry = RuleRegistry()
    for rule in get_default_rules():
        registry.register(rule)

    engine = CorrelationEngine(rule_registry=registry, enable_fp_reduction=True)

    # Example 1: IP Whitelisting
    print("\n[1] IP Whitelisting")
    print("-" * 60)

    # Add vulnerability scanner to whitelist
    engine.add_whitelist_ip(
        ip="192.168.1.50",
        name="authorized_scanner",
        description="Authorized vulnerability scanner"
    )
    print("   Added authorized scanner IP to whitelist")

    # Generate events from scanner (would normally trigger port scan rule)
    print("   Generating port scan events from whitelisted IP...")
    for port in [22, 80, 443, 3389, 445]:
        event = SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.PORT_SCAN,
            severity=EventSeverity.HIGH,
            src_ip="192.168.1.50",  # Whitelisted IP
            dst_ip="192.168.1.1",
            dst_port=port,
        )
        alerts = engine.process_event(event)

    print(f"   Alerts generated: {len(engine.get_alerts(include_false_positives=False))}")
    print(f"   False positives filtered: {engine.stats.false_positives_filtered}")

    # Example 2: CIDR Whitelisting
    print("\n[2] CIDR Range Whitelisting")
    print("-" * 60)

    # Whitelist entire internal network
    if engine.fp_reducer:
        entry = WhitelistEntry(
            name="internal_network",
            entry_type=WhitelistType.IP,
            value="10.0.0.0/8",
            description="Internal corporate network",
        )
        engine.fp_reducer.add_whitelist_entry(entry)
        print("   Added 10.0.0.0/8 to whitelist")

    # Example 3: User Whitelisting
    print("\n[3] User Whitelisting")
    print("-" * 60)

    if engine.fp_reducer:
        entry = WhitelistEntry(
            name="service_accounts",
            entry_type=WhitelistType.USER,
            value="svc_backup",
            description="Backup service account",
        )
        engine.fp_reducer.add_whitelist_entry(entry)
        print("   Added svc_backup to user whitelist")

    # Example 4: Alert Suppression (duplicate alerts)
    print("\n[4] Alert Suppression")
    print("-" * 60)

    # Reset engine for clean demo
    engine = CorrelationEngine(rule_registry=registry, enable_fp_reduction=True)

    # Generate the same type of alert multiple times
    print("   Generating multiple alerts of same type...")

    alert_count = 0
    for i in range(5):
        event = SecurityEvent(
            source=EventSource.AUTHENTICATION,
            event_type=EventType.LOGIN_FAILURE,
            severity=EventSeverity.MEDIUM,
            src_ip="185.220.101.42",
            dst_port=22,
            dst_user="admin",
        )
        alerts = engine.process_event(event)
        if alerts:
            alert_count = len(engine.get_alerts())

    print(f"   Events processed: 5 (15 failed logins)")
    print(f"   Unique alerts: {alert_count}")
    print(f"   Duplicates suppressed: {engine.stats.false_positives_filtered}")

    # Example 5: Behavioral Baselining
    print("\n[5] Behavioral Baselining")
    print("-" * 60)

    reducer = FalsePositiveReducer()

    # Establish baseline for user login counts
    print("   Establishing baseline (normal behavior)...")
    for _ in range(20):
        reducer.update_baseline("user", "jsmith", "daily_login_count", 5)

    baseline = reducer.baselines.get("user:jsmith:daily_login_count")
    if baseline:
        print(f"   Baseline login count for jsmith: {baseline.baseline_value:.1f}")

    # Check if anomalous
    print("\n   Checking for anomalies...")

    # Normal login count
    is_anomaly = reducer.is_anomalous("user", "jsmith", "daily_login_count", 6)
    print(f"   6 logins: Anomalous? {is_anomaly}")

    # High login count
    is_anomaly = reducer.is_anomalous("user", "jsmith", "daily_login_count", 50)
    print(f"   50 logins: Anomalous? {is_anomaly}")

    # Example 6: Manual False Positive Marking
    print("\n[6] Manual False Positive Marking")
    print("-" * 60)

    # Create an alert and mark it as FP
    from correlation_engine.models.alert import Alert, AlertCategory

    alert = Alert(
        title="Suspicious Activity",
        description="Test alert",
        category=AlertCategory.ANOMALY,
    )
    alert.add_note("Initial investigation showed legitimate activity")

    # Mark as false positive
    alert.mark_false_positive("Determined to be legitimate admin activity", None)

    print(f"   Alert status: {alert.status.value}")
    print(f"   Is false positive: {alert.is_false_positive}")
    print(f"   Reason: {alert.false_positive_reason}")

    # Example 7: Whitelist Entry Expiration
    print("\n[7] Expiring Whitelist Entries")
    print("-" * 60)

    from datetime import datetime, timedelta

    reducer = FalsePositiveReducer()

    # Add temporary whitelist entry
    entry = WhitelistEntry(
        name="temp_contractor",
        entry_type=WhitelistType.IP,
        value="172.16.0.100",
        description="Temporary contractor access",
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    reducer.add_whitelist_entry(entry)
    print("   Added temporary whitelist (expires in 1 hour)")

    # Check if still valid
    match = reducer.is_whitelisted(ip="172.16.0.100")
    print(f"   Currently whitelisted: {match is not None}")

    # Example 8: Full Alert Processing
    print("\n[8] Full Alert Processing with FP Reduction")
    print("-" * 60)

    engine = CorrelationEngine(rule_registry=registry, enable_fp_reduction=True)

    # Add whitelists
    engine.add_whitelist_ip("192.168.1.50", "scanner")

    # Generate mix of events
    events = [
        # Should be whitelisted
        SecurityEvent(
            source=EventSource.FIREWALL,
            event_type=EventType.PORT_SCAN,
            severity=EventSeverity.HIGH,
            src_ip="192.168.1.50",
        ),
        # Should generate alert
        SecurityEvent(
            source=EventSource.AUTHENTICATION,
            event_type=EventType.LOGIN_FAILURE,
            severity=EventSeverity.HIGH,
            src_ip="185.220.101.42",
            dst_port=22,
        ),
    ] * 10  # Repeat to trigger threshold

    for event in events:
        engine.process_event(event)

    stats = engine.get_stats()
    print(f"   Events processed: {stats['events_processed']}")
    print(f"   Alerts generated: {stats['alerts_generated']}")
    print(f"   False positives filtered: {stats['false_positives_filtered']}")

    print("\n" + "=" * 60)
    print("False positive reduction example completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
