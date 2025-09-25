#!/usr/bin/env python3
"""
Example: Basic Security Event Correlation

This example demonstrates how to use the correlation engine
to detect security threats from sample events.
"""

from correlation_engine import CorrelationEngine, RuleRegistry
from correlation_engine.models.event import (
    EventSeverity,
    EventSource,
    EventType,
    SecurityEvent,
)
from correlation_engine.utils.sample_data import get_default_rules, generate_sample_events


def main():
    print("=" * 60)
    print("Security Event Correlation Engine - Example")
    print("=" * 60)

    # Initialize the engine with default rules
    print("\n[1] Initializing correlation engine...")
    registry = RuleRegistry()
    for rule in get_default_rules():
        registry.register(rule)

    engine = CorrelationEngine(rule_registry=registry)
    print(f"   Loaded {len(registry)} rules")

    # Generate sample events
    print("\n[2] Generating sample security events...")
    events = generate_sample_events(100)
    print(f"   Generated {len(events)} events")

    # Process events
    print("\n[3] Processing events...")
    alerts = engine.process_events(events)
    print(f"   Generated {len(alerts)} alerts")

    # Display alert summary
    print("\n[4] Alert Summary:")
    print("-" * 60)

    for alert in alerts[:10]:  # Show first 10 alerts
        print(f"\n   Alert: {alert.title}")
        print(f"   Priority: {alert.priority.value}")
        print(f"   Severity: {alert.severity.value}")
        print(f"   Category: {alert.category.value}")
        print(f"   Events: {alert.event_count}")
        print(f"   Source IPs: {', '.join(alert.src_ips[:3])}")
        if alert.mitre_tactics:
            print(f"   MITRE Tactics: {', '.join(alert.mitre_tactics)}")

    # Display engine statistics
    print("\n[5] Engine Statistics:")
    print("-" * 60)
    stats = engine.get_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")

    # Example: Process a specific attack pattern
    print("\n[6] Simulating Brute Force Attack...")
    print("-" * 60)

    # Reset engine for clean demo
    engine = CorrelationEngine(rule_registry=registry)

    # Simulate brute force attack (10 failed logins from same IP)
    attacker_ip = "185.220.101.42"
    for i in range(10):
        event = SecurityEvent(
            source=EventSource.AUTHENTICATION,
            event_type=EventType.LOGIN_FAILURE,
            severity=EventSeverity.MEDIUM,
            src_ip=attacker_ip,
            dst_port=22,
            dst_user="admin",
            description=f"Failed SSH login attempt {i+1}",
        )
        alerts = engine.process_event(event)

        if alerts:
            print(f"\n   [!] Alert triggered after {i+1} attempts!")
            for alert in alerts:
                print(f"   Alert: {alert.title}")
                print(f"   Priority: {alert.priority.value}")

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
