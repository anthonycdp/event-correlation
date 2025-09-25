#!/usr/bin/env python3
"""
Example: Custom Rule Creation

This example demonstrates how to create and use custom correlation rules.
"""

from correlation_engine import CorrelationEngine, RuleRegistry
from correlation_engine.models.event import (
    EventSeverity,
    EventSource,
    EventType,
    SecurityEvent,
)
from correlation_engine.rules.rule import (
    Condition,
    ConditionGroup,
    ConditionOperator,
    CorrelationRule,
    LogicalOperator,
    RuleType,
)


def create_custom_rules():
    """Create custom correlation rules for specific detection scenarios."""

    rules = []

    # Rule 1: Detect data exfiltration via DNS
    dns_exfil_rule = CorrelationRule(
        rule_id="custom-dns-001",
        name="DNS Data Exfiltration",
        description="Detects potential DNS-based data exfiltration",
        enabled=True,
        rule_type=RuleType.SINGLE_EVENT,
        conditions=ConditionGroup(
            operator=LogicalOperator.AND,
            conditions=[
                Condition(
                    field="event_type",
                    operator=ConditionOperator.EQUALS,
                    value="dns_query",
                ),
                Condition(
                    field="description",
                    operator=ConditionOperator.REGEX,
                    value=r".*[a-zA-Z0-9]{30,}.*",  # Long encoded strings in DNS
                ),
            ],
        ),
        alert_title="Potential DNS Data Exfiltration",
        alert_description="DNS query contains suspiciously long encoded data",
        alert_category="data_exfiltration",
        alert_severity="critical",
        mitre_tactics=["Exfiltration"],
        mitre_techniques=["T1048.003"],
        base_score=85,
        tags=["dns", "exfiltration", "detection"],
    )
    rules.append(dns_exfil_rule)

    # Rule 2: Detect after-hours access to sensitive systems
    after_hours_rule = CorrelationRule(
        rule_id="custom-time-001",
        name="After-Hours Access to Sensitive System",
        description="Detects access to sensitive systems outside business hours",
        enabled=True,
        rule_type=RuleType.SINGLE_EVENT,
        conditions=ConditionGroup(
            operator=LogicalOperator.AND,
            conditions=[
                Condition(
                    field="event_type",
                    operator=ConditionOperator.EQUALS,
                    value="login_success",
                ),
                Condition(
                    field="dst_host",
                    operator=ConditionOperator.IN,
                    value=["db-server-01", "finance-server", "hr-system"],
                ),
            ],
        ),
        alert_title="After-Hours Access Detected",
        alert_description="Access to sensitive system outside normal hours",
        alert_category="policy_violation",
        alert_severity="medium",
        base_score=50,
        tags=["policy", "insider_threat"],
    )
    rules.append(after_hours_rule)

    # Rule 3: Detect impossible travel (login from distant locations)
    impossible_travel_rule = CorrelationRule(
        rule_id="custom-travel-001",
        name="Impossible Travel Detected",
        description="Detects logins from geographically impossible locations",
        enabled=True,
        rule_type=RuleType.SEQUENCE,
        sequence=[
            # First login from location A
            ConditionGroup(
                conditions=[
                    Condition(
                        field="event_type",
                        operator=ConditionOperator.EQUALS,
                        value="login_success",
                    ),
                    Condition(
                        field="src_ip",
                        operator=ConditionOperator.IN,
                        value=["192.168.1.0/24", "10.0.0.0/8"],  # Internal IPs
                    ),
                ],
            ),
            # Second login from external IP
            ConditionGroup(
                conditions=[
                    Condition(
                        field="event_type",
                        operator=ConditionOperator.EQUALS,
                        value="login_success",
                    ),
                    Condition(
                        field="src_ip",
                        operator=ConditionOperator.REGEX,
                        value=r"^(?!192\.168\.|10\.).*",  # External IP
                    ),
                ],
            ),
        ],
        sequence_timeout_minutes=60,
        alert_title="Impossible Travel Detected",
        alert_description="User logged in from locations too far apart in short time",
        alert_category="account_compromise",
        alert_severity="high",
        mitre_tactics=["Initial Access"],
        mitre_techniques=["T1078"],
        base_score=80,
        tags=["account", "geolocation", "impossible_travel"],
    )
    rules.append(impossible_travel_rule)

    # Rule 4: Detect privilege escalation via group membership changes
    priv_esc_rule = CorrelationRule(
        rule_id="custom-priv-001",
        name="Privilege Escalation via Group Change",
        description="Detects users being added to privileged groups",
        enabled=True,
        rule_type=RuleType.SINGLE_EVENT,
        conditions=ConditionGroup(
            operator=LogicalOperator.AND,
            conditions=[
                Condition(
                    field="event_type",
                    operator=ConditionOperator.EQUALS,
                    value="configuration_change",
                ),
                Condition(
                    field="description",
                    operator=ConditionOperator.CONTAINS,
                    value="Domain Admins",
                ),
            ],
        ),
        alert_title="Privileged Group Modification",
        alert_description="User added to Domain Admins group",
        alert_category="privilege_escalation",
        alert_severity="critical",
        mitre_tactics=["Persistence", "Privilege Escalation"],
        mitre_techniques=["T1098"],
        base_score=90,
        tags=["ad", "privilege", "domain_admin"],
    )
    rules.append(priv_esc_rule)

    # Rule 5: Detect multiple malware detections from same source
    malware_campaign_rule = CorrelationRule(
        rule_id="custom-malware-001",
        name="Malware Campaign Detection",
        description="Multiple malware detections suggest active campaign",
        enabled=True,
        rule_type=RuleType.THRESHOLD,
        conditions=ConditionGroup(
            conditions=[
                Condition(
                    field="event_type",
                    operator=ConditionOperator.EQUALS,
                    value="malware_detected",
                ),
            ],
        ),
        threshold=3,
        time_window_minutes=30,
        alert_title="Active Malware Campaign Detected",
        alert_description="Multiple malware detections indicate active campaign",
        alert_category="malware",
        alert_severity="critical",
        mitre_tactics=["Execution"],
        base_score=90,
        tags=["malware", "campaign"],
    )
    rules.append(malware_campaign_rule)

    return rules


def main():
    print("=" * 60)
    print("Custom Rule Creation Example")
    print("=" * 60)

    # Create registry and add custom rules
    registry = RuleRegistry()
    custom_rules = create_custom_rules()

    print("\n[1] Creating custom rules...")
    for rule in custom_rules:
        registry.register(rule)
        print(f"   Added rule: {rule.name} ({rule.rule_type.value})")

    # Initialize engine
    engine = CorrelationEngine(rule_registry=registry)

    # Test DNS exfiltration rule
    print("\n[2] Testing DNS Exfiltration Rule...")
    dns_event = SecurityEvent(
        source=EventSource.DNS,
        event_type=EventType.DNS_QUERY,
        severity=EventSeverity.HIGH,
        src_ip="192.168.1.100",
        description="DNS query for ZmlsZV9jb250ZW50c19lbmNvZGVkX2luX2Jhc2U2NA.exfil.evil.com",
    )
    alerts = engine.process_event(dns_event)
    if alerts:
        print(f"   [!] Alert: {alerts[0].title}")

    # Test malware campaign rule
    print("\n[3] Testing Malware Campaign Rule...")
    for i in range(4):
        event = SecurityEvent(
            source=EventSource.ENDPOINT,
            event_type=EventType.MALWARE_DETECTED,
            severity=EventSeverity.CRITICAL,
            src_host=f"workstation-{i:03d}",
            description=f"Malware detected: Trojan.GenericKD.{i}",
        )
        alerts = engine.process_event(event)
        if alerts:
            print(f"   [!] Alert triggered after {i+1} detections: {alerts[0].title}")

    # Show all alerts
    print("\n[4] All Generated Alerts:")
    print("-" * 60)
    for alert in engine.get_alerts():
        print(f"\n   Alert: {alert.title}")
        print(f"   Rule ID: {alert.rule_id}")
        print(f"   Priority: {alert.priority.value}")
        print(f"   Category: {alert.category.value}")

    # Save custom rules to file
    print("\n[5] Saving rules to file...")
    import yaml
    rules_data = [rule.to_yaml_dict() for rule in custom_rules]
    with open("custom_rules.yaml", "w") as f:
        yaml.dump(rules_data, f, default_flow_style=False)
    print("   Saved to custom_rules.yaml")

    print("\n" + "=" * 60)
    print("Custom rule example completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
