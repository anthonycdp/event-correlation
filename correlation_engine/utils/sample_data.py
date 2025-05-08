"""
Sample Data Generator

Generates realistic security events for testing and demonstration.
"""

import random
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

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


# Sample data for realistic event generation
INTERNAL_IPS = [
    "192.168.1.10",
    "192.168.1.50",
    "192.168.1.100",
    "192.168.1.150",
    "10.0.0.5",
    "10.0.0.10",
    "10.0.0.20",
    "172.16.0.5",
    "172.16.0.10",
]

EXTERNAL_IPS = [
    "45.33.32.156",
    "185.220.101.1",
    "91.121.87.18",
    "178.62.33.12",
    "104.248.50.49",
    "159.65.200.100",
    "167.99.50.31",
    "139.59.170.200",
]

MALICIOUS_IPS = [
    "185.220.101.42",  # Known Tor exit node
    "91.121.87.100",   # Known malicious
    "45.155.205.233",  # Suspicious
    "193.32.162.89",   # Known C2
]

USERS = [
    "admin",
    "jsmith",
    "mwilson",
    "tjohnson",
    "agarcia",
    "slee",
    "kpatel",
    "service_account",
    "backup_user",
    "svc_sql",
]

HOSTS = [
    "web-server-01",
    "db-server-01",
    "app-server-01",
    "file-server-01",
    "dc-01",
    "dc-02",
    "workstation-001",
    "workstation-002",
    "workstation-003",
    "mail-server-01",
]

DESTINATION_PORTS = {
    "ssh": 22,
    "http": 80,
    "https": 443,
    "rdp": 3389,
    "smb": 445,
    "dns": 53,
    "ftp": 21,
    "mysql": 3306,
    "mssql": 1433,
    "rdp_alt": 3390,
}


def generate_sample_events(count: int = 50) -> list[SecurityEvent]:
    """
    Generate a variety of sample security events.

    Includes normal traffic, suspicious activity, and attack patterns.
    """
    events = []
    base_time = datetime.now(timezone.utc) - timedelta(hours=1)

    # 1. Generate brute force attack pattern (10-15% of events)
    brute_force_count = random.randint(int(count * 0.10), int(count * 0.15))
    events.extend(_generate_brute_force_events(base_time, brute_force_count))

    # 2. Generate port scan events (5-10%)
    port_scan_count = random.randint(int(count * 0.05), int(count * 0.10))
    events.extend(_generate_port_scan_events(base_time + timedelta(minutes=5), port_scan_count))

    # 3. Generate normal authentication events (40-50%)
    auth_count = random.randint(int(count * 0.40), int(count * 0.50))
    events.extend(_generate_auth_events(base_time, auth_count))

    # 4. Generate firewall events (20-30%)
    fw_count = random.randint(int(count * 0.20), int(count * 0.30))
    events.extend(_generate_firewall_events(base_time, fw_count))

    # 5. Generate DNS events (5-10%)
    dns_count = random.randint(int(count * 0.05), int(count * 0.10))
    events.extend(_generate_dns_events(base_time, dns_count))

    # 6. Generate lateral movement indicators (1-3 events)
    events.extend(_generate_lateral_movement_events(base_time + timedelta(minutes=30)))

    # Sort by timestamp
    events.sort(key=lambda e: e.timestamp)

    return events[:count]


def _generate_brute_force_events(
    base_time: datetime, count: int
) -> list[SecurityEvent]:
    """Generate a brute force attack pattern."""
    events = []
    attacker_ip = random.choice(MALICIOUS_IPS)
    target_user = random.choice(["admin", "root", "administrator"])
    target_host = random.choice(HOSTS[:5])  # Critical systems

    for i in range(count):
        # Space events closely together (burst pattern)
        timestamp = base_time + timedelta(seconds=random.randint(1, 60))

        event = SecurityEvent(
            timestamp=timestamp,
            source=EventSource.AUTHENTICATION,
            event_type=EventType.LOGIN_FAILURE,
            severity=EventSeverity.MEDIUM,
            src_ip=attacker_ip,
            src_port=random.randint(40000, 65000),
            src_host=None,
            src_user=None,
            dst_ip="192.168.1.1",
            dst_port=22,
            dst_host=target_host,
            dst_user=target_user,
            description=f"Failed SSH login attempt for user '{target_user}' from {attacker_ip}",
            tags=["brute_force", "ssh"],
            metadata={"attempt_number": i + 1, "protocol": "ssh"},
        )
        events.append(event)
        base_time = timestamp

    return events


def _generate_port_scan_events(
    base_time: datetime, count: int
) -> list[SecurityEvent]:
    """Generate port scanning events."""
    events = []
    scanner_ip = random.choice(MALICIOUS_IPS)
    target_ip = random.choice(INTERNAL_IPS)

    ports_to_scan = random.sample(list(DESTINATION_PORTS.values()), min(count, 10))

    for port in ports_to_scan:
        timestamp = base_time + timedelta(milliseconds=random.randint(100, 500))

        event = SecurityEvent(
            timestamp=timestamp,
            source=EventSource.FIREWALL,
            event_type=EventType.PORT_SCAN,
            severity=EventSeverity.HIGH,
            src_ip=scanner_ip,
            src_port=random.randint(40000, 65000),
            dst_ip=target_ip,
            dst_port=port,
            description=f"Port scan detected: {scanner_ip} -> {target_ip}:{port}",
            tags=["reconnaissance", "port_scan"],
            metadata={"scan_type": "sequential"},
        )
        events.append(event)
        base_time = timestamp

    return events


def _generate_auth_events(base_time: datetime, count: int) -> list[SecurityEvent]:
    """Generate normal authentication events."""
    events = []

    for _ in range(count):
        timestamp = base_time + timedelta(minutes=random.randint(0, 59))
        user = random.choice(USERS)
        src_ip = random.choice(INTERNAL_IPS[:5])  # Workstation IPs
        dst_host = random.choice(HOSTS)

        # 80% success, 20% failure for normal events
        if random.random() < 0.8:
            event_type = EventType.LOGIN_SUCCESS
            severity = EventSeverity.LOW
            description = f"Successful login for user '{user}' from {src_ip}"
        else:
            event_type = EventType.LOGIN_FAILURE
            severity = EventSeverity.LOW
            description = f"Failed login for user '{user}' from {src_ip} (wrong password)"

        event = SecurityEvent(
            timestamp=timestamp,
            source=EventSource.AUTHENTICATION,
            event_type=event_type,
            severity=severity,
            src_ip=src_ip,
            src_port=random.randint(40000, 65000),
            dst_host=dst_host,
            dst_user=user,
            description=description,
            tags=["authentication"],
        )
        events.append(event)

    return events


def _generate_firewall_events(base_time: datetime, count: int) -> list[SecurityEvent]:
    """Generate firewall connection events."""
    events = []

    for _ in range(count):
        timestamp = base_time + timedelta(seconds=random.randint(0, 3600))

        # Mix of internal->external and external->internal
        if random.random() < 0.7:
            src_ip = random.choice(INTERNAL_IPS)
            dst_ip = random.choice(EXTERNAL_IPS)
        else:
            src_ip = random.choice(EXTERNAL_IPS)
            dst_ip = random.choice(INTERNAL_IPS)

        dst_port = random.choice(list(DESTINATION_PORTS.values()))

        # Most connections allowed, some blocked
        if random.random() < 0.9:
            event_type = EventType.CONNECTION
            severity = EventSeverity.LOW
            description = f"Connection allowed: {src_ip} -> {dst_ip}:{dst_port}"
        else:
            event_type = EventType.CONNECTION_DENIED
            severity = EventSeverity.MEDIUM
            description = f"Connection blocked: {src_ip} -> {dst_ip}:{dst_port} (policy violation)"

        event = SecurityEvent(
            timestamp=timestamp,
            source=EventSource.FIREWALL,
            event_type=event_type,
            severity=severity,
            src_ip=src_ip,
            src_port=random.randint(40000, 65000),
            dst_ip=dst_ip,
            dst_port=dst_port,
            description=description,
            tags=["firewall", "network"],
        )
        events.append(event)

    return events


def _generate_dns_events(base_time: datetime, count: int) -> list[SecurityEvent]:
    """Generate DNS query events."""
    events = []
    suspicious_domains = [
        "malware-c2.evil.com",
        "data-exfil.attacker.net",
        "phishing-site.bad.org",
    ]
    normal_domains = [
        "google.com",
        "microsoft.com",
        "github.com",
        "amazonaws.com",
        "office365.com",
    ]

    for _ in range(count):
        timestamp = base_time + timedelta(seconds=random.randint(0, 3600))

        # 20% suspicious domains
        if random.random() < 0.2:
            domain = random.choice(suspicious_domains)
            severity = EventSeverity.HIGH
            src_ip = random.choice(INTERNAL_IPS)
        else:
            domain = random.choice(normal_domains)
            severity = EventSeverity.LOW
            src_ip = random.choice(INTERNAL_IPS)

        event = SecurityEvent(
            timestamp=timestamp,
            source=EventSource.DNS,
            event_type=EventType.DNS_QUERY,
            severity=severity,
            src_ip=src_ip,
            dst_ip="8.8.8.8",
            dst_port=53,
            description=f"DNS query for {domain}",
            tags=["dns"],
            metadata={"domain": domain, "query_type": "A"},
        )
        events.append(event)

    return events


def _generate_lateral_movement_events(base_time: datetime) -> list[SecurityEvent]:
    """Generate lateral movement indicators."""
    events = []

    # Simulate attacker moving from compromised host to others
    compromised_host = INTERNAL_IPS[2]  # 192.168.1.100
    attacker_user = "jsmith"  # Compromised account

    targets = [
        ("192.168.1.1", 445, "smb"),  # DC via SMB
        ("192.168.1.50", 3389, "rdp"),  # Server via RDP
        ("10.0.0.5", 22, "ssh"),  # DB server via SSH
    ]

    for target_ip, target_port, protocol in targets:
        timestamp = base_time + timedelta(minutes=random.randint(1, 10))

        event = SecurityEvent(
            timestamp=timestamp,
            source=EventSource.NETWORK_FLOW,
            event_type=EventType.CONNECTION,
            severity=EventSeverity.HIGH,
            src_ip=compromised_host,
            src_port=random.randint(40000, 65000),
            dst_ip=target_ip,
            dst_port=target_port,
            src_user=attacker_user,
            description=f"Internal connection: {compromised_host} -> {target_ip}:{target_port} ({protocol})",
            tags=["lateral_movement", protocol],
            metadata={"protocol": protocol},
        )
        events.append(event)

    return events


def get_default_rules() -> list[CorrelationRule]:
    """Get default correlation rules."""
    rules = []

    # Rule 1: Brute Force Detection
    brute_force_rule = CorrelationRule(
        rule_id="bf-001",
        name="SSH Brute Force Attack",
        description="Detects multiple failed SSH login attempts from the same source",
        enabled=True,
        rule_type=RuleType.THRESHOLD,
        conditions=ConditionGroup(
            operator=LogicalOperator.AND,
            conditions=[
                Condition(
                    field="event_type",
                    operator=ConditionOperator.EQUALS,
                    value="login_failure",
                ),
                Condition(
                    field="dst_port",
                    operator=ConditionOperator.EQUALS,
                    value=22,
                ),
            ],
        ),
        threshold=5,
        time_window_minutes=5,
        alert_title="SSH Brute Force Attack Detected",
        alert_description="Multiple failed SSH login attempts detected from the same source IP",
        alert_category="brute_force",
        alert_severity="high",
        mitre_tactics=["Credential Access"],
        mitre_techniques=["T1110.001"],
        base_score=70,
        tags=["brute_force", "ssh", "authentication"],
    )
    rules.append(brute_force_rule)

    # Rule 2: Port Scan Detection
    port_scan_rule = CorrelationRule(
        rule_id="ps-001",
        name="Port Scan Detection",
        description="Detects sequential port scanning activity",
        enabled=True,
        rule_type=RuleType.THRESHOLD,
        conditions=ConditionGroup(
            operator=LogicalOperator.AND,
            conditions=[
                Condition(
                    field="event_type",
                    operator=ConditionOperator.EQUALS,
                    value="port_scan",
                ),
            ],
        ),
        threshold=5,
        time_window_minutes=5,
        alert_title="Port Scan Activity Detected",
        alert_description="Sequential port scanning detected from external source",
        alert_category="external_attack",
        alert_severity="high",
        mitre_tactics=["Reconnaissance"],
        mitre_techniques=["T1046"],
        base_score=60,
        tags=["reconnaissance", "port_scan"],
    )
    rules.append(port_scan_rule)

    # Rule 3: Malware Communication
    malware_rule = CorrelationRule(
        rule_id="mal-001",
        name="Malware C2 Communication",
        description="Detects communication with known malicious IPs",
        enabled=True,
        rule_type=RuleType.SINGLE_EVENT,
        conditions=ConditionGroup(
            operator=LogicalOperator.OR,
            conditions=[
                Condition(
                    field="src_ip",
                    operator=ConditionOperator.IN,
                    value=MALICIOUS_IPS,
                ),
                Condition(
                    field="dst_ip",
                    operator=ConditionOperator.IN,
                    value=MALICIOUS_IPS,
                ),
            ],
        ),
        alert_title="Communication with Malicious IP Detected",
        alert_description="Network communication with a known malicious IP address was detected",
        alert_category="malware",
        alert_severity="critical",
        mitre_tactics=["Command and Control"],
        mitre_techniques=["T1071"],
        base_score=90,
        tags=["malware", "c2", "threat_intel"],
    )
    rules.append(malware_rule)

    # Rule 4: Lateral Movement Sequence
    lateral_movement_rule = CorrelationRule(
        rule_id="lm-001",
        name="Lateral Movement Detection",
        description="Detects lateral movement through internal network",
        enabled=True,
        rule_type=RuleType.SEQUENCE,
        conditions=ConditionGroup(
            conditions=[
                Condition(field="src_ip", operator=ConditionOperator.EXISTS, value=None),
            ],
        ),
        sequence=[
            # Step 1: Login success
            ConditionGroup(
                conditions=[
                    Condition(
                        field="event_type",
                        operator=ConditionOperator.EQUALS,
                        value="login_success",
                    ),
                ],
            ),
            # Step 2: Connection to critical system
            ConditionGroup(
                conditions=[
                    Condition(
                        field="event_type",
                        operator=ConditionOperator.EQUALS,
                        value="connection",
                    ),
                    Condition(
                        field="dst_port",
                        operator=ConditionOperator.IN,
                        value=[22, 3389, 445, 135],
                    ),
                ],
            ),
        ],
        sequence_timeout_minutes=30,
        alert_title="Potential Lateral Movement Detected",
        alert_description="Sequence of events suggests lateral movement within the network",
        alert_category="lateral_movement",
        alert_severity="high",
        mitre_tactics=["Lateral Movement"],
        mitre_techniques=["T1021"],
        base_score=80,
        tags=["lateral_movement", "insider_threat"],
    )
    rules.append(lateral_movement_rule)

    # Rule 5: DNS Exfiltration
    dns_rule = CorrelationRule(
        rule_id="dns-001",
        name="Suspicious DNS Query",
        description="Detects DNS queries to suspicious domains",
        enabled=True,
        rule_type=RuleType.SINGLE_EVENT,
        conditions=ConditionGroup(
            operator=LogicalOperator.OR,
            conditions=[
                Condition(
                    field="metadata.domain",
                    operator=ConditionOperator.REGEX,
                    value=r".*(evil|malware|c2|exfil|attacker).*",
                ),
            ],
        ),
        alert_title="Suspicious DNS Query Detected",
        alert_description="DNS query to a potentially malicious domain was detected",
        alert_category="data_exfiltration",
        alert_severity="high",
        mitre_tactics=["Exfiltration", "Command and Control"],
        mitre_techniques=["T1048.003", "T1071.004"],
        base_score=75,
        tags=["dns", "exfiltration", "c2"],
    )
    rules.append(dns_rule)

    # Rule 6: Account Lockout
    lockout_rule = CorrelationRule(
        rule_id="lock-001",
        name="Account Lockout",
        description="Detects account lockout events",
        enabled=True,
        rule_type=RuleType.SINGLE_EVENT,
        conditions=ConditionGroup(
            conditions=[
                Condition(
                    field="event_type",
                    operator=ConditionOperator.EQUALS,
                    value="account_lockout",
                ),
            ],
        ),
        alert_title="Account Lockout Detected",
        alert_description="An account has been locked out, possibly due to brute force attack",
        alert_category="brute_force",
        alert_severity="medium",
        mitre_tactics=["Credential Access"],
        mitre_techniques=["T1110"],
        base_score=50,
        tags=["account", "lockout", "authentication"],
    )
    rules.append(lockout_rule)

    return rules


def generate_sample_data_file(filepath: str, event_count: int = 100) -> None:
    """Generate a sample data file with events."""
    import json

    events = generate_sample_events(event_count)

    with open(filepath, "w") as f:
        for event in events:
            f.write(event.model_dump_json() + "\n")


def generate_sample_rules_file(filepath: str) -> None:
    """Generate a sample rules YAML file."""
    import yaml

    rules = get_default_rules()
    data = [rule.to_yaml_dict() for rule in rules]

    with open(filepath, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
