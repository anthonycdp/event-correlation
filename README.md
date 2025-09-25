# Security Event Correlation Engine

A Python-based rule engine for correlating security events from multiple sources, detecting threats through pattern matching, and reducing false positives through intelligent filtering.

## Overview

This Security Event Correlation Engine processes events from various security data sources (firewalls, IDS/IPS, authentication systems, DNS servers, etc.) and applies configurable correlation rules to detect security incidents. The engine supports multiple correlation types including threshold-based detection, sequence matching, and aggregation.

### Key Features

- **Multi-Source Event Parsing**: Flexible parser for firewalls, IDS/IPS, authentication logs, DNS, and more
- **Flexible Rule Engine**: Supports single-event, threshold, sequence, and aggregation rules
- **Alert Prioritization**: Automatic priority calculation based on severity, event count, and threat category
- **False Positive Reduction**: Whitelisting, behavioral baselining, and alert suppression
- **MITRE ATT&CK Integration**: Map detections to tactics and techniques
- **Extensible Architecture**: Easily add new event sources and correlation rules

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Security Event Sources                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ Firewall │ │   IDS    │ │   Auth   │ │   DNS    │ │  Proxy   │      │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘      │
└───────┼────────────┼────────────┼────────────┼────────────┼─────────────┘
        │            │            │            │            │
        ▼            ▼            ▼            ▼            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          Event Parser                                    │
│  • Normalize event formats                                               │
│  • Parse timestamps, IPs, users                                          │
│  • Map to standard SecurityEvent model                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          Event Buffer                                    │
│  • Time-windowed storage                                                 │
│  • Indexed lookups (IP, user, host)                                     │
│  • Sequence tracking                                                     │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Correlation Engine                                  │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     Rule Evaluator                               │   │
│  │  • Condition matching (equals, in, regex, etc.)                  │   │
│  │  • Logical operators (AND, OR)                                   │   │
│  │  • Nested condition groups                                       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     Rule Types                                   │   │
│  │  • Single Event: Match on individual events                      │   │
│  │  • Threshold: Count-based triggers                               │   │
│  │  • Sequence: Ordered event patterns                              │   │
│  │  • Aggregation: Time-windowed grouping                           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   False Positive Reducer                                 │
│  • IP/User/Host whitelisting                                             │
│  • Behavioral baselining                                                 │
│  • Alert suppression (duplicate detection)                               │
│  • Historical pattern learning                                           │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       Alert Generator                                    │
│  • Priority calculation (P1-P5)                                          │
│  • Entity aggregation                                                    │
│  • MITRE ATT&CK mapping                                                  │
│  • Alert lifecycle management                                            │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                         ┌─────────────────┐
                         │     Alerts      │
                         └─────────────────┘
```

## Installation

```bash
# Clone or copy the project
git clone <repository-url>
cd event-correlation

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"
```

## Quick Start

### Python API

```python
from correlation_engine import CorrelationEngine, RuleRegistry
from correlation_engine.models.event import SecurityEvent, EventSource, EventType
from correlation_engine.utils.sample_data import get_default_rules

# Initialize engine
registry = RuleRegistry()
for rule in get_default_rules():
    registry.register(rule)

engine = CorrelationEngine(rule_registry=registry)

# Create and process events
event = SecurityEvent(
    source=EventSource.AUTHENTICATION,
    event_type=EventType.LOGIN_FAILURE,
    src_ip="192.168.1.100",
    dst_port=22,
    severity="high",
    description="Failed SSH login",
)

alerts = engine.process_event(event)

# Check generated alerts
for alert in alerts:
    print(f"Alert: {alert.title}")
    print(f"Priority: {alert.priority.value}")
    print(f"Events: {alert.event_count}")

# Get statistics
stats = engine.get_stats()
print(f"Events processed: {stats['events_processed']}")
print(f"Alerts generated: {stats['alerts_generated']}")
```

### Command Line Interface

```bash
# Process events from a file
sec-correlate process sample_data/sample_events.jsonl --rules sample_data/rules.yaml

# Run a demo with sample events
sec-correlate demo --count 100

# Interactive mode
sec-correlate interactive --rules sample_data/rules.yaml
```

## Event Model

Events are normalized to a standard `SecurityEvent` model:

```python
{
    "event_id": "evt-001",
    "timestamp": "2024-01-15T10:30:00Z",
    "source": "authentication",      # Event source type
    "event_type": "login_failure",   # Specific event type
    "severity": "high",              # low, medium, high, critical
    "src_ip": "192.168.1.100",
    "src_port": 54321,
    "src_user": "admin",
    "dst_ip": "10.0.0.5",
    "dst_port": 22,
    "dst_host": "server-01",
    "description": "Failed login attempt",
    "tags": ["brute_force"],
    "metadata": {}                    # Additional context
}
```

### Supported Event Sources

| Source | Description |
|--------|-------------|
| `firewall` | Network firewall logs |
| `ids_ips` | Intrusion detection/prevention |
| `authentication` | Auth system logs (SSH, RDP, LDAP) |
| `endpoint` | EDR/endpoint security |
| `network_flow` | NetFlow, sFlow |
| `dns` | DNS server logs |
| `proxy` | Web proxy logs |
| `cloud` | Cloud provider logs |
| `email` | Email security logs |

### Event Types

- **Authentication**: `login_success`, `login_failure`, `logout`, `account_lockout`, `mfa_event`
- **Network**: `connection`, `connection_denied`, `port_scan`
- **Security**: `malware_detected`, `intrusion_detected`
- **DNS**: `dns_query`, `dns_tunneling`
- **Endpoint**: `file_access`, `file_modification`, `process_started`

## Rule Definition

Rules are defined in YAML format:

### Single Event Rule

Triggers on a single matching event:

```yaml
- rule_id: mal-001
  name: Malicious IP Communication
  description: Detects communication with known malicious IPs
  enabled: true
  rule_type: single_event
  conditions:
    operator: or
    conditions:
      - field: src_ip
        operator: in
        value:
          - 185.220.101.42
          - 91.121.87.100
  alert:
    title: Malicious IP Communication Detected
    description: Communication with known malicious IP
    category: malware
    severity: critical
    mitre_tactics:
      - Command and Control
    mitre_techniques:
      - T1071
  base_score: 90
  tags:
    - malware
    - threat_intel
```

### Threshold Rule

Triggers when event count exceeds threshold within a time window:

```yaml
- rule_id: bf-001
  name: SSH Brute Force Attack
  description: Detects multiple failed SSH logins
  enabled: true
  rule_type: threshold
  conditions:
    operator: and
    conditions:
      - field: event_type
        operator: equals
        value: login_failure
      - field: dst_port
        operator: equals
        value: 22
  threshold: 5
  time_window_minutes: 5
  alert:
    title: SSH Brute Force Detected
    description: Multiple failed SSH login attempts
    category: brute_force
    severity: high
```

### Sequence Rule

Triggers when events occur in a specific order:

```yaml
- rule_id: lm-001
  name: Lateral Movement Detection
  description: Detects lateral movement patterns
  enabled: true
  rule_type: sequence
  sequence:
    - conditions:
        - field: event_type
          operator: equals
          value: login_success
    - conditions:
        - field: event_type
          operator: equals
          value: connection
        - field: dst_port
          operator: in
          value: [22, 3389, 445]
  sequence_timeout_minutes: 30
  alert:
    title: Potential Lateral Movement
    description: Sequence suggests lateral movement
    category: lateral_movement
    severity: high
```

### Condition Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Exact match | `value: "login_failure"` |
| `not_equals` | Not equal | `value: "login_success"` |
| `in` | Value in list | `value: ["192.168.1.1", "10.0.0.1"]` |
| `not_in` | Value not in list | `value: ["trusted_ip"]` |
| `contains` | String/list contains | `value: "admin"` |
| `regex` | Regular expression | `value: ".*evil\\.com.*"` |
| `greater_than` | Numeric comparison | `value: 100` |
| `less_than` | Numeric comparison | `value: 10` |
| `exists` | Field is not null | `value: null` |
| `not_exists` | Field is null | `value: null` |

## Alert Prioritization

Alerts are automatically prioritized (P1-P5) based on:

1. **Event Severity** (0-30 points)
   - Critical: 30
   - High: 20
   - Medium: 10
   - Low: 5

2. **Event Count** (0-25 points)
   - 100+ events: 25
   - 50-99: 20
   - 20-49: 15
   - 10-19: 10
   - 5-9: 5

3. **Correlation Score** (0-25 points)
   - Based on rule confidence/base_score

4. **Category Risk** (0-20 points)
   - High: account_compromise, malware, data_exfiltration, lateral_movement
   - Medium: brute_force, privilege_escalation, insider_threat

### Priority Levels

| Priority | Score Range | Response Time |
|----------|-------------|---------------|
| P1 Critical | 80+ | Immediate |
| P2 High | 60-79 | Within 1 hour |
| P3 Medium | 40-59 | Within 4 hours |
| P4 Low | 20-39 | Within 24 hours |
| P5 Informational | 0-19 | Reporting only |

## False Positive Reduction

### Whitelisting

```python
from correlation_engine.processors.false_positive_reducer import (
    FalsePositiveReducer,
    WhitelistEntry,
    WhitelistType,
)

reducer = FalsePositiveReducer()

# Whitelist an IP
entry = WhitelistEntry(
    name="trusted_scanner",
    entry_type=WhitelistType.IP,
    value="192.168.1.50",
    description="Authorized vulnerability scanner",
)
reducer.add_whitelist_entry(entry)

# Whitelist a CIDR range
entry = WhitelistEntry(
    name="internal_network",
    entry_type=WhitelistType.IP,
    value="10.0.0.0/8",
)
reducer.add_whitelist_entry(entry)

# Whitelist a user
entry = WhitelistEntry(
    name="service_account",
    entry_type=WhitelistType.USER,
    value="svc_backup",
)
reducer.add_whitelist_entry(entry)
```

### Alert Suppression

Duplicate alerts are automatically suppressed within a configurable time window to prevent alert fatigue:

```python
# Alerts with the same fingerprint are suppressed for 1 hour by default
# Fingerprint is based on: rule_id, category, src_ips, users, hosts
```

## Example Use Cases

### 1. Brute Force Detection

```python
# Events will be processed and when 5+ login failures occur
# from the same IP within 5 minutes, an alert is generated

for i in range(10):
    event = SecurityEvent(
        source=EventSource.AUTHENTICATION,
        event_type=EventType.LOGIN_FAILURE,
        src_ip="185.220.101.42",
        dst_port=22,
        dst_user="admin",
    )
    engine.process_event(event)

# Check for alerts
alerts = engine.get_prioritized_alerts()
```

### 2. Lateral Movement Detection

```python
# Sequence: Login -> Connection to critical port

# First: Successful login
login_event = SecurityEvent(
    source=EventSource.AUTHENTICATION,
    event_type=EventType.LOGIN_SUCCESS,
    src_ip="192.168.1.100",
    src_user="jsmith",
)
engine.process_event(login_event)

# Then: Connection to critical system
conn_event = SecurityEvent(
    source=EventSource.NETWORK_FLOW,
    event_type=EventType.CONNECTION,
    src_ip="192.168.1.100",
    dst_ip="192.168.1.1",
    dst_port=445,
    src_user="jsmith",
)
engine.process_event(conn_event)
```

### 3. Processing Events from File

```python
from correlation_engine.utils.parsers import JSONLReader

reader = JSONLReader()
events = reader.read_file("security_events.jsonl")

alerts = engine.process_events(events)

for alert in engine.get_prioritized_alerts(limit=10):
    print(f"[{alert.priority.value}] {alert.title}")
    print(f"  Source IPs: {', '.join(alert.src_ips)}")
    print(f"  Events: {alert.event_count}")
```

## Project Structure

```
event-correlation/
├── correlation_engine/
│   ├── __init__.py
│   ├── engine.py              # Main correlation engine
│   ├── cli.py                 # Command-line interface
│   ├── models/
│   │   ├── event.py           # SecurityEvent model
│   │   └── alert.py           # Alert model
│   ├── rules/
│   │   ├── rule.py            # Rule model and conditions
│   │   ├── registry.py        # Rule management
│   │   └── evaluator.py       # Rule evaluation logic
│   ├── processors/
│   │   ├── event_buffer.py    # Time-windowed event storage
│   │   └── false_positive_reducer.py
│   └── utils/
│       ├── parsers.py         # Event parsing utilities
│       └── sample_data.py     # Sample data generation
├── sample_data/
│   ├── sample_events.jsonl    # Sample events
│   └── rules.yaml             # Example rules
├── tests/
│   ├── conftest.py
│   ├── test_models.py
│   ├── test_rules.py
│   ├── test_engine.py
│   └── test_parsers.py
├── pyproject.toml
└── README.md
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=correlation_engine --cov-report=html

# Run specific test file
pytest tests/test_engine.py -v
```

## Performance Considerations

- **Event Buffer**: Configurable max size (default: 100,000 events)
- **TTL**: Events are cleaned up after 24 hours by default
- **Indexing**: Fast lookups by IP, user, host, event type
- **Memory**: ~1KB per event in memory

## Extending the Engine

### Adding a New Event Source

```python
# In your parser, map your source to EventSource
from correlation_engine.models.event import EventSource

# Map your source name
source_map = {
    "my_custom_source": EventSource.CUSTOM,
}
```

### Creating Custom Rules

```python
from correlation_engine.rules.rule import (
    CorrelationRule,
    Condition,
    ConditionGroup,
    ConditionOperator,
    RuleType,
)

custom_rule = CorrelationRule(
    rule_id="custom-001",
    name="Custom Detection",
    description="My custom detection rule",
    rule_type=RuleType.SINGLE_EVENT,
    conditions=ConditionGroup(
        conditions=[
            Condition(
                field="metadata.custom_field",
                operator=ConditionOperator.REGEX,
                value=r"pattern.*",
            ),
        ]
    ),
    alert_title="Custom Alert",
    alert_description="Custom rule triggered",
    alert_category="anomaly",
)

registry.register(custom_rule)
```

## MITRE ATT&CK Mapping

The engine supports mapping alerts to MITRE ATT&CK tactics and techniques:

| Category | Example Tactics |
|----------|----------------|
| brute_force | Credential Access (T1110) |
| malware | Execution, Persistence, C2 |
| lateral_movement | Lateral Movement (T1021) |
| data_exfiltration | Exfiltration (T1048) |
| privilege_escalation | Privilege Escalation (T1078) |

## License

MIT License

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request
