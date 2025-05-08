"""
Correlation Rule Models

Defines the structure for correlation rules that the engine uses
to detect patterns and generate alerts.
"""

from datetime import timedelta
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class RuleType(str, Enum):
    """Types of correlation rules."""

    SINGLE_EVENT = "single_event"  # Match on a single event
    THRESHOLD = "threshold"  # Match when event count exceeds threshold
    SEQUENCE = "sequence"  # Match events in a specific order
    AGGREGATION = "aggregation"  # Aggregate events over time window
    COMPOSITE = "composite"  # Combine multiple rules


class ConditionOperator(str, Enum):
    """Operators for rule conditions."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    REGEX = "regex"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class LogicalOperator(str, Enum):
    """Logical operators for combining conditions."""

    AND = "and"
    OR = "or"


class Condition(BaseModel):
    """A single condition within a rule."""

    field: str  # Event field to check (e.g., "src_ip", "event_type")
    operator: ConditionOperator
    value: Optional[Any] = None  # Value to compare against

    @field_validator("value", mode="before")
    @classmethod
    def validate_value(cls, v: Any, info: Any) -> Any:
        """Ensure value is provided for operators that need it."""
        operator = info.data.get("operator")
        if operator in (
            ConditionOperator.EXISTS,
            ConditionOperator.NOT_EXISTS,
        ):
            return None  # These operators don't need a value
        if v is None:
            raise ValueError(f"Value is required for operator: {operator}")
        return v


class ConditionGroup(BaseModel):
    """A group of conditions with a logical operator."""

    operator: LogicalOperator = LogicalOperator.AND
    conditions: list[Condition] = Field(default_factory=list)
    groups: list["ConditionGroup"] = Field(default_factory=list)  # Nested groups


# Allow recursive model
ConditionGroup.model_rebuild()


class CorrelationRule(BaseModel):
    """
    A correlation rule that defines patterns to detect in security events.

    Rules can be simple (single event match) or complex (multi-event correlation)
    and generate alerts when their conditions are satisfied.
    """

    rule_id: str = Field(default_factory=lambda: str(uuid4())[:8])
    name: str
    description: str
    enabled: bool = True
    rule_type: RuleType = RuleType.SINGLE_EVENT

    # Match conditions
    conditions: ConditionGroup = Field(default_factory=ConditionGroup)

    # For threshold and aggregation rules
    threshold: Optional[int] = None  # Number of events to trigger
    time_window_minutes: int = 60  # Time window for aggregation

    # For sequence rules
    sequence: Optional[list[ConditionGroup]] = None  # Ordered conditions
    sequence_timeout_minutes: int = 60  # Max time for complete sequence

    # Alert generation
    alert_title: str
    alert_description: str
    alert_category: str = "other"
    alert_severity: str = "medium"
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    # Priority scoring
    base_score: int = 50  # 0-100 base score for priority calculation

    # False positive reduction
    whitelist_conditions: Optional[ConditionGroup] = None
    suppression_window_minutes: int = 60  # Suppress duplicate alerts

    # Metadata
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    author: str = "Security Team"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @property
    def time_window(self) -> timedelta:
        """Return time window as timedelta."""
        return timedelta(minutes=self.time_window_minutes)

    @property
    def sequence_timeout(self) -> timedelta:
        """Return sequence timeout as timedelta."""
        return timedelta(minutes=self.sequence_timeout_minutes)

    @property
    def suppression_window(self) -> timedelta:
        """Return suppression window as timedelta."""
        return timedelta(minutes=self.suppression_window_minutes)

    def to_yaml_dict(self) -> dict[str, Any]:
        """Convert rule to a YAML-friendly dictionary."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "rule_type": self.rule_type.value,
            "conditions": self.conditions.model_dump(),
            "threshold": self.threshold,
            "time_window_minutes": self.time_window_minutes,
            "sequence": [s.model_dump() for s in self.sequence] if self.sequence else None,
            "sequence_timeout_minutes": self.sequence_timeout_minutes,
            "alert": {
                "title": self.alert_title,
                "description": self.alert_description,
                "category": self.alert_category,
                "severity": self.alert_severity,
                "mitre_tactics": self.mitre_tactics,
                "mitre_techniques": self.mitre_techniques,
            },
            "base_score": self.base_score,
            "whitelist_conditions": (
                self.whitelist_conditions.model_dump() if self.whitelist_conditions else None
            ),
            "suppression_window_minutes": self.suppression_window_minutes,
            "tags": self.tags,
            "references": self.references,
            "author": self.author,
        }

    @classmethod
    def from_yaml_dict(cls, data: dict[str, Any]) -> "CorrelationRule":
        """Create rule from YAML dictionary."""
        # Handle alert fields
        alert_data = data.pop("alert", {})
        data["alert_title"] = alert_data.get("title", "Security Alert")
        data["alert_description"] = alert_data.get("description", "")
        data["alert_category"] = alert_data.get("category", "other")
        data["alert_severity"] = alert_data.get("severity", "medium")
        data["mitre_tactics"] = alert_data.get("mitre_tactics", [])
        data["mitre_techniques"] = alert_data.get("mitre_techniques", [])

        # Handle rule_type
        if isinstance(data.get("rule_type"), str):
            data["rule_type"] = RuleType(data["rule_type"])

        # Handle conditions
        if "conditions" in data and isinstance(data["conditions"], dict):
            data["conditions"] = ConditionGroup(**data["conditions"])

        # Handle sequence
        if "sequence" in data and data["sequence"]:
            data["sequence"] = [ConditionGroup(**s) for s in data["sequence"]]

        # Handle whitelist_conditions
        if "whitelist_conditions" in data and data["whitelist_conditions"]:
            data["whitelist_conditions"] = ConditionGroup(**data["whitelist_conditions"])

        return cls(**data)
