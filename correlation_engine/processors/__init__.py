"""Processors package for the correlation engine."""

from correlation_engine.processors.event_buffer import EventBuffer
from correlation_engine.processors.false_positive_reducer import (
    FalsePositiveReducer,
    WhitelistEntry,
    WhitelistType,
)

__all__ = [
    "EventBuffer",
    "FalsePositiveReducer",
    "WhitelistEntry",
    "WhitelistType",
]
