"""Trustworthy-eval harness core abstractions.

This package depends only on ``pydantic`` + stdlib. Sibling packages
(``projections``, ``scaffolds``, ...) own heavier dependencies like OTel and
LangGraph; do NOT import them from ``core``.
"""

from __future__ import annotations

from core.enums import Capability, Hook, Severity, StepKind, Verdict
from core.projection import Projection
from core.report import Report
from core.runtime import Gate, Monitor
from core.scaffold import RunResult, Scaffold, runnable
from core.scanner import Decision, ScanContext, Scanner, Violation
from core.store import TraceStore
from core.suite import TaskSuite
from core.task import Attack, GroundTruth, Task
from core.trace import Step, Trace
from core.trust import TrustPolicy
from core.world import World, WorldHandle

__all__ = [
    "Attack",
    "Capability",
    "Decision",
    "Gate",
    "GroundTruth",
    "Hook",
    "Monitor",
    "Projection",
    "Report",
    "RunResult",
    "Scaffold",
    "ScanContext",
    "Scanner",
    "Severity",
    "Step",
    "StepKind",
    "Task",
    "TaskSuite",
    "Trace",
    "TraceStore",
    "TrustPolicy",
    "Verdict",
    "Violation",
    "World",
    "WorldHandle",
    "runnable",
]
