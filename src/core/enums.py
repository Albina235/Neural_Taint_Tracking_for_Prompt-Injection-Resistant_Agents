"""Enumerations and capability tag constants used across the core abstractions."""

from __future__ import annotations

from enum import StrEnum


class Hook(StrEnum):
    """Lifecycle hook a scanner attaches to.

    A scanner declares one or more hooks; the runtime invokes it at each
    matching point. ``PRE_TOOL`` and ``POST_TOOL`` are online (can BLOCK);
    ``POST_TURN`` is offline and report-only.
    """

    PRE_TOOL = "pre_tool"
    POST_TOOL = "post_tool"
    POST_TURN = "post_turn"


class StepKind(StrEnum):
    """The kind of a :class:`~core.trace.Step` in a trace."""

    TOOL = "tool"
    ENV = "env"
    MODEL = "model"
    FINAL = "final"


class Verdict(StrEnum):
    """Online runtime verdict for a candidate action."""

    ALLOW = "allow"
    BLOCK = "block"


class Severity(StrEnum):
    """Severity attached to a :class:`~core.scanner.Violation`."""

    INFO = "info"
    WARN = "warn"
    CRITICAL = "critical"


class Capability:
    """Open string tags for capability matching.

    This is intentionally NOT an enum; teams add new capability tags freely.
    A :class:`~core.task.Task` declares the tags it requires; a
    :class:`~core.scaffold.Scaffold` declares the tags it provides.
    """

    RETRIEVE = "retrieve"
    FS = "fs"
    BASH = "bash"
    EXEC = "exec"
    SQL = "sql"
    GATE = "gate"
