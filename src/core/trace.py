"""Thin trace model produced by a :class:`~core.projection.Projection`."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from core.enums import StepKind


class Step(BaseModel):
    """A single event in a trace.

    Agent tool calls, environment observations, model calls, and the final
    output all use this same shape, distinguished by ``kind``.
    """

    model_config = ConfigDict(extra="forbid")

    kind: StepKind
    name: str | None = None
    args: dict[str, object] = Field(default_factory=dict)
    output: str = ""
    span_id: str | None = None
    parent_span_id: str | None = None
    agent: str | None = None
    metadata: dict[str, object] = Field(default_factory=dict)


class Trace(BaseModel):
    """An ordered sequence of :class:`Step` objects for a single run."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = ""
    steps: list[Step] = Field(default_factory=list)

    def tool_steps(self) -> list[Step]:
        """Return all steps where ``kind == StepKind.TOOL``."""
        return [s for s in self.steps if s.kind == StepKind.TOOL]

    def env_steps(self) -> list[Step]:
        """Return all steps where ``kind == StepKind.ENV``."""
        return [s for s in self.steps if s.kind == StepKind.ENV]

    def final(self) -> str:
        """Return the output of the last ``FINAL`` step, or an empty string."""
        for step in reversed(self.steps):
            if step.kind == StepKind.FINAL:
                return step.output
        return ""
