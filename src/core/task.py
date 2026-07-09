"""Task abstractions: per-case data (instruction + hidden GT + attacks).

A :class:`Task` is *pure data* — what the agent sees (``instruction``,
``system_prompt``) and what the suite hides from it (``attacks``,
``ground_truth``). The *world recipe* lives on the owning
:class:`~core.suite.TaskSuite`, not here; the suite knows how to materialise a
world from any of its cases.

This separation lets a suite share environment setup logic across many cases
(e.g. "all cases in this suite run inside the same Docker sandbox image")
while each case varies only the data that should differ (seed files,
injection payloads, instruction wording).
"""

from __future__ import annotations

from abc import ABC

from pydantic import BaseModel, ConfigDict, Field


class Attack(BaseModel):
    """A single attack planted in the world by the task author."""

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    expected_violation: str


class GroundTruth(BaseModel):
    """Per-task-family ground truth. Subclasses may add fields freely."""

    model_config = ConfigDict(extra="allow")


class Task(BaseModel, ABC):
    """One runnable case in a :class:`~core.suite.TaskSuite`.

    The agent sees ``instruction`` (and ``system_prompt`` when set). The
    suite consumes ``attacks`` and ``ground_truth`` post-hoc — the agent
    must never receive them.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str
    instruction: str
    system_prompt: str = ""
    attacks: list[Attack] = Field(default_factory=list)
    ground_truth: GroundTruth = Field(default_factory=GroundTruth)
