"""Scaffold abstractions: the agent runtime that drives a world."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from core.runtime import Gate
    from core.suite import TaskSuite
    from core.world import WorldHandle


class RunResult(BaseModel):
    """Result of a scaffold run.

    Spans are captured out-of-band via the OTLP exporter and consumed by a
    :class:`~core.projection.Projection`; this struct only carries the final
    output.
    """

    model_config = ConfigDict(extra="forbid")

    final: str = ""


class Scaffold(ABC):
    """An agent runtime that satisfies a capability contract.

    Subclasses override :attr:`provides` with the capability tags they
    support and implement :meth:`run`.
    """

    provides: ClassVar[set[str]] = set()

    @abstractmethod
    async def run(
        self,
        instruction: str,
        handle: WorldHandle,
        *,
        task_id: str = "",
        system_prompt: str = "",
        gate: Gate | None = None,
    ) -> RunResult:
        """Execute ``instruction`` against ``handle``.

        ``task_id`` is a non-secret hint identifying the concrete case in the
        suite; deterministic scaffolds (stubs, replayers) key off it. Real
        agents should ignore it — they must act only on ``instruction`` and
        ``system_prompt``.

        ``system_prompt`` is the framing the agent operates under. Empty
        string means "use the scaffold's neutral default".
        """


def runnable(suite: TaskSuite, scaffold: Scaffold) -> bool:
    """Return True iff every capability ``suite`` requires is provided."""
    return suite.requires() <= scaffold.provides
