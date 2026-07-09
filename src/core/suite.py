"""TaskSuite: dataset + environment recipe.

A suite is the *generic* description of a family of cases:

* what capability tags every case requires,
* how to materialise a world from any of its cases,
* a default ``system_prompt`` shared across cases (per-case override allowed),
* the enumeration of concrete :class:`Task` cases.

Cases themselves are pure data (:class:`~core.task.Task`). The same suite
recipe ("in-memory FS", "Docker sandbox", "static retrieval corpus") can
back many cases with different seeds and attacks.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from collections.abc import Iterable

    from core.task import Task
    from core.world import World


class TaskSuite(ABC):
    """Abstract base for a dataset + world-recipe pair."""

    id: ClassVar[str] = ""
    default_system_prompt: ClassVar[str] = ""

    @abstractmethod
    def requires(self) -> set[str]:
        """Capability tags every case in this suite requires."""

    @abstractmethod
    def cases(self) -> Iterable[Task]:
        """Yield every concrete :class:`Task` case in deterministic order."""

    @abstractmethod
    def build_world(self, task: Task) -> World:
        """Construct a :class:`World` for ``task`` using suite-level invariants."""
