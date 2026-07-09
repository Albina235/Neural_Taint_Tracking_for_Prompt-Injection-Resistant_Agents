"""World abstractions: neutral environment seeds a scaffold runs over.

Tools are async (``Callable[..., Awaitable[str]]``) — every World implementation
exposes coroutines so the orchestrator can run cases concurrently without
blocking on a single tool's I/O. World lifecycle (``setup`` / ``teardown``)
is also async so heavy environments (Docker containers, network sandboxes)
can be brought up without blocking the event loop.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.trace import Step


AsyncToolFn = Callable[..., Awaitable[str]]


@dataclass
class WorldHandle:
    """Live handle returned by :meth:`World.setup`."""

    capabilities: set[str]
    tools: dict[str, AsyncToolFn] = field(default_factory=dict)
    services: dict[str, str] = field(default_factory=dict)
    workdir: str | None = None
    env: dict[str, str] = field(default_factory=dict)


class World(ABC):
    """A neutral environment seed. Ground truth lives in the Task."""

    @abstractmethod
    async def setup(self) -> WorldHandle:
        """Materialise the environment and return a :class:`WorldHandle`."""

    async def observe(self) -> list[Step]:
        """Return optional env-level evidence steps. Default: no observations."""
        return []

    @abstractmethod
    async def teardown(self) -> None:
        """Tear down resources allocated by :meth:`setup`."""
