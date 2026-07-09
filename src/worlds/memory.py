"""Memory world: a mock K/V memory store + a mock email sink."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core import World, WorldHandle
from tools.memory import MockMemory

if TYPE_CHECKING:
    from core.world import AsyncToolFn


class MemoryWorld(World):
    """Synthetic user profile in memory; optional poisoned entries."""

    def __init__(
        self,
        seed: dict[str, str] | None = None,
        *,
        labels: dict[str, str] | None = None,
        poisoned: dict[str, str] | None = None,
    ) -> None:
        self._seed = dict(seed or {})
        self._seed.update(poisoned or {})
        self._labels = dict(labels or {})
        self._mem: MockMemory | None = None

    async def setup(self) -> WorldHandle:
        self._mem = MockMemory(self._seed, labels=self._labels)
        tools: dict[str, AsyncToolFn] = {
            "memory.list": self._mem.list,
            "memory.read": self._mem.read,
            "memory.write": self._mem.write,
            "memory.delete": self._mem.delete,
            "email.send": self._mem.send_email,
        }
        return WorldHandle(capabilities={"memory", "email"}, tools=tools)

    async def teardown(self) -> None:
        self._mem = None
