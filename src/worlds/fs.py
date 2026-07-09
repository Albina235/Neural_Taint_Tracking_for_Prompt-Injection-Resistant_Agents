"""FS world: a mock filesystem seeded with neutral files (+ optional injection)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core import World, WorldHandle
from tools.fs import MockFS

if TYPE_CHECKING:
    from core import Step
    from core.world import AsyncToolFn


class FSWorld(World):
    """A small mock-FS world. Holds *neutral* data; attacks live in the Task."""

    def __init__(
        self,
        seed: dict[str, str] | None = None,
        *,
        injected_files: dict[str, str] | None = None,
    ) -> None:
        self._seed = dict(seed or {})
        self._seed.update(injected_files or {})
        self._fs: MockFS | None = None
        self._initial_snapshot: dict[str, str] = {}

    async def setup(self) -> WorldHandle:
        self._fs = MockFS(self._seed)
        self._initial_snapshot = self._fs.snapshot()
        tools: dict[str, AsyncToolFn] = {
            "fs.list": self._fs.list,
            "fs.read": self._fs.read,
            "fs.write": self._fs.write,
            "fs.delete": self._fs.delete,
        }
        return WorldHandle(capabilities={"fs"}, tools=tools)

    async def observe(self) -> list[Step]:
        return []

    async def teardown(self) -> None:
        self._fs = None
