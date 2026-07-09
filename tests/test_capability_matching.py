"""Capability-matching contract: ``runnable`` enforces ``suite.requires <= provides``."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from core import (
    RunResult,
    Scaffold,
    Task,
    TaskSuite,
    World,
    WorldHandle,
    runnable,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from core import Gate


class _NullWorld(World):
    async def setup(self) -> WorldHandle:
        return WorldHandle(capabilities=set())

    async def teardown(self) -> None:
        return None


class _RetrieveCase(Task):
    pass


class _RetrieveSuite(TaskSuite):
    id: ClassVar[str] = "_test_retrieve_suite"

    def requires(self) -> set[str]:
        return {"retrieve"}

    def cases(self) -> Iterable[Task]:
        return [_RetrieveCase(id="t1", instruction="find X")]

    def build_world(self, task: Task) -> World:
        del task
        return _NullWorld()


class _RichScaffold(Scaffold):
    provides: ClassVar[set[str]] = {"retrieve", "exec"}

    async def run(
        self,
        instruction: str,
        handle: WorldHandle,
        *,
        task_id: str = "",
        system_prompt: str = "",
        gate: Gate | None = None,
    ) -> RunResult:
        del instruction, handle, task_id, system_prompt, gate
        return RunResult()


class _PoorScaffold(Scaffold):
    provides: ClassVar[set[str]] = {"exec"}

    async def run(
        self,
        instruction: str,
        handle: WorldHandle,
        *,
        task_id: str = "",
        system_prompt: str = "",
        gate: Gate | None = None,
    ) -> RunResult:
        del instruction, handle, task_id, system_prompt, gate
        return RunResult()


def test_runnable_when_provides_superset() -> None:
    assert runnable(_RetrieveSuite(), _RichScaffold()) is True


def test_not_runnable_when_capability_missing() -> None:
    assert runnable(_RetrieveSuite(), _PoorScaffold()) is False


def test_suite_yields_cases() -> None:
    suite = _RetrieveSuite()
    cases = list(suite.cases())
    assert [c.id for c in cases] == ["t1"]
