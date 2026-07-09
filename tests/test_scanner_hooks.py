"""Scanner hook contract: hooks select which runtime invokes a scanner."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core import (
    Gate,
    Hook,
    Monitor,
    Scanner,
    Trace,
    Violation,
)

if TYPE_CHECKING:
    from core import ScanContext


class AlwaysBlock(Scanner):
    id = "always_block"
    hooks = frozenset({Hook.PRE_TOOL})

    def evaluate(self, ctx: ScanContext) -> list[Violation]:
        del ctx
        return [Violation(type="blocked")]


class PostTurnNoop(Scanner):
    id = "post_turn_noop"
    hooks = frozenset({Hook.POST_TURN})

    def evaluate(self, ctx: ScanContext) -> list[Violation]:
        del ctx
        return [Violation(type="seen_post_turn")]


class PostToolBlock(Scanner):
    id = "post_tool_block"
    hooks = frozenset({Hook.POST_TOOL})

    def evaluate(self, ctx: ScanContext) -> list[Violation]:
        del ctx
        return [Violation(type="bad_result")]


def test_pre_tool_blocks() -> None:
    gate = Gate([AlwaysBlock()])
    assert gate.before_tool("exec", {"command": "x"}).allow is False


def test_monitor_ignores_pre_tool_only_scanner() -> None:
    assert Monitor([AlwaysBlock()]).scan(Trace()) == []


def test_gate_ignores_post_turn_only_scanner() -> None:
    gate = Gate([PostTurnNoop()])
    assert gate.before_tool("exec", {"command": "x"}).allow is True
    assert gate.after_tool("exec", {"command": "x"}, "ok").allow is True


def test_monitor_runs_post_turn_scanner() -> None:
    violations = Monitor([PostTurnNoop()]).scan(Trace())
    assert [v.type for v in violations] == ["seen_post_turn"]


def test_post_tool_blocks_on_result() -> None:
    gate = Gate([PostToolBlock()])
    assert gate.before_tool("exec", {"command": "x"}).allow is True
    assert gate.after_tool("exec", {"command": "x"}, "leaked").allow is False
