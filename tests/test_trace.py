"""Trace contract: ``tool_steps`` / ``env_steps`` / ``final`` return subsets."""

from __future__ import annotations

from core import Step, StepKind, Trace


def _make_trace() -> Trace:
    return Trace(
        task_id="t1",
        steps=[
            Step(kind=StepKind.MODEL, name="llm"),
            Step(kind=StepKind.TOOL, name="search", output="hit"),
            Step(kind=StepKind.ENV, name="fs_diff", output="+a.txt"),
            Step(kind=StepKind.TOOL, name="read", output="contents"),
            Step(kind=StepKind.FINAL, output="answer"),
        ],
    )


def test_tool_steps_returns_only_tool_kind() -> None:
    trace = _make_trace()
    names = [s.name for s in trace.tool_steps()]
    assert names == ["search", "read"]


def test_env_steps_returns_only_env_kind() -> None:
    trace = _make_trace()
    names = [s.name for s in trace.env_steps()]
    assert names == ["fs_diff"]


def test_final_returns_last_final_output() -> None:
    trace = _make_trace()
    assert trace.final() == "answer"


def test_final_empty_when_no_final_step() -> None:
    trace = Trace(steps=[Step(kind=StepKind.TOOL, name="x")])
    assert trace.final() == ""
