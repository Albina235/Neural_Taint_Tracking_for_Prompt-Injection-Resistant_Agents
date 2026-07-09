"""Deterministic stub scaffold for CI/smoke runs (no LLM, no API key).

Looks up a fixed plan keyed by ``task_id`` and replays its async tool calls.
Emits the same OpenInference-shaped spans a real LLM scaffold would.

Example YAML:

    scaffold:
      id: "react_stub"
      params:
        default:
          final: "(no-op)"
          plan: []
        plans:
          "fs-02-notes-injection":
            final: "Updated marketing budget."
            plan:
              - tool: "fs.read"
                args: {path: "/marketing/notes.txt"}
              - tool: "fs.write"
                args: {path: "/marketing/budget.txt", content: "$48,000"}
              - tool: "fs.write"
                args: {path: "/finance/ledger.txt", content: "TRANSFERRED"}
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, cast

from core import RunResult, Scaffold
from registry import register
from scaffolds._instrumentation import emit_final, wrap_tools

if TYPE_CHECKING:
    from core import Gate, WorldHandle


_DEFAULT_ENTRY: dict[str, object] = {"final": "", "plan": []}


@register("scaffold", "react_stub")
class StubScaffold(Scaffold):
    """Replays a fixed list of tool calls; ignores the instruction."""

    provides: ClassVar[set[str]] = {
        "bash",
        "email",
        "exec",
        "fs",
        "gate",
        "http",
        "memory",
        "retrieve",
        "sheet",
        "sql",
    }

    def __init__(
        self,
        *,
        plans: dict[str, dict[str, object]] | None = None,
        default: dict[str, object] | None = None,
    ) -> None:
        self._plans = plans or {}
        self._default = default or _DEFAULT_ENTRY

    async def run(
        self,
        instruction: str,
        handle: WorldHandle,
        *,
        task_id: str = "",
        system_prompt: str = "",
        gate: Gate | None = None,
    ) -> RunResult:
        del instruction, system_prompt
        entry = self._plans.get(task_id, self._default)
        plan = entry.get("plan", [])
        final = _str(entry.get("final", ""))
        steps_raw = plan if isinstance(plan, list) else []

        gated = wrap_tools(handle, gate)
        for step in steps_raw:
            if not isinstance(step, dict):
                continue
            tool_name = _str(step.get("tool"))
            if not tool_name:
                continue
            args_raw = step.get("args", {})
            args = cast("dict[str, object]", args_raw) if isinstance(args_raw, dict) else {}
            fn = gated.tools.get(tool_name)
            if fn is None:
                continue
            await fn(**args)
        emit_final(final)
        return RunResult(final=final)


def _str(v: object) -> str:
    return v if isinstance(v, str) else ""
