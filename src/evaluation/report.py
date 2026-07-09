"""Render Markdown: one report per case + one aggregate across cases."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from configs import RunConfig
    from core import Task, Trace, Violation
    from evaluation.orchestrator import CaseOutcome


def render_case_markdown(
    cfg: RunConfig,
    cfg_hash: str,
    case: Task,
    trace: Trace,
    violations: list[Violation],
) -> str:
    lines: list[str] = []
    lines.append(f"# Case report — {case.id}")
    lines.append("")
    lines.append(f"- **run:** `{cfg.run.id}`  •  **config_hash:** `{cfg_hash}`")
    lines.append(f"- **suite:** `{cfg.suite.id}`  •  **scaffold:** `{cfg.scaffold.id}`")
    lines.append(f"- **scanners:** {[s.id for s in cfg.scanners]}")
    lines.append("")

    lines.append("## Instruction")
    lines.append(f"> {_oneline(case.instruction, limit=400)}")
    lines.append("")

    lines.append("## Trace summary")
    lines.append(f"- total steps: **{len(trace.steps)}**")
    lines.append(f"- tool calls: **{len(trace.tool_steps())}**")
    lines.append(f"- env observations: **{len(trace.env_steps())}**")
    final = trace.final()
    if final:
        lines.append(f"- final answer: `{_oneline(final)}`")
    lines.append("")

    lines.append("## Violations")
    if not violations:
        lines.append("_None._")
    else:
        lines.append("| type | severity | detail |")
        lines.append("|------|----------|--------|")
        for v in violations:
            lines.append(f"| `{v.type}` | {v.severity.value} | {_oneline(v.detail)} |")
    lines.append("")

    lines.append("## Sensitivity (attack → caught?)")
    if not case.attacks:
        lines.append("_No attacks declared in this case._")
    else:
        caught_types = {v.type for v in violations}
        lines.append("| attack id | kind | expected violation | caught |")
        lines.append("|-----------|------|--------------------|--------|")
        for a in case.attacks:
            mark = "yes" if a.expected_violation in caught_types else "no"
            lines.append(f"| `{a.id}` | {a.kind} | `{a.expected_violation}` | **{mark}** |")
    lines.append("")

    lines.append("## Tool calls")
    if not trace.tool_steps():
        lines.append("_None._")
    else:
        for i, s in enumerate(trace.tool_steps(), 1):
            lines.append(
                f"{i}. `{s.name}` args=`{_oneline(str(s.args))}` output=`{_oneline(s.output)}`"
            )
    lines.append("")
    return "\n".join(lines)


def render_aggregate_markdown(
    cfg: RunConfig,
    cfg_hash: str,
    outcomes: list[CaseOutcome],
) -> str:
    lines: list[str] = []
    lines.append(f"# Run report — {cfg.run.id}")
    lines.append("")
    lines.append(f"- **config_hash:** `{cfg_hash}`")
    lines.append(f"- **suite:** `{cfg.suite.id}`  •  **scaffold:** `{cfg.scaffold.id}`")
    lines.append(f"- **scanners:** {[s.id for s in cfg.scanners]}")
    lines.append(f"- **cases:** {len(outcomes)}")
    lines.append("")

    lines.append("## Per-case summary")
    lines.append("| case_id | violations | by severity | report |")
    lines.append("|---------|-----------:|-------------|--------|")
    for o in outcomes:
        by_sev: dict[str, int] = {}
        for v in o.violations:
            by_sev[v.severity.value] = by_sev.get(v.severity.value, 0) + 1
        sev_text = ", ".join(f"{k}: {n}" for k, n in sorted(by_sev.items())) or "—"
        rel = f"cases/{o.case_id}/report.md"
        lines.append(f"| `{o.case_id}` | {len(o.violations)} | {sev_text} | [↗]({rel}) |")
    lines.append("")

    lines.append("## Totals")
    total = sum(len(o.violations) for o in outcomes)
    cases_with_findings = sum(1 for o in outcomes if o.violations)
    lines.append(f"- total violations: **{total}**")
    lines.append(f"- cases with ≥1 violation: **{cases_with_findings}** / {len(outcomes)}")
    lines.append("")
    return "\n".join(lines)


def _oneline(s: str, limit: int = 140) -> str:
    out = s.replace("\n", " ").strip()
    if len(out) > limit:
        out = out[: limit - 1] + "…"
    return out
