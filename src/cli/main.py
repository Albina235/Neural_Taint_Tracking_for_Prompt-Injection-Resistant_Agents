"""``taicf`` CLI: ``run``, ``score``, ``smoke``."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer

from configs import load_config
from evaluation import run as run_eval
from evaluation import score as score_run

if TYPE_CHECKING:
    from evaluation import CaseOutcome

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Trustworthy Agentic AI Claim-Survival harness.",
)


@app.command("run")
def cmd_run(
    config: Annotated[
        Path,
        typer.Option("--config", "-c", exists=True, dir_okay=False, readable=True),
    ],
) -> None:
    """Execute every case in the configured suite from a YAML config."""
    cfg = load_config(config)
    outcome = run_eval(cfg)
    _echo_outcome(outcome.run_dir, outcome.cases)


@app.command("score")
def cmd_score(
    run_id: Annotated[str, typer.Option("--run", "-r")],
    root: Annotated[Path, typer.Option("--root", help="Runs root.")] = Path("runs"),
) -> None:
    """Re-score a finished run from its persisted config and per-case spans."""
    outcome = score_run(root, run_id)
    _echo_outcome(outcome.run_dir, outcome.cases)


@app.command("smoke")
def cmd_smoke(
    configs_dir: Annotated[
        Path,
        typer.Option("--configs", "-C", help="Directory containing smoke_*.yaml files."),
    ] = Path("configs"),
) -> None:
    """Run every ``smoke_*_stub.yaml`` config under ``--configs``."""
    files = sorted(configs_dir.glob("smoke_*_stub.yaml"))
    if not files:
        typer.echo(f"No smoke_*_stub.yaml found under {configs_dir}", err=True)
        raise typer.Exit(code=1)
    for path in files:
        typer.echo(f"\n=== {path.name} ===")
        cfg = load_config(path)
        outcome = run_eval(cfg)
        _echo_outcome(outcome.run_dir, outcome.cases, indent="  ")


def _echo_outcome(run_dir: Path, cases: list[CaseOutcome], indent: str = "") -> None:
    typer.echo(f"{indent}run_dir: {run_dir}")
    typer.echo(f"{indent}cases:   {len(cases)}")
    for c in cases:
        typer.echo(f"{indent}- [{c.case_id}] violations={len(c.violations)}")
        for v in c.violations:
            typer.echo(f"{indent}    - [{v.severity.value}] {v.type}: {v.detail}")


if __name__ == "__main__":
    app()
