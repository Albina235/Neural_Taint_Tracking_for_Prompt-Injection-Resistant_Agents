"""Orchestrate one run: setup → execute every case (concurrent) → scan → report."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

import yaml

from configs import config_hash, load_config
from core import Gate, Monitor, Trace, Violation, runnable
from evaluation.dotenv import load_dotenv
from evaluation.otel_setup import setup_otel
from evaluation.report import render_aggregate_markdown, render_case_markdown
from evaluation.store_jsonl import JSONLTraceStore, load_run
from projections import OTLPProjection
from registry import load_builtins, resolve
from scaffolds._instrumentation import emit_env

if TYPE_CHECKING:
    from configs import RunConfig
    from core import Scaffold, Scanner, Task, TaskSuite


@dataclass
class CaseOutcome:
    case_id: str
    case_dir: Path
    trace: Trace
    violations: list[Violation]


@dataclass
class RunOutcome:
    run_dir: Path
    config_hash: str
    cases: list[CaseOutcome] = field(default_factory=list)


def run(cfg: RunConfig) -> RunOutcome:
    """Sync entry-point that drives :func:`arun` under a fresh event loop."""
    return asyncio.run(arun(cfg))


def score(root: str | Path, run_id: str) -> RunOutcome:
    """Sync entry-point that drives :func:`ascore` under a fresh event loop."""
    return asyncio.run(ascore(root, run_id))


async def arun(cfg: RunConfig) -> RunOutcome:
    """Execute every case in the configured suite concurrently."""
    load_dotenv()
    load_builtins()
    cfg_hash = config_hash(cfg)

    suite = _build_suite(cfg)
    scaffold = _build_scaffold(cfg)
    if not runnable(suite, scaffold):
        missing = suite.requires() - scaffold.provides
        msg = (
            f"Scaffold {cfg.scaffold.id!r} provides {sorted(scaffold.provides)}; "
            f"suite {cfg.suite.id!r} requires {sorted(suite.requires())}. "
            f"Missing: {sorted(missing)}."
        )
        raise ValueError(msg)
    scanners = _build_scanners(cfg)

    run_dir = Path(cfg.store.root) / cfg.run.id
    run_dir.mkdir(parents=True, exist_ok=True)
    _persist_config(cfg, run_dir)

    cases = _select_cases(suite, cfg.suite.case_ids)
    if not cases:
        msg = f"Suite {cfg.suite.id!r} yielded no cases (filter={cfg.suite.case_ids!r})"
        raise ValueError(msg)

    max_concurrency = max(1, cfg.run.max_concurrency)
    instrument_langchain = max_concurrency == 1
    semaphore = asyncio.Semaphore(max_concurrency)

    async def _bounded(case: Task) -> CaseOutcome:
        async with semaphore:
            return await _run_one_case(
                cfg=cfg,
                cfg_hash=cfg_hash,
                suite=suite,
                case=case,
                scaffold=scaffold,
                scanners=scanners,
                instrument_langchain=instrument_langchain,
            )

    outcomes = await asyncio.gather(*(_bounded(c) for c in cases))

    aggregate = render_aggregate_markdown(cfg, cfg_hash, list(outcomes))
    (run_dir / "report.md").write_text(aggregate, encoding="utf-8")

    return RunOutcome(run_dir=run_dir, config_hash=cfg_hash, cases=list(outcomes))


async def ascore(root: str | Path, run_id: str) -> RunOutcome:
    """Re-score a finished run from its persisted ``cfg.yaml`` + per-case spans."""
    load_dotenv()
    load_builtins()
    cfg_path = Path(root) / run_id / "cfg.yaml"
    cfg = load_config(cfg_path)
    cfg_hash = config_hash(cfg)

    suite = _build_suite(cfg)
    scanners = _build_scanners(cfg)
    cases = _select_cases(suite, cfg.suite.case_ids)

    outcomes: list[CaseOutcome] = []
    for case in cases:
        case_dir = Path(cfg.store.root) / cfg.run.id / "cases" / case.id
        trace, violations = _score_from_disk(root=case_dir.parent, case=case, scanners=scanners)
        (case_dir / "report.md").write_text(
            render_case_markdown(cfg, cfg_hash, case, trace, violations),
            encoding="utf-8",
        )
        _write_violations(case_dir, cfg_hash, violations)
        outcomes.append(
            CaseOutcome(
                case_id=case.id,
                case_dir=case_dir,
                trace=trace,
                violations=violations,
            )
        )

    run_dir = Path(cfg.store.root) / cfg.run.id
    (run_dir / "report.md").write_text(
        render_aggregate_markdown(cfg, cfg_hash, outcomes), encoding="utf-8"
    )
    return RunOutcome(run_dir=run_dir, config_hash=cfg_hash, cases=outcomes)


def _build_suite(cfg: RunConfig) -> TaskSuite:
    cls = resolve("suite", cfg.suite.id)
    return cast("TaskSuite", cls(**cfg.suite.params))


def _build_scaffold(cfg: RunConfig) -> Scaffold:
    cls = resolve("scaffold", cfg.scaffold.id)
    params = dict(cfg.scaffold.params)
    if cfg.scaffold.llm is not None:
        params.setdefault("llm", cfg.scaffold.llm.model_dump())
    return cast("Scaffold", cls(**params))


def _build_scanners(cfg: RunConfig) -> list[Scanner]:
    out: list[Scanner] = []
    for spec in cfg.scanners:
        cls = resolve("scanner", spec.id)
        out.append(cast("Scanner", cls(**spec.params)))
    return out


def _select_cases(suite: TaskSuite, case_ids: list[str]) -> list[Task]:
    all_cases = list(suite.cases())
    if not case_ids:
        return all_cases
    wanted = set(case_ids)
    return [c for c in all_cases if c.id in wanted]


async def _run_one_case(
    *,
    cfg: RunConfig,
    cfg_hash: str,
    suite: TaskSuite,
    case: Task,
    scaffold: Scaffold,
    scanners: list[Scanner],
    instrument_langchain: bool,
) -> CaseOutcome:
    case_run_id = f"{cfg.run.id}/cases/{case.id}"
    store = JSONLTraceStore(root=cfg.store.root, run_id=case_run_id)

    world = suite.build_world(case)
    handle = await world.setup()
    try:
        with setup_otel(
            store,
            run_id=case_run_id,
            config_hash=cfg_hash,
            instrument_langchain=instrument_langchain,
        ):
            gate = Gate(scanners, gt=case.ground_truth)
            system_prompt = case.system_prompt or suite.default_system_prompt
            await scaffold.run(
                case.instruction,
                handle,
                task_id=case.id,
                system_prompt=system_prompt,
                gate=gate,
            )
            for env_step in await world.observe():
                emit_env(env_step.name or "env", env_step.metadata)
    finally:
        await world.teardown()

    trace, violations = _score_from_disk(root=store.run_dir.parent, case=case, scanners=scanners)
    (store.run_dir / "report.md").write_text(
        render_case_markdown(cfg, cfg_hash, case, trace, violations),
        encoding="utf-8",
    )
    _write_violations(store.run_dir, cfg_hash, violations)
    return CaseOutcome(case_id=case.id, case_dir=store.run_dir, trace=trace, violations=violations)


def _score_from_disk(
    *,
    root: Path,
    case: Task,
    scanners: list[Scanner],
) -> tuple[Trace, list[Violation]]:
    spans = load_run(root, case.id)
    trace = OTLPProjection(task_id=case.id).project(spans)
    violations = Monitor(scanners).scan(trace, gt=case.ground_truth)
    return trace, violations


def _persist_config(cfg: RunConfig, run_dir: Path) -> None:
    with (run_dir / "cfg.yaml").open("w", encoding="utf-8") as fh:
        yaml.safe_dump(cfg.model_dump(mode="json"), fh, sort_keys=True)


def _write_violations(case_dir: Path, cfg_hash: str, violations: list[Violation]) -> None:
    payload = {
        "config_hash": cfg_hash,
        "violations": [v.model_dump(mode="json") for v in violations],
    }
    (case_dir / "violations.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
