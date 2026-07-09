"""End-to-end: each smoke stub config yields the expected per-case violations."""

from __future__ import annotations

from pathlib import Path

import pytest

from configs import RunConfig, load_config
from evaluation import run as run_eval
from evaluation import score

REPO_ROOT = Path(__file__).resolve().parent.parent


def _patch_root(cfg: RunConfig, tmp_path: Path) -> RunConfig:
    """Redirect store.root to tmp so tests do not pollute the repo's runs/."""
    payload = cfg.model_dump(mode="json")
    payload["store"]["root"] = str(tmp_path)
    return RunConfig.model_validate(payload)


@pytest.mark.parametrize(
    ("config_name", "clean_case_id", "attack_case_id", "expected_types"),
    [
        (
            "smoke_fs_stub.yaml",
            "fs-01-clean",
            "fs-02-notes-injection",
            {"unauthorized_write"},
        ),
        (
            "smoke_memory_stub.yaml",
            "mem-01-clean",
            "mem-02-system-note",
            {"unauthorized_recipient", "memory_poison_followed"},
        ),
        (
            "smoke_retrieval_stub.yaml",
            "ret-01-clean",
            "ret-02-note-attacker",
            {"injection_followed", "unsupported_citation"},
        ),
    ],
)
def test_smoke_config_separates_clean_and_attack(
    tmp_path: Path,
    config_name: str,
    clean_case_id: str,
    attack_case_id: str,
    expected_types: set[str],
) -> None:
    cfg = load_config(REPO_ROOT / "configs" / config_name)
    cfg = _patch_root(cfg, tmp_path)
    outcome = run_eval(cfg)

    by_id = {c.case_id: c for c in outcome.cases}
    assert clean_case_id in by_id, f"clean case missing: {clean_case_id}"
    assert attack_case_id in by_id, f"attack case missing: {attack_case_id}"

    assert by_id[clean_case_id].violations == [], "clean baseline should produce no violations"
    attack_types = {v.type for v in by_id[attack_case_id].violations}
    assert expected_types <= attack_types, (
        f"attack case {attack_case_id}: expected {expected_types} ⊆ {attack_types}"
    )

    assert (outcome.run_dir / "report.md").exists()
    assert (outcome.run_dir / "cfg.yaml").exists()
    case_dir = by_id[attack_case_id].case_dir
    assert (case_dir / "report.md").exists()
    assert (case_dir / "violations.json").exists()
    assert (case_dir / "spans.jsonl").exists()


def test_score_recomputes_without_rerunning(tmp_path: Path) -> None:
    cfg = load_config(REPO_ROOT / "configs" / "smoke_fs_stub.yaml")
    cfg = _patch_root(cfg, tmp_path)
    first = run_eval(cfg)
    attack = next(c for c in first.cases if c.case_id == "fs-02-notes-injection")
    spans_path = attack.case_dir / "spans.jsonl"
    mtime_before = spans_path.stat().st_mtime

    rescored = score(cfg.store.root, cfg.run.id)
    assert spans_path.stat().st_mtime == mtime_before
    rescored_attack = next(c for c in rescored.cases if c.case_id == "fs-02-notes-injection")
    assert {v.type for v in rescored_attack.violations} == {v.type for v in attack.violations}


def test_case_ids_filter_runs_subset(tmp_path: Path) -> None:
    cfg = load_config(REPO_ROOT / "configs" / "smoke_fs_stub.yaml")
    cfg = _patch_root(cfg, tmp_path)
    payload = cfg.model_dump(mode="json")
    payload["suite"]["case_ids"] = ["fs-01-clean", "fs-02-notes-injection"]
    cfg = RunConfig.model_validate(payload)
    outcome = run_eval(cfg)
    assert [c.case_id for c in outcome.cases] == [
        "fs-01-clean",
        "fs-02-notes-injection",
    ]
