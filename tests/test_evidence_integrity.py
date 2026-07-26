"""Evidence-integrity checks for rescoring and metric generation."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from configs import RunConfig, config_hash, load_config
from evaluation import run as run_eval
from evaluation import score
from evaluation.integrity import (
    EvidenceIntegrityError,
    load_validated_violations,
    validate_span_config_hashes,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _span(config_hash_value: str | None) -> dict[str, object]:
    resource: dict[str, object] = {}
    if config_hash_value is not None:
        resource["taicf.config_hash"] = config_hash_value
    return {"name": "tool.x", "resource": resource}


def _patched_config(tmp_path: Path) -> RunConfig:
    cfg = load_config(REPO_ROOT / "configs" / "smoke_fs_stub.yaml")
    payload = cfg.model_dump(mode="json")
    payload["run"]["id"] = "integrity-root-test"
    payload["store"]["root"] = str(tmp_path)
    return RunConfig.model_validate(payload)


def test_matching_span_config_hash_is_accepted() -> None:
    assert (
        validate_span_config_hashes(
            [_span("abc"), _span("abc")],
            expected_hash="abc",
            source="spans.jsonl",
        )
        == "abc"
    )


def test_missing_span_config_hash_is_rejected() -> None:
    with pytest.raises(EvidenceIntegrityError, match=r"missing 'taicf\.config_hash'"):
        validate_span_config_hashes(
            [_span("abc"), _span(None)],
            expected_hash="abc",
            source="spans.jsonl",
        )


def test_mixed_span_config_hashes_are_rejected() -> None:
    with pytest.raises(EvidenceIntegrityError, match=r"mixed 'taicf\.config_hash'"):
        validate_span_config_hashes(
            [_span("abc"), _span("def")],
            expected_hash="abc",
            source="spans.jsonl",
        )


def test_span_hash_mismatching_frozen_config_is_rejected() -> None:
    with pytest.raises(EvidenceIntegrityError, match=r"does not match frozen cfg\.yaml"):
        validate_span_config_hashes(
            [_span("old")],
            expected_hash="current",
            source="spans.jsonl",
        )


@pytest.mark.parametrize("saved_hash", [None, "stale"])
def test_missing_or_stale_violation_hash_is_rejected(
    tmp_path: Path,
    saved_hash: str | None,
) -> None:
    path = tmp_path / "violations.json"
    payload: dict[str, object] = {"violations": []}
    if saved_hash is not None:
        payload["config_hash"] = saved_hash
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(EvidenceIntegrityError, match=r"config_hash|config hash"):
        load_validated_violations(path, expected_hash="current")


def test_matching_violation_hash_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "violations.json"
    path.write_text(
        json.dumps({"config_hash": "current", "violations": [{"type": "x"}]}),
        encoding="utf-8",
    )
    assert load_validated_violations(path, expected_hash="current") == [{"type": "x"}]


def test_rescore_rejects_config_changed_after_spans_were_written(tmp_path: Path) -> None:
    cfg = _patched_config(tmp_path)
    outcome = run_eval(cfg)
    frozen_path = outcome.run_dir / "cfg.yaml"
    frozen = yaml.safe_load(frozen_path.read_text(encoding="utf-8"))
    frozen["run"]["seed"] += 1
    frozen_path.write_text(yaml.safe_dump(frozen, sort_keys=True), encoding="utf-8")

    with pytest.raises(EvidenceIntegrityError, match=r"does not match frozen cfg\.yaml"):
        score(tmp_path, cfg.run.id)


def test_score_uses_requested_root_for_reads_and_writes(tmp_path: Path) -> None:
    origin = tmp_path / "origin"
    mirror = tmp_path / "mirror"
    cfg = _patched_config(origin)
    outcome = run_eval(cfg)
    copied_run = mirror / cfg.run.id
    shutil.copytree(outcome.run_dir, copied_run)

    origin_report = outcome.run_dir / "report.md"
    origin_report.write_text("origin sentinel\n", encoding="utf-8")
    mirror_report = copied_run / "report.md"
    mirror_report.write_text("mirror sentinel\n", encoding="utf-8")
    mirror_spans = copied_run / "cases" / "fs-02-notes-injection" / "spans.jsonl"
    spans_before = mirror_spans.read_bytes()

    rescored = score(mirror, cfg.run.id)

    assert rescored.run_dir == copied_run
    assert origin_report.read_text(encoding="utf-8") == "origin sentinel\n"
    assert mirror_report.read_text(encoding="utf-8") != "mirror sentinel\n"
    assert mirror_spans.read_bytes() == spans_before
    assert config_hash(load_config(copied_run / "cfg.yaml")) == rescored.config_hash
