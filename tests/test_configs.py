"""Config schema + YAML loader + deterministic config_hash."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import yaml

from configs import RunConfig, config_hash, load_config

if TYPE_CHECKING:
    from pathlib import Path


def _write(tmp_path: Path, name: str, payload: dict[str, object]) -> Path:
    p = tmp_path / name
    p.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")
    return p


def _minimal_cfg() -> dict[str, object]:
    return {
        "run": {"id": "r1", "seed": 1},
        "scaffold": {"id": "react_stub", "params": {"default": {"final": "ok", "plan": []}}},
        "suite": {"id": "lite_fs_protected_paths", "case_ids": ["fs-01-clean"]},
        "scanners": [{"id": "unauthorized_write"}],
        "store": {"kind": "jsonl", "root": "runs/"},
    }


def test_load_config_roundtrip(tmp_path: Path) -> None:
    path = _write(tmp_path, "x.yaml", _minimal_cfg())
    cfg = load_config(path)
    assert cfg.run.id == "r1"
    assert cfg.scaffold.id == "react_stub"
    assert cfg.suite.case_ids == ["fs-01-clean"]
    assert [s.id for s in cfg.scanners] == ["unauthorized_write"]


def test_config_hash_is_stable_across_key_order(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.yaml", _minimal_cfg())
    b_payload = dict(reversed(list(_minimal_cfg().items())))
    b = _write(tmp_path, "b.yaml", b_payload)
    assert config_hash(load_config(a)) == config_hash(load_config(b))


def test_config_hash_changes_with_content() -> None:
    payload = _minimal_cfg()
    cfg1 = RunConfig.model_validate(payload)
    payload["run"] = {"id": "r2", "seed": 1}
    cfg2 = RunConfig.model_validate(payload)
    assert config_hash(cfg1) != config_hash(cfg2)


def test_load_rejects_unknown_field(tmp_path: Path) -> None:
    payload = _minimal_cfg()
    payload["run"] = {"id": "r1", "seed": 1, "unknown": True}
    path = _write(tmp_path, "bad.yaml", payload)
    with pytest.raises(Exception):  # noqa: B017  pydantic ValidationError
        load_config(path)
