"""JSONL trace store: append, group, truncate-on-reuse."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from evaluation.store_jsonl import JSONLTraceStore, load_run

if TYPE_CHECKING:
    from pathlib import Path


def test_save_then_grouped(tmp_path: Path) -> None:
    store = JSONLTraceStore(root=tmp_path, run_id="r1")
    store.save([{"name": "a"}, {"name": "b"}])
    store.save([{"name": "c"}])
    groups = store.grouped()
    assert len(groups) == 1
    assert [s["name"] for s in groups[0]] == ["a", "b", "c"]


def test_truncates_on_reuse(tmp_path: Path) -> None:
    JSONLTraceStore(root=tmp_path, run_id="r1").save([{"name": "old"}])
    fresh = JSONLTraceStore(root=tmp_path, run_id="r1")
    fresh.save([{"name": "new"}])
    spans = load_run(tmp_path, "r1")
    assert [s["name"] for s in spans] == ["new"]


def test_load_run_missing(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_run(tmp_path, "nope")
