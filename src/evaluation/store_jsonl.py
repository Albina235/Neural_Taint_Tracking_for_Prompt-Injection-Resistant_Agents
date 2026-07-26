"""Filesystem-backed JSONL implementation of :class:`core.TraceStore`."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from core import TraceStore
from evaluation.integrity import validate_span_config_hashes


class JSONLTraceStore(TraceStore):
    """Append-only JSONL store.

    Each call to :meth:`save` appends one batch of spans (one JSON object per
    line) to ``<root>/<run_id>/spans.jsonl`` and remembers the run for
    grouping. The same store can host multiple runs across its lifetime.
    """

    def __init__(self, root: str | Path, run_id: str) -> None:
        self._root = Path(root)
        self._run_id = run_id
        self._lock = threading.Lock()
        self._known_runs: list[str] = [run_id]
        self.run_dir.mkdir(parents=True, exist_ok=True)
        # Truncate any prior spans file for this run_id — runs are idempotent.
        if self.spans_path.exists():
            self.spans_path.unlink()

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def run_dir(self) -> Path:
        return self._root / self._run_id

    @property
    def spans_path(self) -> Path:
        return self.run_dir / "spans.jsonl"

    def save(self, spans: list[dict[str, object]]) -> None:
        if not spans:
            return
        with self._lock, self.spans_path.open("a", encoding="utf-8") as fh:
            for span in spans:
                fh.write(json.dumps(span, ensure_ascii=False, sort_keys=True))
                fh.write("\n")

    def grouped(self) -> list[list[dict[str, object]]]:
        """Return spans grouped by run_id, in the order runs were registered."""
        out: list[list[dict[str, object]]] = []
        for run_id in self._known_runs:
            path = self._root / run_id / "spans.jsonl"
            if not path.exists():
                out.append([])
                continue
            out.append(_read_jsonl(path))
        return out


def load_run(root: str | Path, run_id: str) -> list[dict[str, object]]:
    """Read spans for a single run from disk (used by ``taicf score``)."""
    path = Path(root) / run_id / "spans.jsonl"
    if not path.exists():
        msg = f"No spans file at {path}"
        raise FileNotFoundError(msg)
    return _read_jsonl(path)


def load_validated_run(
    root: str | Path,
    run_id: str,
    *,
    expected_config_hash: str,
) -> list[dict[str, object]]:
    """Load spans and bind every one to the expected frozen configuration."""
    path = Path(root) / run_id / "spans.jsonl"
    spans = load_run(root, run_id)
    validate_span_config_hashes(
        spans,
        expected_hash=expected_config_hash,
        source=path,
    )
    return spans


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, dict):
                out.append(obj)
    return out
