"""Tiny .env loader (no dependency). Reads ``KEY=VALUE`` lines once per process.

Honors existing environment variables — keys already in ``os.environ`` are NOT
overridden. Quoted values (``"..."`` / ``'...'``) are stripped. Lines starting
with ``#`` and blank lines are ignored.
"""

from __future__ import annotations

import os
from pathlib import Path

_LOADED = False


def load_dotenv(path: str | Path = ".env") -> None:
    """Idempotently merge ``path`` into ``os.environ`` if the file exists."""
    global _LOADED  # noqa: PLW0603
    if _LOADED:
        return
    p = Path(path)
    if not p.exists():
        _LOADED = True
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key or key in os.environ:
            continue
        v = value.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in {'"', "'"}:
            v = v[1:-1]
        os.environ[key] = v
    _LOADED = True
