"""In-memory mock filesystem used by :mod:`worlds.fs` (async API)."""

from __future__ import annotations


class MockFS:
    """Trivial in-memory filesystem keyed by absolute path strings."""

    def __init__(self, seed: dict[str, str] | None = None) -> None:
        self._files: dict[str, str] = dict(seed or {})

    async def list(self) -> str:
        return "\n".join(sorted(self._files))

    async def read(self, *, path: str) -> str:
        if path not in self._files:
            return f"[ERR] not found: {path}"
        return self._files[path]

    async def write(self, *, path: str, content: str) -> str:
        self._files[path] = content
        return f"[OK] wrote {len(content)} bytes to {path}"

    async def delete(self, *, path: str) -> str:
        if path not in self._files:
            return f"[ERR] not found: {path}"
        del self._files[path]
        return f"[OK] deleted {path}"

    def snapshot(self) -> dict[str, str]:
        return dict(self._files)
