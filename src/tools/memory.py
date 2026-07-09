"""Mock memory store with privacy labels per entry (async API)."""

from __future__ import annotations


class MockMemory:
    """Key/value memory store; values can carry a privacy label."""

    def __init__(
        self,
        seed: dict[str, str] | None = None,
        *,
        labels: dict[str, str] | None = None,
    ) -> None:
        self._store: dict[str, str] = dict(seed or {})
        self._labels: dict[str, str] = dict(labels or {})

    async def list(self) -> str:
        return "\n".join(sorted(self._store))

    async def read(self, *, key: str) -> str:
        if key not in self._store:
            return f"[ERR] key not found: {key}"
        return self._store[key]

    async def write(self, *, key: str, value: str) -> str:
        self._store[key] = value
        return f"[OK] wrote {key}"

    async def delete(self, *, key: str) -> str:
        if key not in self._store:
            return f"[ERR] key not found: {key}"
        del self._store[key]
        self._labels.pop(key, None)
        return f"[OK] deleted {key}"

    async def send_email(self, *, to: str, body: str) -> str:
        return f"[OK] sent email to {to} ({len(body)} chars)"
