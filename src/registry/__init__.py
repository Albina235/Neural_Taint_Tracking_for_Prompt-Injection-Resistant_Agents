"""Lightweight string-id registry for scaffolds, tasks, scanners, worlds.

Usage:
    @register("scanner", "unauthorized_write")
    class UnauthorizedWriteScanner(Scanner):
        ...

    cls = resolve("scanner", "unauthorized_write")
    instance = cls(**params)

Modules that define registrations must be imported before lookup. See
:func:`load_builtins` for the canonical bootstrap.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

_REGISTRIES: dict[str, dict[str, type[object]]] = {}

T = TypeVar("T", bound=type[object])


def register(kind: str, id_: str) -> Callable[[T], T]:
    """Class decorator that records ``cls`` under ``(kind, id_)``."""

    def _wrap(cls: T) -> T:
        bucket = _REGISTRIES.setdefault(kind, {})
        if id_ in bucket:
            msg = f"Duplicate registration: kind={kind!r} id={id_!r}"
            raise ValueError(msg)
        bucket[id_] = cls
        return cls

    return _wrap


def resolve(kind: str, id_: str) -> type[object]:
    """Return the class registered under ``(kind, id_)``."""
    bucket = _REGISTRIES.get(kind, {})
    if id_ not in bucket:
        known = sorted(bucket)
        msg = f"Unknown {kind!r}: {id_!r}. Registered: {known}"
        raise KeyError(msg)
    return bucket[id_]


def list_ids(kind: str) -> list[str]:
    """Return sorted ids registered under ``kind``."""
    return sorted(_REGISTRIES.get(kind, {}))


_BUILTINS_LOADED = False


def load_builtins() -> None:
    """Trigger built-in registrations.

    Imports :mod:`registry.builtins` once per process; that module performs
    eager top-level imports of every shipped scaffold/suite/scanner.
    Idempotent — safe to call from multiple entry-points.
    """
    global _BUILTINS_LOADED  # noqa: PLW0603
    if _BUILTINS_LOADED:
        return
    import registry.builtins  # noqa: PLC0415  (bootstrap shim by design)

    _BUILTINS_LOADED = True


__all__ = ["list_ids", "load_builtins", "register", "resolve"]
