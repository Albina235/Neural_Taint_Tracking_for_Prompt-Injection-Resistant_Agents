"""Trace store abstraction: the canonical evidence sink."""

from __future__ import annotations

from abc import ABC, abstractmethod


class TraceStore(ABC):
    """Persistence interface for raw OTLP spans grouped by run.

    The local store is the canonical evidence; any external backend
    (LangFuse, etc.) is a mirror, never the source of truth.
    """

    @abstractmethod
    def save(self, spans: list[dict[str, object]]) -> None:
        """Persist a batch of spans."""

    @abstractmethod
    def grouped(self) -> list[list[dict[str, object]]]:
        """Return spans grouped per run, in the order they were saved."""
