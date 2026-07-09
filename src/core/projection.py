"""Projection abstraction: OTLP spans -> thin :class:`~core.trace.Trace`."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.trace import Trace


class Projection(ABC):
    """Tolerant projector from raw OTLP span dicts to a :class:`Trace`.

    Concrete subclasses live in ``projections/`` and should read only the
    fields scanners need, tolerating both OpenInference and OTel-GenAI
    attribute flavors.
    """

    @abstractmethod
    def project(self, spans: list[dict[str, object]]) -> Trace:
        """Project a list of span dicts into a thin :class:`Trace`."""
