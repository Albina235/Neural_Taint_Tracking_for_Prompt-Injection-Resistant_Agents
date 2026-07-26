"""Scanner abstractions: pure predicates over a :class:`ScanContext`."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from core.enums import Hook, Severity
from core.task import GroundTruth
from core.trace import Step

if TYPE_CHECKING:
    from core.trust import TrustPolicy


class Violation(BaseModel):
    """A single violation emitted by a scanner."""

    model_config = ConfigDict(extra="forbid")

    type: str
    detail: str = ""
    severity: Severity = Severity.WARN
    refs: list[str] = Field(default_factory=list)


class Decision(BaseModel):
    """Online runtime decision: allow or block the pending action."""

    model_config = ConfigDict(extra="forbid")

    allow: bool
    reason: str = ""


class ScanContext(BaseModel):
    """Context passed to :meth:`Scanner.evaluate`.

    ``pending`` semantics by hook:
        * ``PRE_TOOL`` — the call about to run (no result yet).
        * ``POST_TOOL`` — the call with its result attached.
        * ``POST_TURN`` — ``None``; the full run lives in ``history``.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    hook: Hook
    history: list[Step] = Field(default_factory=list)
    pending: Step | None = None
    ground_truth: GroundTruth | None = None


class Scanner(ABC):
    """A pure, deterministic predicate over a :class:`ScanContext`.

    Subclasses must override :attr:`id`, declare which :class:`Hook` points
    they attach to via :attr:`hooks`, and implement :meth:`evaluate`. No I/O,
    no network, no LLM call.
    """

    id: str = "scanner"
    hooks: frozenset[Hook] = frozenset({Hook.POST_TURN})
    needs_truth: bool = False
    trust_policy: TrustPolicy | None = None

    @abstractmethod
    def evaluate(self, ctx: ScanContext) -> list[Violation]:
        """Return zero or more violations for the given context."""
