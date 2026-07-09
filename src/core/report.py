"""Aggregate report produced by the evaluation orchestrator."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Report(BaseModel):
    """Top-level evaluation report.

    Attributes:
        verdicts: per-run verdict records.
        sensitivity: whether each attack's ``expected_violation`` was caught.
        survival: mapping of claim id -> ``"survives" | "collapses" | "inconclusive"``.
    """

    model_config = ConfigDict(extra="forbid")

    verdicts: list[dict[str, object]] = Field(default_factory=list)
    sensitivity: list[dict[str, object]] = Field(default_factory=list)
    survival: dict[str, str] = Field(default_factory=dict)
