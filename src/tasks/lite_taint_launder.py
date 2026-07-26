"""Compatibility suite id for the single canonical transformation ladder.

Historically this module defined a different nine-attack ladder and produced the
now-historical 4/9 result.  New evaluations use :func:`tasks._laundering.build_ladder`
through :class:`tasks.taint_laundering.TaintLaunderingSuite`, which contains 11
attack cases.  The old suite id remains registered so existing configurations do
not fail, but it delegates to the same cases and world recipe.
"""

from __future__ import annotations

from typing import ClassVar

from registry import register
from tasks.taint_laundering import TaintLaunderingSuite


@register("suite", "lite_taint_launder")
class LiteTaintLaunderSuite(TaintLaunderingSuite):
    """Backward-compatible name for the canonical 11-case ladder."""

    id: ClassVar[str] = "lite_taint_launder"
