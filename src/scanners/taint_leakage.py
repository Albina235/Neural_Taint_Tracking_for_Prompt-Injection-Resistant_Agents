"""Deterministic value-based Taint-Scanner (``taint_leakage``).

Certified property (deliberately narrow, per reviewer feedback):

    *Absence of detected lexical flow* — no normalized fragment of an
    untrusted tool output reaches an argument of a privileged tool without a
    covering ``gate.sanitize`` declassification earlier in the trace, under
    the explicit trace-completeness and normalization assumptions below.

This is **not** a proof of information-theoretic non-interference: semantic
laundering (paraphrase / re-encoding by the LLM) defeats substring matching
by construction and is measured as scanner recall, not assumed away.

Mechanism
---------
1. Walk the (partial or full) trace in order.
2. Every step whose tool is an *untrusted source* (``core.trust``) contributes
   taint fragments: the full normalized output plus all normalized token
   ``n``-grams of length ``ngram`` (default 5) with at least ``min_chars``
   normalized characters (default 16). JSON outputs are decomposed and every
   string leaf contributes fragments too.
3. Every ``gate.sanitize`` step declassifies: any fragment that is a
   substring of the normalized text it processed (args + output) is removed
   from the live taint set from that point on.
4. At every *privileged sink* call, every argument string (JSON-decomposed)
   is normalized and tested for any surviving taint fragment. A hit emits a
   ``taint_leakage`` violation (CRITICAL) referencing both the sink span and
   the originating source span.

Normalization (explicit, part of the certificate statement): Unicode NFKC ->
casefold -> every non-alphanumeric character becomes a space -> whitespace
collapsed. This makes the detector robust to *light transformations* (case,
punctuation, spacing, unicode confusable forms folded by NFKC) while staying
pure and deterministic (``needs_truth = False``; no I/O, no LLM).

Hooks: ``PRE_TOOL`` (online block via Gate) and ``POST_TURN`` (post-hoc audit
over the projected trace) run the *same* predicate — core invariant #2.
"""

from __future__ import annotations

import json
import unicodedata
from typing import TYPE_CHECKING

from core import Hook, Scanner, Severity, StepKind, Violation
from core.trust import (
    PRIVILEGED_SINK_PREFIXES,
    SANITIZER_PREFIXES,
    TRUST_LEVEL_ATTR,
    UNTRUSTED_SOURCE_PREFIXES,
    is_privileged_sink,
    is_sanitizer,
    is_untrusted_source,
)
from registry import register

if TYPE_CHECKING:
    from core import ScanContext, Step


# ---------------------------------------------------------------------------
# Normalization + fragment extraction (pure helpers, unit-tested directly)
# ---------------------------------------------------------------------------


def normalize(text: str) -> str:
    """NFKC -> casefold -> non-alphanumeric to space -> collapse whitespace."""
    folded = unicodedata.normalize("NFKC", text).casefold()
    cleaned = "".join(ch if ch.isalnum() else " " for ch in folded)
    return " ".join(cleaned.split())


def _string_leaves(value: object) -> list[str]:
    """Flatten a (possibly JSON-structured) value into its string leaves."""
    if isinstance(value, str):
        parsed = _try_json(value)
        if parsed is not None and not isinstance(parsed, str):
            return _string_leaves(parsed)
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for v in value.values():
            out.extend(_string_leaves(v))
        return out
    if isinstance(value, list):
        out = []
        for v in value:
            out.extend(_string_leaves(v))
        return out
    return []


def _try_json(s: str) -> object | None:
    s = s.strip()
    if not (s.startswith("{") or s.startswith("[")):
        return None
    try:
        return json.loads(s)
    except (ValueError, TypeError):
        return None


def fragments(text: str, *, ngram: int, min_chars: int) -> set[str]:
    """Normalized full string + token n-grams, filtered by ``min_chars``."""
    norm = normalize(text)
    if not norm:
        return set()
    out: set[str] = set()
    if len(norm) >= min_chars:
        out.add(norm)
    tokens = norm.split()
    if len(tokens) >= ngram:
        for i in range(len(tokens) - ngram + 1):
            frag = " ".join(tokens[i : i + ngram])
            if len(frag) >= min_chars:
                out.add(frag)
    return out


# ---------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------


@register("scanner", "taint_leakage")
class TaintLeakageScanner(Scanner):
    """Value-based lexical-flow scanner over the ``taicf.trust.*`` lineage."""

    id = "taint_leakage"
    hooks = frozenset({Hook.PRE_TOOL, Hook.POST_TURN})
    needs_truth = False

    def __init__(
        self,
        *,
        ngram: int = 5,
        min_chars: int = 16,
        untrusted_tools: list[str] | None = None,
        sanitizer_tools: list[str] | None = None,
        privileged_tools: list[str] | None = None,
    ) -> None:
        self._ngram = ngram
        self._min_chars = min_chars
        self._untrusted = tuple(untrusted_tools) if untrusted_tools else UNTRUSTED_SOURCE_PREFIXES
        self._sanitizers = tuple(sanitizer_tools) if sanitizer_tools else SANITIZER_PREFIXES
        self._privileged = tuple(privileged_tools) if privileged_tools else PRIVILEGED_SINK_PREFIXES

    # -- trust resolution ---------------------------------------------------

    def _level_untrusted(self, step: Step) -> bool:
        """Prefer the propagated ``taicf.trust.level``; fall back to names."""
        level = step.metadata.get(TRUST_LEVEL_ATTR)
        if isinstance(level, str):
            return level == "untrusted"
        return is_untrusted_source(step.name or "", self._untrusted)

    def _is_sanitizer(self, step: Step) -> bool:
        level = step.metadata.get(TRUST_LEVEL_ATTR)
        if isinstance(level, str) and level == "sanitized":
            return True
        return is_sanitizer(step.name or "", self._sanitizers)

    def _is_sink(self, step: Step) -> bool:
        return is_privileged_sink(step.name or "", self._privileged)

    # -- taint-set construction ----------------------------------------------

    def _absorb_source(self, step: Step, taint: dict[str, str]) -> None:
        """Add fragments of an untrusted output; remember the source span.

        Fragments are inserted in sorted order so the taint dict's iteration
        order — and therefore the fragment quoted in a violation — is stable
        across processes (``fragments`` returns a set, whose iteration order
        depends on hash randomization).
        """
        ref = step.span_id or (step.name or "?")
        for leaf in _string_leaves(step.output):
            for frag in sorted(fragments(leaf, ngram=self._ngram, min_chars=self._min_chars)):
                taint.setdefault(frag, ref)

    def _declassify(self, step: Step, taint: dict[str, str]) -> None:
        """Remove fragments covered by what the gate actually released.

        Only the gate's *output* is treated as declassified, not its input
        arguments. A sound declassifier releases the text it vouches for as its
        return value (e.g. ``gate.allow_quote`` returns an allow-listed
        document); covering by input args would let a caller declassify
        arbitrary text just by passing it in.
        """
        covered: list[str] = []
        for leaf in _string_leaves(step.output):
            norm = normalize(leaf)
            if norm:
                covered.append(norm)
        if not covered:
            return
        for frag in [f for f in taint if any(f in c for c in covered)]:
            del taint[frag]

    def _check_sink(self, step: Step, taint: dict[str, str]) -> list[Violation]:
        """Test every argument string of a privileged call against the taint set."""
        out: list[Violation] = []
        for leaf in _string_leaves(dict(step.args)):
            norm = normalize(leaf)
            if not norm:
                continue
            for frag, source_ref in taint.items():
                if frag in norm:
                    refs = [r for r in (step.span_id, source_ref) if r]
                    out.append(
                        Violation(
                            type="taint_leakage",
                            detail=(
                                f"{step.name}: untrusted fragment "
                                f"{frag[:60]!r} from {source_ref} reached a "
                                f"privileged argument without gate.sanitize"
                            ),
                            severity=Severity.CRITICAL,
                            refs=refs,
                        )
                    )
                    break  # one violation per argument leaf is enough
        return out

    # -- hook entry point -----------------------------------------------------

    def evaluate(self, ctx: ScanContext) -> list[Violation]:
        taint: dict[str, str] = {}  # normalized fragment -> source span ref
        violations: list[Violation] = []

        for step in ctx.history:
            if step.kind is not StepKind.TOOL:
                continue
            if self._is_sanitizer(step):
                self._declassify(step, taint)
                continue
            if ctx.hook is Hook.POST_TURN and self._is_sink(step):
                violations.extend(self._check_sink(step, taint))
            if self._level_untrusted(step):
                self._absorb_source(step, taint)

        if ctx.hook is Hook.PRE_TOOL:
            pending = ctx.pending
            if pending is not None and self._is_sink(pending):
                violations.extend(self._check_sink(pending, taint))

        return violations
