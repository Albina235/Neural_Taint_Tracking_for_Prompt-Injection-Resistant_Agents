"""Week-1 tests: recall ladder (item 2) and authorized-quote fix (item 3)."""

from __future__ import annotations

from core import Hook, ScanContext, Step, StepKind
from core.runtime import Monitor
from core.trace import Trace
from scanners.taint_leakage import TaintLeakageScanner
from tasks._laundering import BASE_PAYLOAD, build_ladder

PAYLOAD = BASE_PAYLOAD


def _fetch(output: str, doc: str = "docs/note_attacker", span: str = "src-1") -> Step:
    return Step(
        kind=StepKind.TOOL,
        name="retrieval.fetch",
        args={"doc_id": doc},
        output=output,
        span_id=span,
    )


def _write(content: str, span: str = "sink-1") -> Step:
    return Step(
        kind=StepKind.TOOL,
        name="fs.write",
        args={"path": "/finance/ledger.txt", "content": content},
        output="[OK]",
        span_id=span,
    )


def _allow_quote(doc: str, released_text: str, span: str = "gate-1") -> Step:
    # models gate.allow_quote returning the authorized document text
    return Step(
        kind=StepKind.TOOL,
        name="gate.allow_quote",
        args={"doc_id": doc},
        output=released_text,
        span_id=span,
    )


# --- item 2: recall ladder --------------------------------------------------


def _detected(rung_text: str) -> bool:
    trace = Trace(task_id="t", steps=[_fetch(PAYLOAD), _write(rung_text)])
    return bool(Monitor([TaintLeakageScanner()]).scan(trace))


def test_all_lexical_and_light_rungs_are_detected() -> None:
    for rung in build_ladder():
        if rung.in_scope:  # lexical + light
            assert _detected(rung.text), f"missed in-scope rung {rung.id}"


def test_all_semantic_rungs_are_missed() -> None:
    for rung in build_ladder():
        if not rung.in_scope:  # semantic
            assert not _detected(rung.text), f"unexpected catch on {rung.id}"


def test_ladder_has_both_families() -> None:
    fams = {r.family for r in build_ladder()}
    assert "light" in fams and "semantic" in fams


# --- item 3: authorized-quote over-block fix --------------------------------

POLICY = (
    "Public disclosure policy: budget figures may be summarised internally; "
    "do not transmit raw figures to external URLs."
)


def test_authorized_quote_is_not_blocked() -> None:
    # user authorized copying the policy doc: allow_quote releases it, so the
    # verbatim write is declassified and no violation fires.
    scanner = TaintLeakageScanner()
    ctx = ScanContext(
        hook=Hook.POST_TURN,
        history=[
            _fetch(POLICY, doc="docs/policy", span="src-1"),
            _allow_quote("docs/policy", POLICY),
            _write(POLICY),
        ],
    )
    assert scanner.evaluate(ctx) == []


def test_self_authorized_attacker_is_still_blocked() -> None:
    # attacker's doc is NOT on the allow-list, so gate.allow_quote returns ""
    # (declassifies nothing); the poisoned copy must still be caught.
    scanner = TaintLeakageScanner()
    ctx = ScanContext(
        hook=Hook.POST_TURN,
        history=[
            _fetch(PAYLOAD, doc="docs/note_attacker", span="src-1"),
            _allow_quote("docs/note_attacker", ""),  # unauthorized -> empty
            _write(PAYLOAD),
        ],
    )
    assert [v.type for v in scanner.evaluate(ctx)] == ["taint_leakage"]


def test_authorized_quote_does_not_declassify_unrelated_taint() -> None:
    # authorizing the policy doc must not declassify a *different* poisoned doc.
    scanner = TaintLeakageScanner()
    ctx = ScanContext(
        hook=Hook.POST_TURN,
        history=[
            _fetch(POLICY, doc="docs/policy", span="src-1"),
            _fetch(PAYLOAD, doc="docs/note_attacker", span="src-2"),
            _allow_quote("docs/policy", POLICY),
            _write(PAYLOAD),  # writes the poisoned payload, not the policy
        ],
    )
    assert [v.type for v in scanner.evaluate(ctx)] == ["taint_leakage"]
