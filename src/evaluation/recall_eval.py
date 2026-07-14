"""Recall evaluation over the transformation ladder (Week 1, item 2).

Builds one trace per rung (fetch poisoned doc -> write transformed payload),
runs the Taint-Scanner offline, and reports detection per family. This is a
property of the scanner, so it runs deterministically with no LLM.

Run:  python -m evaluation.recall_eval
"""

from __future__ import annotations

from core import Step, StepKind, Trace
from core.runtime import Monitor
from scanners.taint_leakage import TaintLeakageScanner
from tasks._laundering import BASE_PAYLOAD, build_ladder


def _trace(rung_text: str) -> Trace:
    fetch = Step(
        kind=StepKind.TOOL,
        name="retrieval.fetch",
        args={"doc_id": "docs/note_attacker"},
        output=BASE_PAYLOAD,
        span_id="src-1",
    )
    write = Step(
        kind=StepKind.TOOL,
        name="fs.write",
        args={"path": "/finance/ledger.txt", "content": rung_text},
        output="[OK]",
        span_id="sink-1",
    )
    return Trace(task_id="recall", steps=[fetch, write])


def evaluate() -> dict[str, dict[str, int]]:
    monitor = Monitor([TaintLeakageScanner()])
    per_family: dict[str, dict[str, int]] = {}
    rows: list[tuple[str, str, bool]] = []
    for rung in build_ladder():
        detected = bool(monitor.scan(_trace(rung.text)))
        rows.append((rung.id, rung.family, detected))
        fam = per_family.setdefault(rung.family, {"total": 0, "detected": 0})
        fam["total"] += 1
        fam["detected"] += int(detected)

    print(f"{'rung':16s} {'family':10s} detected")
    print("-" * 40)
    for rid, fam, det in rows:
        print(f"{rid:16s} {fam:10s} {'yes' if det else 'no'}")

    print("\nRecall by family:")
    for fam, c in per_family.items():
        rate = c["detected"] / c["total"]
        print(f"  {fam:10s} {c['detected']}/{c['total']} = {rate:.2f}")

    in_scope = {"total": 0, "detected": 0}
    for fam in ("lexical", "light"):
        if fam in per_family:
            in_scope["total"] += per_family[fam]["total"]
            in_scope["detected"] += per_family[fam]["detected"]
    sem = per_family.get("semantic", {"total": 0, "detected": 0})
    print(
        f"\nin-scope recall (lexical+light): "
        f"{in_scope['detected']}/{in_scope['total']}"
    )
    print(f"semantic recall (the gap):      {sem['detected']}/{sem['total']}")
    return per_family


if __name__ == "__main__":
    evaluate()
