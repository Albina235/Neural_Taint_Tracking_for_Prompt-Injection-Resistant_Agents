"""Project OTel/OpenInference span dicts into the thin :class:`core.Trace`.

The projection is tolerant: it reads only the fields scanners need and falls
back gracefully when an attribute is missing or shaped differently across
instrumentations.

OpenInference attribute reference (subset used here):

* ``openinference.span.kind`` — ``"TOOL"`` / ``"LLM"`` / ``"RETRIEVER"`` / ...
* ``tool.name`` / ``tool.parameters`` (JSON) / ``input.value`` / ``output.value``
* ``llm.model_name`` / ``llm.token_count.*`` / ``output.value``
* ``retrieval.documents.{i}.document.id`` / ``.content``

We additionally honour two TAICF-specific attributes that the stub scaffold
and orchestrator use to mark FINAL / ENV steps:

* ``taicf.kind == "FINAL"`` → :data:`core.StepKind.FINAL`
* ``taicf.kind == "ENV"``   → :data:`core.StepKind.ENV`
"""

from __future__ import annotations

import json
from typing import cast

from core import Projection, Step, StepKind, Trace

_OI_KIND = "openinference.span.kind"
_TAICF_KIND = "taicf.kind"


class OTLPProjection(Projection):
    """Identity-ish projection from OpenInference span dicts to ``core.Trace``."""

    def __init__(self, task_id: str = "") -> None:
        self._task_id = task_id

    def project(self, spans: list[dict[str, object]]) -> Trace:
        ordered = sorted(spans, key=_start_ns)
        steps: list[Step] = []
        for span in ordered:
            step = _span_to_step(span)
            if step is not None:
                steps.append(step)
        return Trace(task_id=self._task_id, steps=steps)


def _start_ns(span: dict[str, object]) -> int:
    v = span.get("start_ns")
    return v if isinstance(v, int) else 0


def _span_to_step(span: dict[str, object]) -> Step | None:
    attrs = _attrs(span)
    taicf_kind = attrs.get(_TAICF_KIND)
    oi_kind = attrs.get(_OI_KIND)

    name = _str(span.get("name"))
    span_id = _str_or_none(span.get("span_id"))
    parent_span_id = _str_or_none(span.get("parent_span_id"))
    metadata = _metadata(span, attrs)

    if taicf_kind == "FINAL":
        return Step(
            kind=StepKind.FINAL,
            name=name or None,
            output=_extract_output(attrs),
            span_id=span_id,
            parent_span_id=parent_span_id,
            metadata=metadata,
        )

    if taicf_kind == "ENV":
        return Step(
            kind=StepKind.ENV,
            name=_str(attrs.get("taicf.env.name")) or name or None,
            args=_extract_args(attrs),
            output=_extract_output(attrs),
            span_id=span_id,
            parent_span_id=parent_span_id,
            metadata=metadata,
        )

    # Spans without a ``taicf.kind`` marker are framework auto-instrumentation
    # (LangChain TOOL/CHAIN/AGENT wrappers, retriever runners, …). They are
    # kept in the JSONL store for downstream tooling (LangFuse / Phoenix
    # mirrors) but are *not* projected — only spans we explicitly mark are
    # part of the scanner-visible ``Trace``.
    if taicf_kind == "TOOL" or (oi_kind == "TOOL" and taicf_kind == "TOOL"):
        return Step(
            kind=StepKind.TOOL,
            name=_str(attrs.get("tool.name")) or name or None,
            args=_extract_args(attrs),
            output=_extract_output(attrs),
            span_id=span_id,
            parent_span_id=parent_span_id,
            metadata=metadata,
        )

    if taicf_kind == "RETRIEVER":
        args = _extract_args(attrs)
        if "query" not in args:
            q = _str(attrs.get("input.value"))
            if q:
                args["query"] = q
        return Step(
            kind=StepKind.TOOL,
            name=name or "retrieval.search",
            args=args,
            output=_extract_retrieved_docs(attrs) or _extract_output(attrs),
            span_id=span_id,
            parent_span_id=parent_span_id,
            metadata=metadata,
        )

    if taicf_kind == "MODEL":
        return Step(
            kind=StepKind.MODEL,
            name=_str(attrs.get("llm.model_name")) or name or None,
            args=_extract_args(attrs),
            output=_extract_output(attrs),
            span_id=span_id,
            parent_span_id=parent_span_id,
            metadata=metadata,
        )

    # Anything else (OI auto-instrumentation, CHAIN/AGENT wrappers) — skip.
    return None


def _attrs(span: dict[str, object]) -> dict[str, object]:
    raw = span.get("attributes")
    return cast("dict[str, object]", raw) if isinstance(raw, dict) else {}


def _metadata(span: dict[str, object], attrs: dict[str, object]) -> dict[str, object]:
    out: dict[str, object] = {}
    for k in ("start_ns", "end_ns", "status", "trace_id"):
        v = span.get(k)
        if v is not None:
            out[k] = v
    for k, v in attrs.items():
        if k.startswith("llm.token_count.") or k == "llm.token_count":
            out[k] = v
        elif k.startswith("taicf.trust.") or k.startswith("taicf.gate."):
            # Propagate the trust namespace onto Step.metadata so the
            # Taint-Scanner can resolve provenance post-hoc.
            out[k] = v
    return out


def _extract_args(attrs: dict[str, object]) -> dict[str, object]:
    raw = attrs.get("tool.parameters")
    if isinstance(raw, str):
        parsed = _try_json(raw)
        if isinstance(parsed, dict):
            return cast("dict[str, object]", parsed)
    raw = attrs.get("input.value")
    if isinstance(raw, str):
        parsed = _try_json(raw)
        if isinstance(parsed, dict):
            return cast("dict[str, object]", parsed)
        return {"input": raw}
    return {}


def _extract_output(attrs: dict[str, object]) -> str:
    raw = attrs.get("output.value")
    if isinstance(raw, str):
        return raw
    if raw is not None:
        return json.dumps(raw, ensure_ascii=False)
    return ""


def _extract_retrieved_docs(attrs: dict[str, object]) -> str:
    docs: list[dict[str, object]] = []
    i = 0
    while True:
        prefix = f"retrieval.documents.{i}.document."
        doc_id = attrs.get(prefix + "id")
        if doc_id is None:
            break
        docs.append(
            {
                "id": doc_id,
                "content": attrs.get(prefix + "content"),
                "score": attrs.get(prefix + "score"),
            }
        )
        i += 1
    if not docs:
        return ""
    return json.dumps(docs, ensure_ascii=False)


def _str(v: object) -> str:
    return v if isinstance(v, str) else ""


def _str_or_none(v: object) -> str | None:
    return v if isinstance(v, str) else None


def _try_json(s: str) -> object:
    try:
        return json.loads(s)
    except (ValueError, TypeError):
        return None
