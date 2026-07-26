"""OTLP projection: maps OpenInference span dicts into core.Trace."""

from __future__ import annotations

from core import StepKind
from core.trust import DEFAULT_TRUST_POLICY
from projections import OTLPProjection


def _span(
    name: str,
    attrs: dict[str, object],
    *,
    start_ns: int = 0,
    span_id: str = "s",
) -> dict[str, object]:
    return {
        "name": name,
        "trace_id": "t",
        "span_id": span_id,
        "parent_span_id": None,
        "start_ns": start_ns,
        "end_ns": start_ns + 1,
        "kind": "INTERNAL",
        "status": "OK",
        "attributes": attrs,
        "events": [],
        "resource": {},
    }


def test_projects_tool_span() -> None:
    spans = [
        _span(
            "tool.fs.write",
            {
                "openinference.span.kind": "TOOL",
                "taicf.kind": "TOOL",
                "tool.name": "fs.write",
                "tool.parameters": '{"path": "/tmp/a", "content": "x"}',
                "output.value": "[OK] wrote 1 bytes to /tmp/a",
            },
        )
    ]
    trace = OTLPProjection("t1").project(spans)
    assert len(trace.steps) == 1
    s = trace.steps[0]
    assert s.kind is StepKind.TOOL
    assert s.name == "fs.write"
    assert s.args["path"] == "/tmp/a"
    assert s.output.startswith("[OK]")


def test_skips_oi_tool_span_without_taicf_kind() -> None:
    """OI auto-instrumentation TOOL spans are kept in the store but skipped here."""
    spans = [
        _span(
            "fs_write",
            {
                "openinference.span.kind": "TOOL",
                "tool.name": "fs_write",
                "input.value": "/tmp/a",
            },
        )
    ]
    assert OTLPProjection().project(spans).steps == []


def test_projects_final_and_env_by_taicf_kind() -> None:
    spans = [
        _span(
            "agent.final",
            {"taicf.kind": "FINAL", "output.value": "done"},
            start_ns=10,
            span_id="f",
        ),
        _span(
            "env.fs_diff",
            {
                "taicf.kind": "ENV",
                "taicf.env.name": "fs_diff",
                "input.value": "{}",
                "output.value": "{}",
            },
            start_ns=5,
            span_id="e",
        ),
    ]
    trace = OTLPProjection().project(spans)
    kinds = [s.kind for s in trace.steps]
    assert kinds == [StepKind.ENV, StepKind.FINAL]
    assert trace.final() == "done"


def test_skips_chain_agent_spans() -> None:
    spans = [
        _span("chain.AgentExecutor", {"openinference.span.kind": "CHAIN"}),
        _span("agent.run", {"openinference.span.kind": "AGENT"}),
    ]
    assert OTLPProjection().project(spans).steps == []


def test_propagates_taicf_trust_metadata() -> None:
    spans = [
        _span(
            "tool.retrieval.fetch",
            {
                "openinference.span.kind": "TOOL",
                "taicf.kind": "TOOL",
                "tool.name": "retrieval.fetch",
                "tool.parameters": '{"doc_id": "docs/x"}',
                "output.value": "payload",
                "taicf.trust.level": "untrusted",
                "taicf.trust.source": "retrieval.fetch",
                "taicf.trust.policy": DEFAULT_TRUST_POLICY.fingerprint,
                "taicf.gate.decision": "allow",
            },
        )
    ]
    step = OTLPProjection("t").project(spans).steps[0]
    assert step.metadata["taicf.trust.level"] == "untrusted"
    assert step.metadata["taicf.trust.source"] == "retrieval.fetch"
    assert step.metadata["taicf.trust.policy"] == DEFAULT_TRUST_POLICY.fingerprint
    assert step.metadata["taicf.gate.decision"] == "allow"
