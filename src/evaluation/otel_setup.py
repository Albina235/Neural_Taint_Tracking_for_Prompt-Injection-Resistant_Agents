"""OTel TracerProvider + custom span exporter pointing at a :class:`TraceStore`.

The orchestrator opens :func:`setup_otel` for the lifetime of one run. Inside
that context:

* a fresh :class:`TracerProvider` is created (not installed as the global one
  — this keeps parallel/test runs independent);
* every emitted span is serialised to a dict and pushed to the
  :class:`~core.store.TraceStore` synchronously;
* ``openinference-instrumentation-langchain`` is bound to this provider so
  LangChain / LangGraph emits OpenInference-shaped spans into our store.

Stub scaffolds (no LangChain) fetch the active tracer via
:func:`get_run_tracer`.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from opentelemetry.sdk.trace import ReadableSpan
    from opentelemetry.trace import Tracer

    from core import TraceStore


def _try_langchain_instrumentor() -> object | None:
    """Return a LangChainInstrumentor only if langchain_core is importable."""
    try:
        import langchain_core  # noqa: F401, PLC0415
    except ImportError:
        return None
    from openinference.instrumentation.langchain import (  # noqa: PLC0415
        LangChainInstrumentor,
    )

    return LangChainInstrumentor()


_RUN_PROVIDER: ContextVar[TracerProvider | None] = ContextVar("taicf_run_provider", default=None)


class TraceStoreSpanExporter(SpanExporter):
    """SpanExporter that serialises spans and saves them to a TraceStore."""

    def __init__(self, store: TraceStore) -> None:
        self._store = store

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        batch = [_readable_to_dict(s) for s in spans]
        self._store.save(batch)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        del timeout_millis
        return True


@contextmanager
def setup_otel(
    store: TraceStore,
    run_id: str,
    config_hash: str,
    *,
    instrument_langchain: bool = True,
) -> Iterator[TracerProvider]:
    """Bind an OTel provider for the duration of one run.

    Args:
        store: where to send serialised spans.
        run_id: identifies the run; attached as a resource attribute.
        config_hash: deterministic config hash; attached as a resource attribute.
        instrument_langchain: when True, install
            :class:`LangChainInstrumentor` against this provider so LangGraph /
            LangChain code emits OpenInference spans into ``store``.

    Yields:
        The :class:`TracerProvider` for this run.
    """
    resource = Resource.create(
        {
            "service.name": "taicf",
            "taicf.run_id": run_id,
            "taicf.config_hash": config_hash,
        }
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(SimpleSpanProcessor(TraceStoreSpanExporter(store)))

    instrumentor = _try_langchain_instrumentor() if instrument_langchain else None
    if instrumentor is not None:
        instrumentor.instrument(tracer_provider=provider)  # type: ignore[attr-defined]

    token = _RUN_PROVIDER.set(provider)
    try:
        yield provider
    finally:
        _RUN_PROVIDER.reset(token)
        if instrumentor is not None:
            instrumentor.uninstrument()  # type: ignore[attr-defined]
        provider.shutdown()


def get_run_tracer(name: str = "taicf") -> Tracer:
    """Return a tracer bound to the active run's provider.

    Raises:
        RuntimeError: if called outside :func:`setup_otel`.
    """
    provider = _RUN_PROVIDER.get()
    if provider is None:
        msg = "get_run_tracer() called outside an active setup_otel() context"
        raise RuntimeError(msg)
    return provider.get_tracer(name)


def _readable_to_dict(span: ReadableSpan) -> dict[str, object]:
    ctx = span.get_span_context()
    parent = span.parent
    trace_id = f"{ctx.trace_id:032x}" if ctx is not None else ""
    span_id = f"{ctx.span_id:016x}" if ctx is not None else ""
    return {
        "name": span.name,
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": f"{parent.span_id:016x}" if parent is not None else None,
        "start_ns": span.start_time,
        "end_ns": span.end_time,
        "kind": span.kind.name,
        "status": span.status.status_code.name,
        "attributes": dict(span.attributes or {}),
        "events": [
            {
                "name": ev.name,
                "timestamp_ns": ev.timestamp,
                "attributes": dict(ev.attributes or {}),
            }
            for ev in span.events
        ],
        "resource": dict(span.resource.attributes or {}),
    }
