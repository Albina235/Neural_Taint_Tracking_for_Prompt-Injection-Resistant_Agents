"""Shared instrumentation for scaffolds: Gate wrapping + OpenInference spans.

Every scaffold runs its tool calls through :func:`wrap_tools`. The wrapper:

1. Opens an OpenInference ``TOOL`` span with ``taicf.kind=TOOL`` (canonical
   marker — the projection only emits Steps for spans carrying that).
2. Consults the optional :class:`~core.Gate`. On ``BLOCK`` the tool body is
   not invoked; ``"[BLOCKED: <reason>]"`` is returned and the span is closed
   with status ``ERROR``.
3. Invokes the wrapped async tool, then calls ``gate.after_tool`` so
   ``POST_TOOL`` scanners can react to the result.

Both the wrapper and the wrapped tools are async, matching the rest of the
world surface.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

from opentelemetry.trace import Status, StatusCode

from core import WorldHandle
from core.trust import DEFAULT_TRUST_POLICY
from evaluation.otel_setup import get_run_tracer

if TYPE_CHECKING:
    from core import Gate
    from core.world import AsyncToolFn


def wrap_tools(handle: WorldHandle, gate: Gate | None) -> WorldHandle:
    """Return a new :class:`WorldHandle` with every tool gated + traced."""
    wrapped: dict[str, AsyncToolFn] = {
        name: _wrap(name, fn, gate) for name, fn in handle.tools.items()
    }
    return WorldHandle(
        capabilities=handle.capabilities,
        tools=wrapped,
        services=dict(handle.services),
        workdir=handle.workdir,
        env=dict(handle.env),
    )


def _wrap(name: str, fn: AsyncToolFn, gate: Gate | None) -> AsyncToolFn:
    async def _call(**kwargs: object) -> str:
        tracer = get_run_tracer("taicf.tool")
        with tracer.start_as_current_span(f"tool.{name}") as span:
            trust_metadata = (
                gate.tool_metadata(name, dict(kwargs))
                if gate is not None
                else DEFAULT_TRUST_POLICY.metadata(name, dict(kwargs))
            )
            span.set_attribute("openinference.span.kind", "TOOL")
            span.set_attribute("taicf.kind", "TOOL")
            span.set_attribute("tool.name", name)
            span.set_attribute("input.value", _json(kwargs))
            span.set_attribute("tool.parameters", _json(kwargs))
            for key, value in trust_metadata.items():
                span.set_attribute(key, cast("Any", value))

            if gate is not None:
                pre = gate.before_tool(name, dict(kwargs), metadata=trust_metadata)
                if not pre.allow:
                    span.set_attribute("taicf.gate.decision", "block")
                    span.set_attribute("taicf.gate.reason", pre.reason)
                    span.set_status(Status(StatusCode.ERROR, "pre-tool block"))
                    msg = f"[BLOCKED: {pre.reason}]"
                    span.set_attribute("output.value", msg)
                    return msg
                span.set_attribute("taicf.gate.decision", "allow")

            try:
                result = await fn(**kwargs)
            except Exception as exc:
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                span.record_exception(exc)
                raise

            span.set_attribute("output.value", result)

            if gate is not None:
                post = gate.after_tool(
                    name,
                    dict(kwargs),
                    result,
                    metadata=trust_metadata,
                )
                if not post.allow:
                    span.set_attribute("taicf.post_block.reason", post.reason)
            return result

    return _call


def emit_final(text: str) -> None:
    """Emit a span marking the agent's final answer."""
    tracer = get_run_tracer("taicf.final")
    with tracer.start_as_current_span("agent.final") as span:
        span.set_attribute("taicf.kind", "FINAL")
        span.set_attribute("output.value", text)


def emit_env(name: str, payload: dict[str, object]) -> None:
    """Emit a span representing an environment-level observation."""
    tracer = get_run_tracer("taicf.env")
    with tracer.start_as_current_span(f"env.{name}") as span:
        span.set_attribute("taicf.kind", "ENV")
        span.set_attribute("taicf.env.name", name)
        span.set_attribute("input.value", _json(payload))
        span.set_attribute("output.value", _json(payload))


def _json(obj: object) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(obj)
