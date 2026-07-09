# TAICF — Trustworthy Agentic AI Claim-Survival harness

TAICF is an evaluation studio for AI agents. The goal is not to build another
agent framework but to turn agent runs into auditable scientific evidence: a
precise trustworthiness claim under stated conditions, backed by a trace that
can be re-scored by another team without re-running the agent.

The unit of work is a *claim* — a falsifiable statement about an agent under
stated conditions (model, scaffold, tools, memory, retrieval, budget,
environment, evaluator). A claim survives if its metric clears the threshold
under controlled shifts (different scaffold, different memory policy, hidden
tasks, adversarial pressure). Both survival and collapse are publishable if
the trace explains why.

## How it works

An agent runs natively over a neutral world seed and emits OpenTelemetry
spans. A separate post-hoc phase reads those spans from a local store,
projects them into a thin trace, and runs scanners — pure deterministic
predicates that emit violations. The same scanner can attach to a pre-tool
hook (online block) and a post-turn hook (offline audit); the logic is
written once.

Ground truth about what counts as a violation (attacks, poisoned data,
protected areas) lives inside the task and is hidden from the agent. The
producer (agent) and the consumer (eval) are decoupled by the trace store,
so a run can be re-scored from frozen spans without spending tokens again.

## Quickstart

The local development suite runs on CPU with no external services.

    uv sync
    uv run taicf smoke

That executes three stub configs over the three lite suites
(filesystem / memory / retrieval) and writes per-case spans, violations, and
reports under `runs/`. No LLM is involved — the stub scaffold replays a
deterministic plan.

To run against a real LLM, point the OpenAI-compatible env at any
OpenAI-shaped endpoint (LM Studio, vLLM, OpenAI itself):

    cp .env.example .env
    # edit OPENAI_API_KEY and OPENAI_BASE_URL
    uv run taicf run --config configs/smoke_fs_react.yaml

See `docs/smoke-react.md` for the full LangGraph + OpenAI-compatible walkthrough.

## Documentation

`docs/architecture.md` explains the core abstractions and how a run flows
from config to scored trace. `docs/extending.md` shows how to add your own
suite, task case, scanner, or scaffold. `docs/smoke-react.md` covers the
current LLM-backed smoke setup.

## Contributing

Before opening a PR, make sure these four pass:

    uv run ruff format --check .
    uv run ruff check .
    uv run mypy
    uv run pytest

Branch from `main`, keep changes scoped, and prefer extending the existing
abstractions (a new `Scanner`, a new `TaskSuite` subclass) over reshaping
the core contract. The contract in `src/core/` is intentionally small —
heavier dependencies (LangGraph, LangChain, OTel exporters) live in sibling
packages and must never leak into `core`.

For non-trivial design choices, write a short note in `docs/` and link it
from the PR. If a change adds a new builtin scaffold, suite, or scanner,
register it in `src/registry/builtins.py` so `taicf` picks it up.
