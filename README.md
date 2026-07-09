# Neural Taint Tracking for Prompt-Injection-Resistant Agents

This project adds a **taint-tracking defense against indirect prompt injection**
to AI agents. An attacker can hide an instruction inside untrusted data (search
results, memory, web pages); the agent may then use that data to trigger a
dangerous tool call (writing a file, running a command, sending data out). The
defense labels the provenance of every tool output and detects (and can block)
untrusted data that reaches a privileged tool call without being sanitized.

The project is built on top of the **TAICF harness** (an evaluation studio for
agent runs, see *Acknowledgements*). TAICF provides the tracing pipeline, the
scanner interface, and the deterministic test runner. My contribution is the
trust-propagation layer, the Taint-Scanner, and the taint-flow test suite
described below.

## How the defense works

1. Every tool output is labelled with its trust level when the tool runs, and
   the label travels with the trace.
2. The Taint-Scanner collects the text produced by untrusted tools and checks
   whether that same text later appears inside a privileged tool call. Before
   comparing, it normalizes the text (lowercase, strip punctuation, fix
   spacing), so small edits do not fool it.
3. If untrusted text reaches a privileged call and was **not** first cleaned by
   `gate.sanitize`, the scanner raises a `taint_leakage` violation. The same
   check can block the call online, or audit the whole run offline.

The scanner is a pure deterministic function (no LLM, no randomness), so a run
can be re-scored from saved data and always gives the same verdict.

## Quickstart

Runs on CPU, no external services, no API key.

    uv sync
    uv run pytest tests/test_taint_scanner.py -q      # 12 unit tests
    uv run taicf run -c configs/smoke_taint_stub.yaml # deterministic run
    uv run taicf score -r smoke-taint-stub            # re-score saved data

The run writes per-case spans, violations, and a report under `runs/`.


## Running against a real LLM

The scanner is designed to work with a real agent too. Point an
OpenAI-compatible endpoint (LM Studio, vLLM, OpenAI) via `.env`, add
`- id: "taint_leakage"` to the `scanners:` list of an LLM config, and run it the
same way. See `docs/smoke-react.md` for the LLM-backed setup.

## Acknowledgements

Built on the **TAICF** evaluation harness, which provides the core
abstractions (`src/core/`), the OTel tracing pipeline, the trace store, and the
deterministic runner. See `docs/architecture.md` for the harness design and
`docs/extending.md` for how new scanners and suites plug in.