# Final evaluation artifacts

These directories were generated from the final implementation. Each contains
the persisted config, per-case spans, violations, Markdown reports, final
environment snapshots inside the spans, and a trace-derived `metrics.json`.

- `final-ladder-defended-stub-validated-20260727`: canonical 11-case fixed
  replay with enforcement.
- `final-ladder-undefended-stub-validated-20260727`: the same fixed replay with
  no scanners.
- `final-taint-flow-defended-stub-validated-20260727`: five attacks and two
  benign cases with enforcement.
- `final-taint-flow-undefended-stub-validated-20260727`: the same seven fixed
  plans with no scanners.
- `smoke-taint-flow-defended-ministral-lmstudio-tnt02`: one defended real-agent
  compatibility case.
- `final-taint-flow-defended-ministral-lmstudio-r1`: one complete defended
  seven-case local real-LLM run.
- `final-taint-flow-undefended-ministral-lmstudio-r1`: the separately executed
  one-run local real-LLM control.
- `lmstudio-ministral-endpoint-validation-2026-07-26`: model discovery, minimal
  chat, native tool calling, and existing-scaffold parsing evidence.
- `evidence-integrity-validated-20260727`: verification receipt for every final
  deterministic and local real-LLM run.
- `real-llm-semantic-utility-assessment-20260727.json`: supplemental manual
  utility review; it does not replace exact-state metrics.
- `deterministic-regeneration-comparison-20260727.json`: old/new hash and
  aggregate comparison.

Fixed replay is a deterministic regression mechanism, not a real LLM agent.
The local real-agent results use
`mistralai/ministral-3-14b-reasoning`, hosted by LM Studio through its
OpenAI-compatible endpoint, for one repetition per condition. Historical
artifacts under `runs/` were not modified or used for final numerical claims.

The older deterministic directories without `validated-20260727` are retained
unchanged but have span/config-hash mismatches. They are historical only and
are excluded from final claims and the intended submission evidence set.

Reproduction commands and metric definitions are in
`docs/evaluation.md`. Numerical claims in the README and final report are
traceable to validated `metrics.json` files and the integrity receipt here.
