# Architecture

TAICF separates producing a run (the agent acting on a world) from judging it
(deciding whether the run violated something). The producer writes spans to a
store; the offline judge reads spans back, projects them into a thin trace, and
runs predicates over it. Scanners that declare `PRE_TOOL` can also run through
the online `Gate`, using the same predicate and trust policy before a side
effect.

## The core abstractions

A `TaskSuite` is a dataset plus an environment recipe. It declares the
capability tags every case in the suite requires (`fs`, `memory`, `retrieve`,
`gate`, …), enumerates concrete `Task` cases in a deterministic order, and
knows how to build a `World` for any of its cases. A suite is generic — it
describes "in-memory FS" or "Docker sandbox" or "static retrieval corpus"
once, and every case in it inherits that recipe.

A `Task` is one runnable case. It is pure data: an `instruction` the agent
sees, an optional `system_prompt`, hidden `attacks`, and a hidden
`ground_truth` object whose shape is per-suite. Cases vary the data that
actually differs between examples — a seed file, a poisoned key, an
injection target — while the suite-level recipe stays constant.

A `World` is the materialised environment. `setup()` returns a `WorldHandle`
carrying capability tags and a map of async tool callables. The world holds
neutral data only; nothing inside it says "this is the bad file". The
attacker/defender labels live in `Task.ground_truth` and never reach the
agent.

A `Scaffold` is the agent runtime. It receives the case's `instruction`,
`system_prompt`, and the world handle, and produces a `RunResult`. The
contract is async — tools, world lifecycle, and `Scaffold.run` are all
coroutines so the orchestrator can run cases concurrently. A scaffold
declares which capability tags it provides; `runnable(suite, scaffold)`
gates whether a suite can be executed against it.

A `Scanner` is a pure deterministic predicate over a `ScanContext`. It
declares which lifecycle hooks it attaches to (`PRE_TOOL`, `POST_TOOL`,
`POST_TURN`) and returns zero or more `Violation`s. The same scanner can
sit on both an online hook (where it returns a block decision) and the
post-turn hook (where it audits the full trace) — the logic is written
once and the runtime picks the appropriate context.

Two runtime objects wrap scanners. `Gate` runs `PRE_TOOL` and `POST_TOOL`
scanners as the scaffold executes; a violation flips its `Decision` to
disallow and the scaffold sees a `[BLOCKED]` string instead of the tool's
result. `Monitor` runs `POST_TURN` scanners over the full projected trace
post-hoc. The same scanner instance can be in both; what differs is the
context fed to it.

A `Projection` turns OTel span dicts into a thin `Trace` of `Step` objects
(kinds: `TOOL`, `ENV`, `MODEL`, `FINAL`). After the evidence-integrity layer
has accepted a run, projection is tolerant of framework-specific attributes:
it reads only the fields scanners need and skips spans that lack a
`taicf.kind` marker. Auto-instrumentation spans from LangChain stay in the
store for later observability backends but do not enter the trace scanners
see.

A `TraceStore` is the canonical evidence sink. The local JSONL store is the
source of truth for a run; any external mirror (LangFuse, Phoenix) is a
copy. The store is keyed by run id and case id, so the same suite executed
twice writes to disjoint paths.

## How a run flows

The orchestrator loads a YAML config and computes its `config_hash` (sha256
of the canonical JSON form — the hash is identical regardless of key order).
It resolves the suite, scaffold, and scanners from the registry, then
checks `runnable(suite, scaffold)`. If the scaffold does not provide every
capability the suite requires, the run errors out before any tool fires.

The orchestrator iterates the suite's cases (optionally filtered by
`suite.case_ids`) and runs each case as one asyncio task. Concurrency is
capped by `asyncio.Semaphore(run.max_concurrency)`; the default is 1, so
runs are sequential unless you opt in. When the cap is greater than 1,
LangChain auto-instrumentation is disabled to avoid cross-talk between
parallel tracer providers — our own `taicf.kind` spans cover what scanners
need anyway.

For each case the orchestrator: builds the world via `suite.build_world(case)`,
opens an OTel tracer provider bound to a per-case JSONL store, constructs a
`Gate` with the case's ground truth, and awaits `scaffold.run(...)`. The
scaffold's tool callables are wrapped so every invocation goes through the
Gate and emits a span carrying `taicf.kind=TOOL`, the canonical (dotted)
tool name, the JSON-serialised arguments, and the result. At the end the
scaffold calls `emit_final(text)` to mark the agent's final answer.

After the scaffold returns, the orchestrator reads the spans back from disk.
Before projection, it requires every span to carry one consistent
`taicf.config_hash` equal to the hash of the frozen `cfg.yaml`. Missing, mixed,
or mismatched hashes are hard failures. Only then does it project the trace and
run `Monitor`. The resulting `violations.json` carries the same hash, followed
by per-case and aggregate Markdown reports.

The same `Monitor` step can be re-run later via
`taicf score --root <root> --run <id>` without the agent. Reads and writes stay
under the supplied root, even if the copied frozen config names an older store
location. The command validates the spans before rewriting derived verdicts
and reports; it never changes `spans.jsonl`. A run is reproducible from frozen
evidence only after these checks pass.

Metric generation applies the same span checks and also validates
`violations.json.config_hash` before using saved verdicts.
`scripts/verify_evidence.py` independently rescans validated spans, checks
trust-policy fingerprints, and requires saved/offline and online/offline
agreement.

## Trust propagation and declassification

`core.trust.TrustPolicy` is the authority for tool classification. The
scaffold's wrapper asks the active `Gate` to resolve metadata for each tool;
when there is no gate (an undefended control), it uses the same default policy
directly. The following attributes are written into both the online pending
`Step` and the persisted span:

- trust level (`trusted` or `untrusted`);
- whether the tool name is known;
- whether the call is privileged;
- the trust-policy fingerprint;
- source provenance for untrusted output; and
- release provenance for a successful `gate.allow_quote`.

The scanner accepts stamped metadata only when the fingerprint matches its
resolved policy. A stale or missing fingerprint causes explicit
reclassification from the current policy and canonical tool name; stale
metadata cannot disable a privileged sink or turn an unknown source into a
trusted one. Evidence verification additionally requires every canonical tool
step in a final artifact to carry the expected current fingerprint.
Known retrieval, read, web, and `gate.sanitize` outputs are untrusted. Known
write, delete, execution, egress, and mutation tools are privileged sinks.
Unknown tools fail closed in both directions: output is untrusted and the call
is privileged.

The lexical scanner maps every normalized fragment to all provenance sources
that produced it. `gate.allow_quote` returns data only for a document that the
world's pre-existing user allowlist contains, and its span names that exact
document provenance. Declassification subtracts only that provenance from
fragments covered by the released output. It does not remove equal text from
another source, and it does not discard remaining sources from a multi-source
fragment. An attacker-controlled document therefore cannot become authorized
by requesting its own release. `gate.sanitize` only records an audit event and
never changes taint.

This is provenance-aware reconstruction of normalized lexical flow. Despite
the project title, the implementation is not a neural taint model. Taint is
attached to fragments and provenances reconstructed from completed tool
outputs, not to individual model tokens or semantic concepts.

## Invariants

A few rules are load-bearing and worth knowing before you change anything.

The `core` package depends only on pydantic and stdlib. Heavy frameworks
belong to sibling packages — `projections/` owns OTel span translation,
`scaffolds/` owns LangGraph and LangChain, `evaluation/` owns the JSONL
store and OTel setup. If you find yourself importing `langgraph` from
`core`, something is wrong.

One predicate, multiple runtimes. A scanner that needs to be both an online
block and a post-hoc audit declares both hooks and writes the logic once.
Never copy the predicate into two scanners.

Ground truth and attacks live in the Task and are visible only to scanners.
The agent sees `instruction` and `system_prompt`; everything else is
hidden. The scaffold receives `task_id` as a hint for deterministic stubs,
but real agents must ignore it.

Capability matching is strict: a suite cannot run on a scaffold that does
not provide every tag in `suite.requires()`. This is checked once before
any tool fires.

The local trace store is the canonical evidence. Anything else — an
observability dashboard, an exported flame graph — is a mirror. The store
contains enough to reconstruct the trace and re-run every scanner offline.

Scanners are pure. They cannot do I/O, call the network, or invoke an LLM.
If you ever need an LLM-assisted scanner, it has to be explicitly
non-primary and may not decide a verdict on its own.

Trust is fail closed. Adding a new tool without adding it to the shared policy
must not make it silently trusted. Register its source/sink role and provenance
rule deliberately, then cover online and offline classification in tests.
