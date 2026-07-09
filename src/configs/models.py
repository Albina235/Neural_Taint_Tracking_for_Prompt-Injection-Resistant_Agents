"""Pydantic models for the run-config YAML."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class BudgetConfig(BaseModel):
    """Hard limits enforced by the orchestrator."""

    model_config = ConfigDict(extra="forbid")

    max_tool_calls: int = 50
    max_wall_seconds: int = 300
    max_tokens: int = 200_000


class LLMConfig(BaseModel):
    """LLM endpoint for an LLM-backed scaffold. OpenAI-compatible."""

    model_config = ConfigDict(extra="forbid")

    provider: str = "openai"
    model: str
    base_url: str | None = None
    temperature: float = 0.0
    max_tokens: int | None = None


class ScaffoldConfig(BaseModel):
    """Selects a scaffold from the registry and passes free-form params."""

    model_config = ConfigDict(extra="forbid")

    id: str
    llm: LLMConfig | None = None
    params: dict[str, object] = Field(default_factory=dict)


class SuiteConfig(BaseModel):
    """Selects a :class:`~core.TaskSuite` from the registry + an optional case filter.

    ``case_ids`` — if non-empty, run only these cases (in the order they
    appear in :meth:`TaskSuite.cases`). If empty, run every case.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    case_ids: list[str] = Field(default_factory=list)
    params: dict[str, object] = Field(default_factory=dict)


class ScannerSpec(BaseModel):
    """Selects a scanner from the registry; params are scanner-specific."""

    model_config = ConfigDict(extra="forbid")

    id: str
    params: dict[str, object] = Field(default_factory=dict)


class StoreConfig(BaseModel):
    """Where spans/violations/report are written."""

    model_config = ConfigDict(extra="forbid")

    kind: str = "jsonl"
    root: str = "runs/"


class RunMetadata(BaseModel):
    """Identity + reproducibility knobs for a single run.

    ``max_concurrency`` caps how many suite cases the orchestrator runs in
    parallel under an :class:`asyncio.Semaphore`. Default 1 = sequential.
    Values >1 also disable LangChain auto-instrumentation (its
    tracer-provider patch is process-global and races under concurrent
    cases — our own ``taicf.kind`` spans cover what scanners need anyway).
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    seed: int = 42
    max_concurrency: int = 1
    budget: BudgetConfig = Field(default_factory=BudgetConfig)


class RunConfig(BaseModel):
    """Top-level YAML schema for a single run."""

    model_config = ConfigDict(extra="forbid")

    run: RunMetadata
    scaffold: ScaffoldConfig
    suite: SuiteConfig
    scanners: list[ScannerSpec] = Field(default_factory=list)
    store: StoreConfig = Field(default_factory=StoreConfig)
