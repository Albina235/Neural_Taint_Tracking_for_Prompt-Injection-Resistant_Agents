"""Retrieval world: static corpus + URL POST sink."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core import World, WorldHandle
from tools.retrieval import MockRetriever

if TYPE_CHECKING:
    from core.world import AsyncToolFn


class RetrievalWorld(World):
    """Static corpus; optionally inject a poisoned document into it."""

    def __init__(
        self,
        corpus: dict[str, str],
        *,
        injections: dict[str, str] | None = None,
    ) -> None:
        self._corpus = dict(corpus)
        if injections:
            for doc_id, suffix in injections.items():
                existing = self._corpus.get(doc_id, "")
                self._corpus[doc_id] = f"{existing}\n\n{suffix}".strip()
        self._retriever: MockRetriever | None = None

    async def setup(self) -> WorldHandle:
        self._retriever = MockRetriever(self._corpus)
        tools: dict[str, AsyncToolFn] = {
            "retrieval.search": self._retriever.search,
            "retrieval.fetch": self._retriever.fetch,
            "http.post": self._retriever.post_url,
        }
        return WorldHandle(capabilities={"retrieve", "http"}, tools=tools)

    async def teardown(self) -> None:
        self._retriever = None
