"""World for the taint-flow suite: retrieval corpus + FS + HTTP sink + gate.

Composes the existing mocks (:class:`tools.retrieval.MockRetriever`,
:class:`tools.fs.MockFS`) and adds the ``gate.sanitize`` declassification
tool from the proposal's Practical Formulation. The gate is *deterministic*
in this world (identity pass-through with an audit log); wiring a neural
Sanitizer agent behind the same tool name is a later-stage swap that does not
change the scanner or the certificate statement.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core import World, WorldHandle
from tools.fs import MockFS
from tools.retrieval import MockRetriever

if TYPE_CHECKING:
    from core.trace import Step


class TaintFlowWorld(World):
    """Static corpus + in-memory FS + URL POST sink + sanitize gate."""

    def __init__(
        self,
        *,
        corpus: dict[str, str],
        injections: dict[str, str] | None = None,
        fs_seed: dict[str, str] | None = None,
    ) -> None:
        merged = dict(corpus)
        for doc_id, payload in (injections or {}).items():
            merged[doc_id] = f"{merged.get(doc_id, '')}\n{payload}".strip()
        self._retriever = MockRetriever(merged)
        self._fs = MockFS(fs_seed or {})
        self._sanitize_log: list[str] = []

    async def _sanitize(self, *, text: str) -> str:
        """Declassification gate: audit-log the text and release it.

        The value-based Taint-Scanner treats the exact strings processed here
        as declassified from this point in the trace onward.
        """
        self._sanitize_log.append(text)
        return text

    async def setup(self) -> WorldHandle:
        return WorldHandle(
            capabilities={"retrieve", "fs", "http", "gate"},
            tools={
                "retrieval.search": self._retriever.search,
                "retrieval.fetch": self._retriever.fetch,
                "http.post": self._retriever.post_url,
                "fs.list": self._fs.list,
                "fs.read": self._fs.read,
                "fs.write": self._fs.write,
                "fs.delete": self._fs.delete,
                "gate.sanitize": self._sanitize,
            },
        )

    async def observe(self) -> list[Step]:
        return []

    async def teardown(self) -> None:
        self._sanitize_log.clear()
