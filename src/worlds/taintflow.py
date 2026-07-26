"""World for the taint-flow suites: corpus, FS, HTTP sink, and two gates.

``gate.allow_quote`` releases a document only when its id is already in the
task's hidden user/policy allowlist. It cannot add entries to that allowlist.
The scanner uses the returned text and exact document provenance to
declassify only that source. An unlisted or attacker-controlled id returns
nothing, so the original taint remains.

``gate.sanitize`` is an audit-only identity operation. It records the request
but has no declassification power.
"""

from __future__ import annotations

from core import Step, StepKind, World, WorldHandle
from tools.fs import MockFS
from tools.retrieval import MockRetriever


class TaintFlowWorld(World):
    """Static corpus, in-memory FS, URL POST sink, and audit/release gates."""

    def __init__(
        self,
        *,
        corpus: dict[str, str],
        injections: dict[str, str] | None = None,
        fs_seed: dict[str, str] | None = None,
        authorized_docs: set[str] | None = None,
    ) -> None:
        self._merged = dict(corpus)
        for doc_id, payload in (injections or {}).items():
            self._merged[doc_id] = f"{self._merged.get(doc_id, '')}\n{payload}".strip()
        self._retriever = MockRetriever(self._merged)
        self._fs = MockFS(fs_seed or {})
        self._authorized = set(authorized_docs or set())
        self._sanitize_log: list[str] = []
        self._authorized_log: list[str] = []

    async def _sanitize(self, *, text: str, reason: str = "") -> str:
        """Annotation-only audit gate. Records the text and returns it.

        IMPORTANT: this gate has NO declassification power (it is not in
        ``core.trust.SANITIZER_PREFIXES``). An identity/"clean this text" gate
        cannot verify that an injection was neutralized, so treating it as a
        declassifier would let an attacker launder a payload by routing it
        here first. Legitimate declassification goes through
        ``gate.allow_quote`` (provenance / allow-list) instead.
        """
        self._sanitize_log.append(f"{reason or 'unspecified'}: {text}")
        return text

    async def _allow_quote(self, *, doc_id: str) -> str:
        """Declassify a document's text, but only if the user authorized it.

        Returns the document text (which the scanner then treats as
        declassified). For an un-authorized id it returns an empty string and
        declassifies nothing, so any taint from that document still triggers a
        violation at the privileged sink.
        """
        if doc_id not in self._authorized:
            return ""
        text = self._merged.get(doc_id, "")
        self._authorized_log.append(doc_id)
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
                "gate.allow_quote": self._allow_quote,
            },
        )

    async def observe(self) -> list[Step]:
        return [
            Step(
                kind=StepKind.ENV,
                name="fs_snapshot",
                metadata={"files": self._fs.snapshot()},
            ),
            Step(
                kind=StepKind.ENV,
                name="gate_audit",
                metadata={
                    "sanitize_calls": len(self._sanitize_log),
                    "authorized_documents": list(self._authorized_log),
                },
            ),
        ]

    async def teardown(self) -> None:
        self._sanitize_log.clear()
        self._authorized_log.clear()
