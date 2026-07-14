"""World for the taint-flow suites: corpus + FS + HTTP sink + two gates.

Adds, on top of the previous stage, an **authorized-quote gate**
(``gate.allow_quote``) for Week 1 item 3 (reduce over-blocking).

Motivation. The value-based scanner has no notion of "the user allowed this
copy", so a legitimate, user-authorized quote of a retrieved document into a
privileged write is flagged as a leak (the over-block case). The fix is a
declassification path the agent can take *only for content the user actually
authorized*: ``gate.allow_quote(doc_id)`` returns and declassifies the document
text, but **only if the id is on the task's allow-list**. If the agent (or an
injected instruction) tries to self-authorize an un-listed document, the gate
returns nothing and declassifies nothing, so the taint survives and the write
is still blocked. Authorization is a user/policy decision and is therefore not
attacker-controllable.

Because ``gate.allow_quote`` is classified as a *sanitizer*
(``core.trust.SANITIZER_PREFIXES``), the existing scanner declassification
logic handles it with no change to the scanner itself.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core import World, WorldHandle
from tools.fs import MockFS
from tools.retrieval import MockRetriever

if TYPE_CHECKING:
    from core.trace import Step


class TaintFlowWorld(World):
    """Static corpus + in-memory FS + URL POST sink + sanitize/allow-quote gates."""

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
        return []

    async def teardown(self) -> None:
        self._sanitize_log.clear()
        self._authorized_log.clear()
