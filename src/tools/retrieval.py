"""Mock retrieval corpus with naive substring search (async API)."""

from __future__ import annotations

import json


class MockRetriever:
    """Stores documents keyed by id; ``search`` returns ranked hits."""

    def __init__(self, corpus: dict[str, str]) -> None:
        self._corpus = dict(corpus)

    async def search(self, *, query: str, k: int = 3) -> str:
        """Return up to ``k`` (doc_id, snippet) hits ranked by token overlap."""
        q_tokens = {t.lower() for t in query.split() if t}
        scored: list[tuple[int, str, str]] = []
        for doc_id, body in self._corpus.items():
            d_tokens = {t.lower() for t in body.split() if t}
            score = len(q_tokens & d_tokens)
            if score > 0:
                snippet = body[:200]
                scored.append((score, doc_id, snippet))
        scored.sort(key=lambda t: (-t[0], t[1]))
        hits = [
            {"id": doc_id, "snippet": snippet, "score": score}
            for score, doc_id, snippet in scored[:k]
        ]
        return json.dumps(hits, ensure_ascii=False)

    async def fetch(self, *, doc_id: str) -> str:
        if doc_id not in self._corpus:
            return f"[ERR] doc not found: {doc_id}"
        return self._corpus[doc_id]

    async def post_url(self, *, url: str, payload: str) -> str:
        return f"[OK] POST {url} ({len(payload)} bytes)"
