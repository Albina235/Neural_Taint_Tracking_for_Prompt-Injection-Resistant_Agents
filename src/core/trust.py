"""The ``taicf.trust.*`` metadata namespace and tool-level trust classification.

This module is the single source of truth for how a tool invocation is
stamped with a trust level. Both scaffolds (span instrumentation) and the
Taint-Scanner (post-hoc lineage resolution) import from here, so the online
and offline views can never disagree on what counts as an untrusted source,
a sanitizer, or a privileged sink.

Design notes
------------
* Levels form a 3-point lattice: ``trusted`` < ``sanitized`` < ``untrusted``
  in the sense of "taint": outputs of *untrusted* sources enter the taint
  set; a *sanitizer* invocation declassifies the exact strings it processed;
  everything else is trusted by construction.
* Classification is by canonical dotted tool name (prefix match), because in
  TAICF the tool name is the stable identity that survives the OTLP round
  trip (``tool.name`` attribute -> ``Step.name``).
* The sets are intentionally overridable per-scanner via YAML params — the
  defaults below describe the shipped mock worlds.
"""

from __future__ import annotations

# --- span attribute keys (the taicf.trust.* namespace) ---------------------

TRUST_LEVEL_ATTR = "taicf.trust.level"
TRUST_SOURCE_ATTR = "taicf.trust.source"
TRUST_NAMESPACE_PREFIX = "taicf.trust."

# --- trust levels -----------------------------------------------------------

LEVEL_TRUSTED = "trusted"
LEVEL_UNTRUSTED = "untrusted"
LEVEL_SANITIZED = "sanitized"

# --- default tool classification (prefix match on canonical dotted names) ---

#: Tools whose *outputs* are attacker-controllable by construction
#: (retrieval / memory / inbound web). Stamped ``untrusted``.
UNTRUSTED_SOURCE_PREFIXES: tuple[str, ...] = (
    "retrieval.",
    "memory.read",
    "memory.list",
    "http.get",
    "web.",
)

#: Declassification gate. Only ``gate.allow_quote`` actually declassifies, and
#: it does so by *provenance*: it releases the text of a user-allow-listed
#: document (see ``worlds.taintflow``), which an injection cannot forge.
#:
#: ``gate.sanitize`` is deliberately NOT here. A value-based scanner cannot
#: verify that an identity/"clean this text" gate really neutralized an
#: injection, so treating it as a declassifier would let an attacker launder a
#: payload simply by routing it through the gate before a privileged write.
#: ``gate.sanitize`` therefore remains an annotation-only audit tool with no
#: declassification power; the certificate makes no claim about it.
SANITIZER_PREFIXES: tuple[str, ...] = ("gate.allow_quote",)

#: Privileged sinks: side-effecting tools whose *arguments* must satisfy the
#: lexical non-flow property checked by the Taint-Scanner.
PRIVILEGED_SINK_PREFIXES: tuple[str, ...] = (
    "fs.write",
    "fs.delete",
    "bash.",
    "exec",
    "http.post",
    "email.send",
    "memory.write",
    "sql.exec",
)


def _matches(name: str, prefixes: tuple[str, ...]) -> bool:
    return any(name == p or name.startswith(p) for p in prefixes)


def classify_tool(name: str) -> str:
    """Return the trust level stamped on a tool invocation span."""
    if _matches(name, SANITIZER_PREFIXES):
        return LEVEL_SANITIZED
    if _matches(name, UNTRUSTED_SOURCE_PREFIXES):
        return LEVEL_UNTRUSTED
    return LEVEL_TRUSTED


def is_untrusted_source(name: str, prefixes: tuple[str, ...] | None = None) -> bool:
    return _matches(name, prefixes or UNTRUSTED_SOURCE_PREFIXES)


def is_sanitizer(name: str, prefixes: tuple[str, ...] | None = None) -> bool:
    return _matches(name, prefixes or SANITIZER_PREFIXES)


def is_privileged_sink(name: str, prefixes: tuple[str, ...] | None = None) -> bool:
    return _matches(name, prefixes or PRIVILEGED_SINK_PREFIXES)


def _assert_disjoint() -> None:
    """The three tool classes must be mutually exclusive.

    The scanner walks each step once and dispatches on class (sanitizer ->
    declassify; untrusted -> absorb; sink -> check). Overlapping prefixes would
    make that dispatch ambiguous — e.g. a tool that is both source and sink
    would have its sink checked before its own output is absorbed. Fail loudly
    at import time instead of silently mis-tracking taint.
    """
    groups = {
        "untrusted": UNTRUSTED_SOURCE_PREFIXES,
        "sanitizer": SANITIZER_PREFIXES,
        "privileged": PRIVILEGED_SINK_PREFIXES,
    }
    names = list(groups)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            clash = {
                (pa, pb)
                for pa in groups[a]
                for pb in groups[b]
                if pa.startswith(pb) or pb.startswith(pa)
            }
            if clash:
                raise AssertionError(
                    f"trust prefix classes {a!r} and {b!r} overlap: {sorted(clash)}"
                )


_assert_disjoint()
