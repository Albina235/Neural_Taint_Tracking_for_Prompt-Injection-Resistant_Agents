"""Resolved trust policy and the ``taicf.trust.*`` trace namespace.

The policy is shared by online enforcement, span instrumentation, and offline
rescoring.  Every new span carries a policy fingerprint; scanners only trust
stamped classifications when that fingerprint matches their configured policy.
This prevents stale or differently configured span labels from silently changing
the result of a re-score.

Unknown tools fail closed:

* their outputs are treated as untrusted sources; and
* their calls are treated as privileged sinks.

This is conservative but keeps an unregistered plugin or misspelled tool from
creating either an untracked source or an unchecked side-effect channel.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

# --- span attribute keys -----------------------------------------------------

TRUST_LEVEL_ATTR = "taicf.trust.level"
TRUST_SOURCE_ATTR = "taicf.trust.source"
TRUST_KNOWN_ATTR = "taicf.trust.known"
TRUST_PRIVILEGED_ATTR = "taicf.trust.privileged"
TRUST_POLICY_ATTR = "taicf.trust.policy"
TRUST_PROVENANCE_ATTR = "taicf.trust.provenance"
TRUST_RELEASE_PROVENANCE_ATTR = "taicf.trust.release_provenance"
TRUST_NAMESPACE_PREFIX = "taicf.trust."

# --- trust levels ------------------------------------------------------------

LEVEL_TRUSTED = "trusted"
LEVEL_UNTRUSTED = "untrusted"
LEVEL_SANITIZED = "sanitized"

# --- default tool classes ----------------------------------------------------

# Outputs that can contain attacker-controlled content.  ``gate.sanitize`` is
# intentionally included: it is an audit-only identity gate, not a declassifier.
UNTRUSTED_SOURCE_PREFIXES: tuple[str, ...] = (
    "retrieval.",
    "memory.read",
    "memory.list",
    "fs.read",
    "fs.list",
    "http.get",
    "web.",
    "gate.sanitize",
)

# The only declassifier.  Its world implementation releases a document only
# when that document id is in the hidden user/policy allow-list.
SANITIZER_PREFIXES: tuple[str, ...] = ("gate.allow_quote",)

# Side-effecting tools whose arguments are checked for lexical taint.
PRIVILEGED_SINK_PREFIXES: tuple[str, ...] = (
    "fs.write",
    "fs.delete",
    "bash.",
    "exec",
    "http.post",
    "email.send",
    "memory.write",
    "memory.delete",
    "sql.exec",
)

# Known tools that are neither untrusted sources, declassifiers, nor privileged
# sinks.  The shipped worlds currently do not require any entries, but the class
# is explicit so extensions never become trusted merely by being unknown.
TRUSTED_TOOL_PREFIXES: tuple[str, ...] = ()


def _matches(name: str, prefixes: tuple[str, ...]) -> bool:
    return any(name == prefix or name.startswith(prefix) for prefix in prefixes)


@dataclass(frozen=True)
class TrustResolution:
    """One tool's resolved policy classification."""

    level: str
    known: bool
    privileged: bool


@dataclass(frozen=True)
class TrustPolicy:
    """Immutable trust policy used by all runtime stages."""

    untrusted_sources: tuple[str, ...] = UNTRUSTED_SOURCE_PREFIXES
    sanitizers: tuple[str, ...] = SANITIZER_PREFIXES
    privileged_sinks: tuple[str, ...] = PRIVILEGED_SINK_PREFIXES
    trusted_tools: tuple[str, ...] = TRUSTED_TOOL_PREFIXES
    unknown_is_untrusted: bool = True
    unknown_is_privileged: bool = True

    @property
    def fingerprint(self) -> str:
        payload = json.dumps(
            {
                "untrusted_sources": self.untrusted_sources,
                "sanitizers": self.sanitizers,
                "privileged_sinks": self.privileged_sinks,
                "trusted_tools": self.trusted_tools,
                "unknown_is_untrusted": self.unknown_is_untrusted,
                "unknown_is_privileged": self.unknown_is_privileged,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def is_known(self, name: str) -> bool:
        groups = (
            self.untrusted_sources,
            self.sanitizers,
            self.privileged_sinks,
            self.trusted_tools,
        )
        return any(_matches(name, group) for group in groups)

    def is_sanitizer(self, name: str) -> bool:
        return _matches(name, self.sanitizers)

    def is_untrusted_source(self, name: str) -> bool:
        if _matches(name, self.untrusted_sources):
            return True
        return not self.is_known(name) and self.unknown_is_untrusted

    def is_privileged_sink(self, name: str) -> bool:
        if _matches(name, self.privileged_sinks):
            return True
        return not self.is_known(name) and self.unknown_is_privileged

    def resolve(self, name: str) -> TrustResolution:
        known = self.is_known(name)
        if self.is_sanitizer(name):
            level = LEVEL_SANITIZED
        elif self.is_untrusted_source(name):
            level = LEVEL_UNTRUSTED
        else:
            level = LEVEL_TRUSTED
        return TrustResolution(
            level=level,
            known=known,
            privileged=self.is_privileged_sink(name),
        )

    def metadata(self, name: str, args: dict[str, object]) -> dict[str, object]:
        """Return the canonical metadata stamped online and into spans."""
        resolution = self.resolve(name)
        metadata: dict[str, object] = {
            TRUST_LEVEL_ATTR: resolution.level,
            TRUST_SOURCE_ATTR: name,
            TRUST_KNOWN_ATTR: resolution.known,
            TRUST_PRIVILEGED_ATTR: resolution.privileged,
            TRUST_POLICY_ATTR: self.fingerprint,
        }
        provenance = source_provenance(name, args)
        if provenance:
            metadata[TRUST_PROVENANCE_ATTR] = provenance
        release = release_provenance(name, args)
        if release:
            metadata[TRUST_RELEASE_PROVENANCE_ATTR] = release
        return metadata


DEFAULT_TRUST_POLICY = TrustPolicy()


def source_provenance(name: str, args: dict[str, object]) -> str:
    """Resolve a stable source identity from canonical tool arguments."""
    if name == "retrieval.fetch":
        doc_id = args.get("doc_id")
        if isinstance(doc_id, str) and doc_id:
            return f"document:{doc_id}"
    if name == "memory.read":
        key = args.get("key")
        if isinstance(key, str) and key:
            return f"memory:{key}"
    if name == "http.get":
        url = args.get("url")
        if isinstance(url, str) and url:
            return f"url:{url}"
    return f"tool:{name}" if name else ""


def release_provenance(name: str, args: dict[str, object]) -> str:
    """Resolve the provenance identity a declassifier is allowed to release."""
    if name == "gate.allow_quote":
        doc_id = args.get("doc_id")
        if isinstance(doc_id, str) and doc_id:
            return f"document:{doc_id}"
    return ""


def classify_tool(name: str, policy: TrustPolicy | None = None) -> str:
    """Return the output trust level under ``policy``."""
    return (policy or DEFAULT_TRUST_POLICY).resolve(name).level


def is_untrusted_source(
    name: str,
    prefixes: tuple[str, ...] | None = None,
) -> bool:
    if prefixes is not None:
        policy = TrustPolicy(untrusted_sources=prefixes)
        return policy.is_untrusted_source(name)
    return DEFAULT_TRUST_POLICY.is_untrusted_source(name)


def is_sanitizer(name: str, prefixes: tuple[str, ...] | None = None) -> bool:
    return _matches(name, prefixes or SANITIZER_PREFIXES)


def is_privileged_sink(
    name: str,
    prefixes: tuple[str, ...] | None = None,
) -> bool:
    if prefixes is not None:
        policy = TrustPolicy(privileged_sinks=prefixes)
        return policy.is_privileged_sink(name)
    return DEFAULT_TRUST_POLICY.is_privileged_sink(name)


def _assert_disjoint(policy: TrustPolicy = DEFAULT_TRUST_POLICY) -> None:
    """Explicit prefix classes must be mutually exclusive."""
    groups = {
        "untrusted": policy.untrusted_sources,
        "sanitizer": policy.sanitizers,
        "privileged": policy.privileged_sinks,
        "trusted": policy.trusted_tools,
    }
    names = list(groups)
    for i, first in enumerate(names):
        for second in names[i + 1 :]:
            clash = {
                (left, right)
                for left in groups[first]
                for right in groups[second]
                if left.startswith(right) or right.startswith(left)
            }
            if clash:
                raise AssertionError(
                    f"trust prefix classes {first!r} and {second!r} overlap: {sorted(clash)}"
                )


_assert_disjoint()
