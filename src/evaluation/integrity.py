"""Hard-fail validation for frozen evaluation evidence.

Rescoring is meaningful only when every span belongs to the exact frozen
configuration being loaded.  These helpers validate that binding before a
projection, scanner, saved verdict, or metric is trusted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

CONFIG_HASH_RESOURCE_ATTR = "taicf.config_hash"


class EvidenceIntegrityError(ValueError):
    """Raised when persisted evidence is missing or inconsistent."""


def validate_span_config_hashes(
    spans: list[dict[str, object]],
    *,
    expected_hash: str,
    source: str | Path,
) -> str:
    """Require one non-empty config hash on every span and match ``cfg.yaml``."""
    label = str(source)
    if not spans:
        raise EvidenceIntegrityError(f"{label}: no spans available for validation")

    hashes: list[str] = []
    missing: list[int] = []
    for index, span in enumerate(spans, start=1):
        resource = span.get("resource")
        value = resource.get(CONFIG_HASH_RESOURCE_ATTR) if isinstance(resource, dict) else None
        if not isinstance(value, str) or not value:
            missing.append(index)
            continue
        hashes.append(value)

    if missing:
        preview = ", ".join(str(index) for index in missing[:5])
        suffix = "..." if len(missing) > 5 else ""
        raise EvidenceIntegrityError(
            f"{label}: missing {CONFIG_HASH_RESOURCE_ATTR!r} on span line(s) {preview}{suffix}"
        )

    unique = sorted(set(hashes))
    if len(unique) != 1:
        raise EvidenceIntegrityError(
            f"{label}: mixed {CONFIG_HASH_RESOURCE_ATTR!r} values: {unique}"
        )
    actual = unique[0]
    if actual != expected_hash:
        raise EvidenceIntegrityError(
            f"{label}: span config hash {actual!r} does not match frozen "
            f"cfg.yaml hash {expected_hash!r}"
        )
    return actual


def load_validated_violations(
    path: str | Path,
    *,
    expected_hash: str,
) -> list[dict[str, object]]:
    """Load saved violations only when their config hash matches the run."""
    target = Path(path)
    if not target.exists():
        raise EvidenceIntegrityError(f"{target}: missing violations artifact")
    payload = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EvidenceIntegrityError(f"{target}: violations artifact must be a JSON object")
    actual = payload.get("config_hash")
    if not isinstance(actual, str) or not actual:
        raise EvidenceIntegrityError(f"{target}: missing 'config_hash'")
    if actual != expected_hash:
        raise EvidenceIntegrityError(
            f"{target}: violations config hash {actual!r} does not match frozen "
            f"cfg.yaml hash {expected_hash!r}"
        )
    violations = payload.get("violations")
    if not isinstance(violations, list):
        raise EvidenceIntegrityError(f"{target}: 'violations' must be a JSON list")
    if not all(isinstance(item, dict) for item in violations):
        raise EvidenceIntegrityError(f"{target}: every violation must be a JSON object")
    return cast("list[dict[str, object]]", violations)
