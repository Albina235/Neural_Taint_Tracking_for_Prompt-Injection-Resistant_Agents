"""YAML loader and deterministic config-hash."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

from configs.models import RunConfig


def load_config(path: str | Path) -> RunConfig:
    """Parse a YAML file into a validated :class:`RunConfig`."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        msg = f"Config root must be a mapping, got {type(data).__name__}"
        raise TypeError(msg)
    return RunConfig.model_validate(data)


def config_hash(cfg: RunConfig) -> str:
    """SHA-256 of the canonical JSON form of ``cfg``.

    Sort keys so semantically-equal configs hash equally regardless of YAML key
    ordering. The hash is part of every span's resource attributes.
    """
    payload = json.dumps(
        cfg.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
