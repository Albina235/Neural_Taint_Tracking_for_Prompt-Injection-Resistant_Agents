"""Registry: register / resolve / list_ids / load_builtins."""

from __future__ import annotations

import pytest

from registry import list_ids, load_builtins, register, resolve


def test_load_builtins_idempotent_and_populates_all_kinds() -> None:
    load_builtins()
    load_builtins()  # idempotent — second call must not raise
    for sid in ("react_stub", "langgraph_react"):
        assert sid in list_ids("scaffold")
    for suite_id in (
        "lite_fs_protected_paths",
        "lite_memory_poison",
        "lite_retrieve_contamination",
    ):
        assert suite_id in list_ids("suite")
    for sid in (
        "unauthorized_write",
        "unauthorized_recipient",
        "memory_poison_followed",
        "unsupported_citation",
        "injection_followed",
    ):
        assert sid in list_ids("scanner")


def test_resolve_unknown_raises() -> None:
    with pytest.raises(KeyError):
        resolve("scaffold", "no_such_scaffold")


def test_register_rejects_duplicate() -> None:
    @register("test_kind", "x")
    class _A:
        pass

    with pytest.raises(ValueError, match="Duplicate"):

        @register("test_kind", "x")
        class _B:
            pass
