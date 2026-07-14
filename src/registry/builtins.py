"""Built-in registrations.

Importing this module triggers every ``@register(...)`` side-effect for the
shipped scaffolds, suites, and scanners. Kept in a dedicated module so that
``import registry`` stays cheap (no transitive pull of LangChain / OTel just
to use the registry API).

Adding a new builtin means adding one import line here. Unused-import warnings
are suppressed via the per-file ignore in ``pyproject.toml``.
"""

from __future__ import annotations

# Scaffolds
import scaffolds.langgraph_react
import scaffolds.react_stub

# Scanners
import scanners.injection_followed
import scanners.memory_poison_followed
import scanners.unauthorized_recipient
import scanners.unauthorized_write
import scanners.unsupported_citation
import scanners.taint_leakage

# Task suites
import tasks.lite_fs_protected_paths
import tasks.lite_memory_poison
import tasks.lite_retrieve_contamination
import tasks.lite_taint_flow
import tasks.lite_taint_launder
import tasks.taint_laundering 
