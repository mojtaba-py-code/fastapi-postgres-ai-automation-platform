"""Table definitions, grouped by bounded context."""

from __future__ import annotations

import importlib

_MODULES = ("identity", "data")


def load_all_tables() -> None:
    """Import every table module so the shared metadata is complete."""
    for name in _MODULES:
        importlib.import_module(f"{__name__}.{name}")
