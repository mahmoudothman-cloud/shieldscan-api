"""Regression guard: every `app.*` submodule must be importable.

Context: during Sub-task 2.3.4 Commit 2 we discovered that
``src/app/db.py`` had been shadowed since M1 by the ``src/app/db/``
package — the file was unreachable yet tests passed (nothing
imported ``AsyncSessionLocal``). The lesson: *"tests pass" does not
imply "all code is reachable."*

This test walks every Python file under ``src/app/`` and imports it
by dotted name. If a file is shadowed or has a broken import, this
test catches it immediately — no more silent orphans.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest


APP_ROOT = Path(__file__).parent.parent / "src" / "app"


def _collect_modules() -> list[str]:
    modules: list[str] = []
    for path in APP_ROOT.rglob("*.py"):
        # Skip __pycache__, migrations, vendored.
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(APP_ROOT.parent)  # src/app/...
        # src/app/x/y.py -> app.x.y ; src/app/x/__init__.py -> app.x
        parts = list(rel.parts)
        if parts[-1] == "__init__.py":
            parts = parts[:-1]
        else:
            parts[-1] = parts[-1][:-3]  # strip .py
        # First part is 'src', drop it.
        if parts and parts[0] == "src":
            parts = parts[1:]
        if parts:
            modules.append(".".join(parts))
    return sorted(set(modules))


@pytest.mark.parametrize("module_name", _collect_modules())
def test_module_importable(module_name):
    """Every file under src/app/ must be importable by dotted name."""
    importlib.import_module(module_name)
