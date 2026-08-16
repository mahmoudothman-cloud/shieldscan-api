"""Tests for ``app.logging_config``.

The first test is the forcing function: it pins the defect this module was
written to fix — that under uvicorn's own default logging configuration, an
INFO record from an ``app.*`` logger is silently discarded. That claim is
what justifies the module existing, so it is asserted rather than asserted-in-
a-comment. It runs in a subprocess because applying uvicorn's ``dictConfig``
in-process would mutate logging state for the rest of the suite.

If uvicorn ever ships a ``root`` entry in ``LOGGING_CONFIG``, test 1 fails and
the module becomes redundant — which is the signal we want.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

import pytest

from app.logging_config import _HANDLER_MARKER, configure_logging

REPO_ROOT = Path(__file__).resolve().parents[1]

# Applied in the subprocess exactly as uvicorn does when launched without
# --log-config (which is how the API is launched).
_UVICORN_PREAMBLE = (
    "import logging, logging.config\n"
    "from uvicorn.config import LOGGING_CONFIG\n"
    "logging.config.dictConfig(LOGGING_CONFIG)\n"
)


def _run(script: str) -> str:
    """Run a snippet in a clean interpreter; return stdout + stderr."""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=REPO_ROOT,  # so pydantic-settings finds .env
    )
    assert result.returncode == 0, (
        f"subprocess failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return result.stdout + result.stderr


# ---------------------------------------------------------------- 1. the defect


def test_uvicorn_default_config_alone_discards_app_info_logs():
    """Under uvicorn's config and nothing else, app INFO goes nowhere.

    WARNING_SENTINEL is the control: it proves the subprocess logs at all,
    so INFO_SENTINEL's absence is the level being dropped and not a broken
    test harness. WARNING survives only via ``logging.lastResort``.
    """
    output = _run(
        _UVICORN_PREAMBLE
        + "log = logging.getLogger('app.services.completions_consumer')\n"
        "log.info('INFO_SENTINEL')\n"
        "log.warning('WARNING_SENTINEL')\n"
    )

    assert "WARNING_SENTINEL" in output, (
        "control line missing — the subprocess emitted nothing at all, so "
        "this test proves nothing about INFO"
    )
    assert "INFO_SENTINEL" not in output, (
        "app-level INFO reached the output without configure_logging(). If "
        "uvicorn now configures the root logger, app/logging_config.py is "
        "redundant and should be removed rather than left as dead ceremony."
    )


# ---------------------------------------------------------------- 2. the fix


def test_configure_logging_makes_app_info_reach_the_output():
    """Same starting conditions as test 1, plus configure_logging()."""
    output = _run(
        _UVICORN_PREAMBLE
        + "from app.logging_config import configure_logging\n"
        "configure_logging('INFO')\n"
        "logging.getLogger('app.services.completions_consumer')"
        ".info('INFO_SENTINEL')\n"
    )

    assert output.count("INFO_SENTINEL") == 1
    # The formatter's value is attribution: which logger, at what time.
    assert "app.services.completions_consumer" in output
    assert "INFO" in output


def test_configure_logging_does_not_double_emit_uvicorn_records():
    """Adding a root handler must not make uvicorn's own lines print twice.

    ``uvicorn`` and ``uvicorn.access`` set ``propagate=False``, and
    ``uvicorn.error`` propagates only as far as its ``uvicorn`` parent, which
    stops there — so uvicorn records never reach root. Asserted rather than
    assumed: a doubled access log would be an obvious regression from a
    change nobody would connect to this module.
    """
    output = _run(
        _UVICORN_PREAMBLE
        + "from app.logging_config import configure_logging\n"
        "configure_logging('INFO')\n"
        "logging.getLogger('uvicorn.error').info('UVICORN_SENTINEL')\n"
        # uvicorn's AccessFormatter reads client_addr / request_line /
        # status_code out of a 5-tuple of args; a bare message makes the
        # formatter itself raise, which prints a traceback containing the
        # message and would look exactly like a double-emit.
        "logging.getLogger('uvicorn.access').info(\n"
        "    '%s - \"%s %s HTTP/%s\" %d',\n"
        "    'ACCESS_SENTINEL', 'GET', '/health', '1.1', 200,\n"
        ")\n"
    )

    assert "--- Logging error ---" not in output
    assert output.count("UVICORN_SENTINEL") == 1
    assert output.count("ACCESS_SENTINEL") == 1


# ---------------------------------------------------------------- 3. in-process behaviour


@pytest.fixture
def restore_root_logging():
    """Snapshot + restore root handlers and level.

    configure_logging() mutates global logging state; without this the
    remaining tests in the session would run with a different root level
    and an extra handler.
    """
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    yield
    root.handlers = saved_handlers
    root.setLevel(saved_level)


def test_configure_logging_is_idempotent(restore_root_logging):
    """Repeat calls replace the handler instead of stacking a second one.

    Two marked handlers would print every line twice — the failure mode of
    the obvious implementation.
    """
    configure_logging("INFO")
    configure_logging("INFO")
    configure_logging("DEBUG")

    root = logging.getLogger()
    marked = [h for h in root.handlers if getattr(h, _HANDLER_MARKER, False)]
    assert len(marked) == 1
    # Last call wins.
    assert root.level == logging.DEBUG


def test_configure_logging_honours_the_level_argument(
    restore_root_logging, capsys
):
    """At WARNING, the job_completed INFO line is correctly suppressed —
    the documented consequence of setting LOG_LEVEL=WARNING."""
    configure_logging("WARNING")
    log = logging.getLogger("app.services.completions_consumer")
    log.info("SUPPRESSED_SENTINEL")
    log.warning("KEPT_SENTINEL")

    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "KEPT_SENTINEL" in combined
    assert "SUPPRESSED_SENTINEL" not in combined
