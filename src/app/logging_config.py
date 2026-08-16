"""Root logging configuration for the API process.

Why this module exists
----------------------
The API had no logging configuration at all, and uvicorn is launched without
``--log-config``. Uvicorn's default ``LOGGING_CONFIG`` attaches handlers to
exactly three loggers — ``uvicorn``, ``uvicorn.error``, ``uvicorn.access`` —
and defines no ``root`` entry. Every ``app.*`` logger therefore had no handler
anywhere on its propagation chain, so:

  - ``logger.info`` and ``logger.debug`` were discarded silently. All 15 INFO
    call sites in ``src/`` produced no output in the running process, ever.
  - ``logger.warning`` / ``error`` / ``exception`` were emitted only by
    ``logging.lastResort``, the stdlib's WARNING-level fallback handler. That
    path prints the bare message to stderr with no timestamp, no logger name
    and no level prefix — which is why API log lines were never attributable
    to a module or a point in time.

This was demonstrated, not inferred: logging INFO and WARNING through an
``app.services.*`` logger after applying uvicorn's own ``LOGGING_CONFIG``
emits the WARNING and drops the INFO. ``test_logging_config.py`` pins that
behaviour in a subprocess so the finding cannot quietly stop being true.

What it does
------------
Adds one ``StreamHandler`` to the root logger with a formatter carrying
timestamp, level, logger name and message, and sets the root level from
``settings.LOG_LEVEL`` (default INFO).

No duplication of uvicorn output: ``uvicorn`` and ``uvicorn.access`` are
configured with ``propagate=False``, and ``uvicorn.error`` propagates only as
far as its ``uvicorn`` parent, which stops there. Uvicorn's records never
reach root, so they are not emitted twice.

Volume: 15 INFO and 2 DEBUG call sites exist in ``src/``, so enabling INFO is
a handful of lines per scan, not a firehose. ``httpx`` is the one third-party
logger that emits at INFO by default (one line per outbound HTTP request,
including every AI call); it is pinned to WARNING below. Remove that entry if
per-request client logging is wanted.

To back this out entirely, drop the ``configure_logging()`` call in
``main.py``. The behaviour reverts to the state described above.
"""

from __future__ import annotations

import logging
import sys

from app.config import settings

_FORMAT = "%(asctime)s %(levelname)-8s %(name)s %(message)s"
_DATEFMT = "%Y-%m-%dT%H:%M:%S%z"

# Marks the handler this module owns, so repeat calls replace it rather than
# stacking a second one (which would double every line).
_HANDLER_MARKER = "_shieldscan_root_handler"

# Third-party loggers that are chatty at INFO. httpx logs one line per
# outbound request; at root INFO that would narrate every Anthropic, OpenAI
# and Qdrant call. Not silenced — raised to WARNING, so failures still show.
_QUIET_AT_WARNING = ("httpx",)


def configure_logging(level: str | None = None) -> None:
    """Install the root handler. Idempotent — safe to call more than once.

    ``level`` overrides ``settings.LOG_LEVEL``; used by tests.
    """
    resolved = (level or settings.LOG_LEVEL).upper()

    root = logging.getLogger()
    for existing in list(root.handlers):
        if getattr(existing, _HANDLER_MARKER, False):
            root.removeHandler(existing)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))
    setattr(handler, _HANDLER_MARKER, True)

    root.addHandler(handler)
    root.setLevel(resolved)

    for name in _QUIET_AT_WARNING:
        logging.getLogger(name).setLevel(logging.WARNING)
