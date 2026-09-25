"""Asyncio runtime for Celery worker processes.

Celery tasks are synchronous; the services are async. Each worker *process*
owns one long-lived event loop (``asyncio.Runner``, uvloop where available)
and one resource bundle (the container, or the sandbox components). Both are
created lazily in the child after the prefork - event loops and connection
pools are not fork-safe - and closed when the process shuts down.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Awaitable, Callable

if sys.platform != "win32":
    import uvloop

    _LOOP_FACTORY: Callable[[], asyncio.AbstractEventLoop] | None = uvloop.new_event_loop
else:  # pragma: no cover - development on Windows only
    _LOOP_FACTORY = None


class ProcessRuntime[T]:
    def __init__(self, factory: Callable[[], T], closer: Callable[[T], Awaitable[None]]) -> None:
        self._factory = factory
        self._closer = closer
        self._runner: asyncio.Runner | None = None
        self._resource: T | None = None

    def _get_runner(self) -> asyncio.Runner:
        if self._runner is None:
            self._runner = asyncio.Runner(loop_factory=_LOOP_FACTORY)
        return self._runner

    def run[R](self, work: Callable[[T], Awaitable[R]]) -> R:
        runner = self._get_runner()
        if self._resource is None:
            self._resource = runner.run(self._build())
        return runner.run(_await(work(self._resource)))

    async def _build(self) -> T:
        return self._factory()  # built inside the loop that will use its pools

    def close(self) -> None:
        if self._runner is None:
            return
        try:
            if self._resource is not None:
                self._runner.run(_await(self._closer(self._resource)))
        finally:
            self._resource = None
            self._runner.close()
            self._runner = None


async def _await[R](awaitable: Awaitable[R]) -> R:
    return await awaitable
