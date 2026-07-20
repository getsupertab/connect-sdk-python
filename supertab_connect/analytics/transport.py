"""Analytics transports (mirrors TS `analytics/transport.ts`).

The HTTP transport is fire-and-forget: ``emit`` schedules the POST on the running
event loop and returns immediately, never blocking the request path or raising.

Unlike a module-level singleton, each ``HttpAnalyticsTransport`` owns its own HTTP
client and the set of in-flight emit tasks, so its lifetime is bounded by its owning
``SupertabConnect`` instance (mirroring the TS SDK). ``aclose`` drains in-flight emits
within a bounded timeout before closing the client, so tasks can never outlive the
client and resurrect a leaked one.
"""

import asyncio
from dataclasses import asdict

import httpx

from supertab_connect._version import _get_sdk_user_agent
from supertab_connect.analytics.types import AnalyticsEvent, AnalyticsTransport
from supertab_connect.common import debug_log, error_log

ANALYTICS_EVENTS_PATH = "/ingest/events"

# Upper bound on how long aclose() waits for in-flight emits to finish before cancelling them.
_DEFAULT_FLUSH_TIMEOUT_SECONDS = 5.0


class NoopAnalyticsTransport:
    """A transport that discards every event. Used when analytics is disabled."""

    def emit(self, event: AnalyticsEvent) -> None:
        # intentional no-op
        return None

    async def aclose(self) -> None:
        # Nothing to drain or close; present for lifecycle symmetry with HttpAnalyticsTransport.
        return None


class HttpAnalyticsTransport:
    """Posts events to the Supertab Connect relay, fire-and-forget.

    Owns its HTTP client and in-flight emit tasks; call ``aclose`` (directly or via the
    owning client's ``aclose`` / ``async with``) to flush and release them.
    """

    def __init__(
        self,
        *,
        url: str,
        api_key: str,
        debug: bool = False,
        flush_timeout: float = _DEFAULT_FLUSH_TIMEOUT_SECONDS,
    ) -> None:
        self._url = url
        self._api_key = api_key
        self._debug = debug
        self._flush_timeout = flush_timeout
        # Strong references to in-flight emit tasks so asyncio doesn't GC them mid-flight
        # (it only keeps weak references to scheduled tasks).
        self._tasks: set[asyncio.Task] = set()
        self._client: httpx.AsyncClient | None = None
        self._closed = False

    def _get_client(self) -> httpx.AsyncClient:
        # Lazy: a transport that never emits (e.g. constructed with no running loop) never
        # creates — and so never leaks — a client.
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(headers={"User-Agent": _get_sdk_user_agent()})
        return self._client

    def emit(self, event: AnalyticsEvent) -> None:
        if self._closed:
            debug_log(self._debug, "Skipping analytics emit: transport is closed")
            return None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running event loop to schedule onto; analytics is best-effort, so skip.
            debug_log(self._debug, "Skipping analytics emit: no running event loop")
            return None

        task = loop.create_task(self._send(event))
        self._tasks.add(task)
        task.add_done_callback(self._on_task_done)
        return None

    def _on_task_done(self, task: asyncio.Task) -> None:
        # Backstop: drop the reference and retrieve any exception so it never surfaces as an
        # "exception was never retrieved" warning, even if _send's own guard is somehow bypassed.
        self._tasks.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            error_log(self._debug, f"analytics emit task error: {error}")

    async def _send(self, event: AnalyticsEvent) -> None:
        # Fail-open: analytics must never block, slow, or alter request handling, so every error
        # (transport, serialization, anything) is swallowed here rather than propagating.
        # No _closed guard here: aclose() awaits (flush) or cancels every scheduled send before
        # closing the client, so a send can neither be silently dropped nor resurrect a client.
        try:
            response = await self._get_client().post(
                self._url,
                json=asdict(event),
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
            )
            if not response.is_success:
                debug_log(self._debug, f"analytics emit failed: {response.status_code}")
        except Exception as error:  # noqa: BLE001 — fail-open guarantee, see comment above
            error_log(self._debug, f"analytics emit error: {error}")

    async def flush(self) -> None:
        """Await in-flight emit tasks, bounded by ``flush_timeout``.

        Does not close the client. Tasks scheduled after the snapshot are not awaited, so the
        wait stays bounded even under a steady stream of emits.
        """
        tasks = list(self._tasks)
        if not tasks:
            return
        await asyncio.wait(tasks, timeout=self._flush_timeout)

    async def aclose(self) -> None:
        """Flush in-flight emits (bounded) and close the HTTP client.

        After this returns, ``emit`` is a no-op. Any emit that outlived the flush timeout is
        cancelled so it cannot resurrect the client after it is closed.
        """
        self._closed = True
        await self.flush()
        stragglers = list(self._tasks)
        for task in stragglers:
            task.cancel()
        if stragglers:
            await asyncio.gather(*stragglers, return_exceptions=True)
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None


# Re-exported so callers can rely on structural typing without importing from `types`.
__all__ = [
    "ANALYTICS_EVENTS_PATH",
    "AnalyticsTransport",
    "HttpAnalyticsTransport",
    "NoopAnalyticsTransport",
]
