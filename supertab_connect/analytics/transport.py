"""Analytics transports (mirrors TS `analytics/transport.ts`).

The HTTP transport is fire-and-forget: ``emit`` schedules the POST on the running
event loop and returns immediately, never blocking the request path or raising.
"""

import asyncio
from dataclasses import asdict

import httpx

from supertab_connect._version import _get_sdk_user_agent
from supertab_connect.analytics.types import AnalyticsEvent, AnalyticsTransport
from supertab_connect.common import debug_log, error_log

ANALYTICS_EVENTS_PATH = "/ingest/events"

# Hold strong references to in-flight emit tasks so they are not garbage-collected
# before they finish (asyncio only keeps weak references to scheduled tasks).
_background_tasks: set[asyncio.Task] = set()

_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(headers={"User-Agent": _get_sdk_user_agent()})
    return _http_client


async def aclose_http_client() -> None:
    global _http_client
    if _http_client is not None and not _http_client.is_closed:
        await _http_client.aclose()
    _http_client = None


class NoopAnalyticsTransport:
    """A transport that discards every event. Used when analytics is disabled."""

    def emit(self, event: AnalyticsEvent) -> None:
        # intentional no-op
        return None


class HttpAnalyticsTransport:
    """Posts events to the Supertab Connect relay, fire-and-forget."""

    def __init__(self, *, url: str, api_key: str, debug: bool = False) -> None:
        self._url = url
        self._api_key = api_key
        self._debug = debug

    def emit(self, event: AnalyticsEvent) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running event loop to schedule onto; analytics is best-effort, so skip.
            debug_log(self._debug, "Skipping analytics emit: no running event loop")
            return None

        task = loop.create_task(self._send(event))
        _background_tasks.add(task)
        task.add_done_callback(self._on_task_done)
        return None

    def _on_task_done(self, task: asyncio.Task) -> None:
        # Backstop: drop the reference and retrieve any exception so it never surfaces as an
        # "exception was never retrieved" warning, even if _send's own guard is somehow bypassed.
        _background_tasks.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            error_log(self._debug, f"analytics emit task error: {error}")

    async def _send(self, event: AnalyticsEvent) -> None:
        # Fail-open: analytics must never block, slow, or alter request handling, so every error
        # (transport, serialization, anything) is swallowed here rather than propagating.
        try:
            response = await _get_http_client().post(
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


# Re-exported so callers can rely on structural typing without importing from `types`.
__all__ = [
    "ANALYTICS_EVENTS_PATH",
    "AnalyticsTransport",
    "HttpAnalyticsTransport",
    "NoopAnalyticsTransport",
    "aclose_http_client",
]
