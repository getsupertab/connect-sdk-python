"""Merchant event recording helpers."""

from typing import Any

import httpx

from connect._version import _get_sdk_user_agent
from connect.common import debug_log, error_log

_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient()
    return _http_client


async def aclose_http_client() -> None:
    global _http_client
    if _http_client is not None and not _http_client.is_closed:
        await _http_client.aclose()
    _http_client = None


async def record_event(
    *,
    api_key: str,
    base_url: str,
    event_name: str,
    properties: dict[str, str],
    license_id: str | None = None,
    debug: bool = False,
) -> None:
    """Record an analytics event without surfacing transport failures."""
    payload: dict[str, Any] = {
        "event_name": event_name,
        "properties": properties,
    }
    if license_id is not None:
        payload["license_id"] = license_id

    try:
        response = await _get_http_client().post(
            f"{base_url.rstrip('/')}/events",
            json=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": _get_sdk_user_agent(),
            },
        )
        if not response.is_success:
            debug_log(debug, f"Failed to record event: {response.status_code}")
    except httpx.HTTPError as error:
        error_log(debug, f"Error recording event: {error}")
