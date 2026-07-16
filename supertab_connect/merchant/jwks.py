"""JWKS fetching and caching for platform key verification."""

import asyncio
import time
from typing import Any

import httpx

from supertab_connect._version import _get_sdk_user_agent
from supertab_connect.common import debug_log, error_log
from supertab_connect.exceptions import JwksKeyNotFoundError

JWKS_CACHE_TTL_SECONDS = 48 * 3600  # 48 hours
# Minimum spacing between key-rotation-triggered refreshes, per base_url. A JWT's `kid` is read
# from its unverified header, so an unauthenticated caller (e.g. via the public status endpoint)
# can present tokens with rotating unknown kids; without this floor each one would bypass the
# cache and force a backend JWKS fetch. Well below the TTL, so genuine rotations still recover
# on the first miss.
_JWKS_MIN_REFRESH_INTERVAL_SECONDS = 60

_jwks_cache: dict[str, dict[str, Any]] = {}
# Monotonic timestamp of the last rotation-refresh per base_url, for the cooldown above.
_jwks_last_refresh: dict[str, float] = {}
# Per-base_url locks so concurrent misses coalesce into a single refresh (single-flight).
_jwks_refresh_locks: dict[str, asyncio.Lock] = {}
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


async def fetch_platform_jwks(base_url: str, *, force: bool = False, debug: bool = False) -> dict[str, Any]:
    """Fetch the platform JWKS from the Supertab well-known endpoint.

    Results are cached per base_url for 48 hours. Subsequent calls within
    the TTL return the cached key set without making a network request.

    ``force=True`` bypasses the TTL and refetches; on a fetch failure the previously cached
    entry is left intact (the write only happens after a successful response).
    """
    normalized_url = base_url.rstrip("/")
    now = time.monotonic()
    cached = _jwks_cache.get(normalized_url)
    if not force and cached is not None and (now - cached["cached_at"]) < JWKS_CACHE_TTL_SECONDS:
        return cached["jwks"]

    jwks_url = f"{normalized_url}/.well-known/jwks.json/platform"
    debug_log(debug, f"Fetching platform JWKS from URL: {jwks_url}")

    try:
        client = _get_http_client()
        response = await client.get(jwks_url)
        response.raise_for_status()

        jwks_data = response.json()
        _jwks_cache[normalized_url] = {"jwks": jwks_data, "cached_at": now}
        return jwks_data
    except httpx.HTTPError as exc:
        error_log(debug, f"Error fetching platform JWKS: {exc}")
        raise


async def refresh_platform_jwks_on_miss(base_url: str, *, debug: bool = False) -> dict[str, Any]:
    """Refresh the cached JWKS after a `kid` miss, throttled to protect the backend.

    Called when a token's `kid` is absent from the currently cached key set — normally a sign the
    platform rotated its signing keys. Because `kid` comes from an unverified JWT header, an
    unauthenticated caller could otherwise force a backend fetch per request; this refetches at
    most once per ``_JWKS_MIN_REFRESH_INTERVAL_SECONDS`` per base_url and coalesces concurrent
    callers via a per-base_url lock (single-flight). Returns the freshest key set available —
    the refreshed set, or the current cache when throttled — and the caller re-checks the `kid`,
    failing closed if it is still absent.
    """
    normalized_url = base_url.rstrip("/")
    lock = _jwks_refresh_locks.setdefault(normalized_url, asyncio.Lock())
    async with lock:
        now = time.monotonic()
        last = _jwks_last_refresh.get(normalized_url)
        if last is not None and (now - last) < _JWKS_MIN_REFRESH_INTERVAL_SECONDS:
            debug_log(debug, "Skipping JWKS refresh: a refresh happened within the cooldown window")
            cached = _jwks_cache.get(normalized_url)
            return cached["jwks"] if cached is not None else {"keys": []}
        # Record the attempt before fetching so a failed refetch still spends the cooldown —
        # a broken backend must not reopen the per-request fetch amplification.
        _jwks_last_refresh[normalized_url] = now
        return await fetch_platform_jwks(normalized_url, force=True, debug=debug)


def clear_jwks_cache() -> None:
    """Invalidate all cached JWKS data and refresh throttling, forcing a fresh fetch on next call."""
    _jwks_cache.clear()
    _jwks_last_refresh.clear()


def _find_key_by_kid(jwks: dict[str, Any], kid: str | None) -> dict[str, Any]:
    """Find a key in the JWKS by key ID.

    Raises JwksKeyNotFoundError if no matching key is found.
    """
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    raise JwksKeyNotFoundError(kid)
