"""JWKS fetching and caching for platform key verification."""

import time
from typing import Any

import httpx

from connect.common import debug_log, error_log
from connect.exceptions import JwksKeyNotFoundError

JWKS_CACHE_TTL_SECONDS = 48 * 3600  # 48 hours

_jwks_cache: dict[str, dict[str, Any]] = {}


async def fetch_platform_jwks(base_url: str, *, debug: bool = False) -> dict[str, Any]:
    """Fetch the platform JWKS from the Supertab well-known endpoint.

    Results are cached per base_url for 48 hours. Subsequent calls within
    the TTL return the cached key set without making a network request.
    """
    now = time.monotonic()
    cached = _jwks_cache.get(base_url)
    if cached is not None and (now - cached["cached_at"]) < JWKS_CACHE_TTL_SECONDS:
        return cached["keys"]

    jwks_url = f"{base_url}/.well-known/jwks.json/platform"
    debug_log(debug, f"Fetching platform JWKS from URL: {jwks_url}")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(jwks_url)
            response.raise_for_status()

        jwks_data = response.json()
        _jwks_cache[base_url] = {"keys": jwks_data, "cached_at": now}
        return jwks_data
    except httpx.HTTPError as exc:
        error_log(debug, f"Error fetching platform JWKS: {exc}")
        raise


def clear_jwks_cache() -> None:
    """Invalidate all cached JWKS data, forcing a fresh fetch on next call."""
    _jwks_cache.clear()


def find_key_by_kid(jwks: dict[str, Any], kid: str | None) -> dict[str, Any]:
    """Find a key in the JWKS by key ID.

    Raises JwksKeyNotFoundError if no matching key is found.
    """
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    raise JwksKeyNotFoundError(kid)
