"""JWKS fetching and caching for platform key verification."""

import time
from typing import Any

import httpx

from connect.exceptions import JwksKeyNotFoundError

JWKS_CACHE_TTL_SECONDS = 48 * 3600  # 48 hours

_jwks_cache: dict[str, Any] = {
    "keys": None,
    "cached_at": 0.0,
}


async def fetch_platform_jwks(base_url: str, *, debug: bool = False) -> dict[str, Any]:
    """Fetch the platform JWKS from the Supertab well-known endpoint.

    Results are cached for 48 hours. Subsequent calls within the TTL return
    the cached key set without making a network request.
    """
    now = time.monotonic()
    if _jwks_cache["keys"] is not None and (now - _jwks_cache["cached_at"]) < JWKS_CACHE_TTL_SECONDS:
        return _jwks_cache["keys"]

    jwks_url = f"{base_url}/.well-known/jwks.json/platform"
    if debug:
        print(f"Fetching platform JWKS from URL: {jwks_url}")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(jwks_url)
            response.raise_for_status()

        jwks_data = response.json()
        _jwks_cache["keys"] = jwks_data
        _jwks_cache["cached_at"] = now
        return jwks_data
    except httpx.HTTPError as exc:
        if debug:
            print(f"Error fetching platform JWKS: {exc}")
        raise


def clear_jwks_cache() -> None:
    """Invalidate the cached JWKS data, forcing a fresh fetch on next call."""
    _jwks_cache["keys"] = None
    _jwks_cache["cached_at"] = 0.0


def find_key_by_kid(jwks: dict[str, Any], kid: str | None) -> dict[str, Any]:
    """Find a key in the JWKS by key ID.

    Raises JwksKeyNotFoundError if no matching key is found.
    """
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    raise JwksKeyNotFoundError(kid)
