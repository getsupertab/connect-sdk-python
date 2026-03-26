"""Tests for JWKS fetching, caching, and key lookup."""

import time
from unittest.mock import patch

import pytest
import respx

from connect.exceptions import JwksKeyNotFoundError
from connect.merchant.jwks import JWKS_CACHE_TTL_SECONDS, clear_jwks_cache, fetch_platform_jwks, find_key_by_kid

from tests.merchant.constants import JWKS_URL, SUPERTAB_BASE_URL


async def test_fetch_platform_jwks(jwks_response):
    """Fetches JWKS from the well-known endpoint."""
    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        result = await fetch_platform_jwks(SUPERTAB_BASE_URL)

        assert result == jwks_response
        assert route.call_count == 1


async def test_fetch_platform_jwks_caches_result(jwks_response):
    """Second call returns cached JWKS without a network request."""
    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        await fetch_platform_jwks(SUPERTAB_BASE_URL)
        await fetch_platform_jwks(SUPERTAB_BASE_URL)

        assert route.call_count == 1


async def test_fetch_platform_jwks_cache_expires(jwks_response):
    """Expired cache triggers a fresh JWKS fetch."""
    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        await fetch_platform_jwks(SUPERTAB_BASE_URL)
        assert route.call_count == 1

        with patch("connect.merchant.jwks.time.monotonic", return_value=time.monotonic() + JWKS_CACHE_TTL_SECONDS + 1):
            await fetch_platform_jwks(SUPERTAB_BASE_URL)

        assert route.call_count == 2


async def test_clear_jwks_cache_forces_refetch(jwks_response):
    """Clearing the cache forces a new fetch on the next call."""
    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        await fetch_platform_jwks(SUPERTAB_BASE_URL)
        clear_jwks_cache()
        await fetch_platform_jwks(SUPERTAB_BASE_URL)

        assert route.call_count == 2


def test_find_key_by_kid_returns_matching_key():
    """Returns the key matching the given kid."""
    jwks = {"keys": [{"kid": "key-1", "kty": "EC"}, {"kid": "key-2", "kty": "EC"}]}

    result = find_key_by_kid(jwks, "key-2")

    assert result == {"kid": "key-2", "kty": "EC"}


def test_find_key_by_kid_raises_on_missing_kid():
    """Raises JwksKeyNotFoundError when the kid is not in the key set."""
    jwks = {"keys": [{"kid": "key-1", "kty": "EC"}]}

    with pytest.raises(JwksKeyNotFoundError, match="no-such-key"):
        find_key_by_kid(jwks, "no-such-key")


def test_find_key_by_kid_raises_on_empty_keys():
    """Raises JwksKeyNotFoundError when the key set is empty."""
    with pytest.raises(JwksKeyNotFoundError):
        find_key_by_kid({"keys": []}, "any-kid")
