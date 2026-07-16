"""Tests for JWKS fetching, caching, and key lookup."""

import time
from unittest.mock import patch

import httpx
import pytest
import respx

import supertab_connect.merchant.jwks as jwks_module
from supertab_connect.exceptions import JwksKeyNotFoundError
from supertab_connect.merchant.jwks import (
    JWKS_CACHE_TTL_SECONDS,
    _find_key_by_kid,
    aclose_http_client,
    clear_jwks_cache,
    fetch_platform_jwks,
    refresh_platform_jwks_on_miss,
)

from tests.merchant.constants import JWKS_URL, SUPERTAB_BASE_URL


async def test_fetch_platform_jwks(jwks_response):
    """Fetches JWKS from the well-known endpoint."""
    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        result = await fetch_platform_jwks(SUPERTAB_BASE_URL)

        assert result == jwks_response
        assert route.call_count == 1


async def test_fetch_platform_jwks_sends_sdk_user_agent(jwks_response):
    """JWKS requests carry the SDK User-Agent header."""
    from supertab_connect._version import _get_sdk_user_agent

    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        clear_jwks_cache()
        await fetch_platform_jwks(SUPERTAB_BASE_URL)

        assert route.calls[0].request.headers["User-Agent"] == _get_sdk_user_agent()


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

        with patch(
            "supertab_connect.merchant.jwks.time.monotonic", return_value=time.monotonic() + JWKS_CACHE_TTL_SECONDS + 1
        ):
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


async def test_refresh_on_miss_refetches_when_not_throttled(jwks_response):
    """A first miss forces a refetch even though the cache is still within its TTL."""
    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        await fetch_platform_jwks(SUPERTAB_BASE_URL)  # warm the cache (fetch #1)
        assert route.call_count == 1

        await refresh_platform_jwks_on_miss(SUPERTAB_BASE_URL)  # fetch #2, bypassing the TTL

        assert route.call_count == 2


async def test_refresh_on_miss_is_throttled_within_cooldown(jwks_response):
    """A second miss inside the cooldown must not hit the backend again — the abuse guard."""
    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        await fetch_platform_jwks(SUPERTAB_BASE_URL)  # fetch #1
        await refresh_platform_jwks_on_miss(SUPERTAB_BASE_URL)  # fetch #2 (first refresh)
        result = await refresh_platform_jwks_on_miss(SUPERTAB_BASE_URL)  # throttled, no fetch

        assert route.call_count == 2
        assert result == jwks_response  # served from cache while throttled


async def test_refresh_on_miss_resumes_after_cooldown(jwks_response):
    """Once the cooldown elapses, a genuine rotation can refresh again."""
    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        await fetch_platform_jwks(SUPERTAB_BASE_URL)  # fetch #1
        await refresh_platform_jwks_on_miss(SUPERTAB_BASE_URL)  # fetch #2

        # Jump past the cooldown window.
        later = time.monotonic() + jwks_module._JWKS_MIN_REFRESH_INTERVAL_SECONDS + 1
        with patch("supertab_connect.merchant.jwks.time.monotonic", return_value=later):
            await refresh_platform_jwks_on_miss(SUPERTAB_BASE_URL)  # fetch #3

        assert route.call_count == 3


async def test_refresh_on_miss_keeps_last_known_cache_on_failed_refetch(jwks_response):
    """A failed forced refetch leaves the previously cached key set intact (fail-safe)."""
    with respx.mock:
        route = respx.get(JWKS_URL)
        route.side_effect = [httpx.Response(200, json=jwks_response), httpx.Response(500)]

        await fetch_platform_jwks(SUPERTAB_BASE_URL)  # fetch #1 (good)
        with pytest.raises(httpx.HTTPError):
            await refresh_platform_jwks_on_miss(SUPERTAB_BASE_URL)  # fetch #2 (500)

        # Old keys survive, so a subsequent cached read still works without another fetch.
        assert await fetch_platform_jwks(SUPERTAB_BASE_URL) == jwks_response
        assert route.call_count == 2


def test_find_key_by_kid_returns_matching_key():
    """Returns the key matching the given kid."""
    jwks = {"keys": [{"kid": "key-1", "kty": "EC"}, {"kid": "key-2", "kty": "EC"}]}

    result = _find_key_by_kid(jwks, "key-2")

    assert result == {"kid": "key-2", "kty": "EC"}


def test_find_key_by_kid_raises_on_missing_kid():
    """Raises JwksKeyNotFoundError when the kid is not in the key set."""
    jwks = {"keys": [{"kid": "key-1", "kty": "EC"}]}

    with pytest.raises(JwksKeyNotFoundError, match="no-such-key"):
        _find_key_by_kid(jwks, "no-such-key")


def test_find_key_by_kid_raises_on_empty_keys():
    """Raises JwksKeyNotFoundError when the key set is empty."""
    with pytest.raises(JwksKeyNotFoundError):
        _find_key_by_kid({"keys": []}, "any-kid")


async def test_aclose_http_client_resets_client(monkeypatch):
    called = {"aclose": 0}

    class DummyClient:
        is_closed = False

        async def aclose(self):
            called["aclose"] += 1

    monkeypatch.setattr("supertab_connect.merchant.jwks._http_client", DummyClient())

    await aclose_http_client()

    assert called["aclose"] == 1
    assert jwks_module._http_client is None
