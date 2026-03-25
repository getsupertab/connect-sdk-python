"""Tests for JWKS fetching, caching, and key lookup."""

import time
from unittest.mock import patch

import pytest
import respx

from connect.exceptions import JwksKeyNotFoundError
from connect.jwks import JWKS_CACHE_TTL_SECONDS, clear_jwks_cache, fetch_platform_jwks, find_key_by_kid

from .conftest import JWKS_URL, SUPERTAB_BASE_URL


@pytest.mark.anyio
async def test_fetch_platform_jwks(jwks_response):
    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        result = await fetch_platform_jwks(SUPERTAB_BASE_URL)

        assert result == jwks_response
        assert route.call_count == 1


@pytest.mark.anyio
async def test_fetch_platform_jwks_caches_result(jwks_response):
    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        await fetch_platform_jwks(SUPERTAB_BASE_URL)
        await fetch_platform_jwks(SUPERTAB_BASE_URL)

        assert route.call_count == 1


@pytest.mark.anyio
async def test_fetch_platform_jwks_cache_expires(jwks_response):
    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        await fetch_platform_jwks(SUPERTAB_BASE_URL)
        assert route.call_count == 1

        with patch("connect.jwks.time.monotonic", return_value=time.monotonic() + JWKS_CACHE_TTL_SECONDS + 1):
            await fetch_platform_jwks(SUPERTAB_BASE_URL)

        assert route.call_count == 2


@pytest.mark.anyio
async def test_clear_jwks_cache_forces_refetch(jwks_response):
    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        await fetch_platform_jwks(SUPERTAB_BASE_URL)
        clear_jwks_cache()
        await fetch_platform_jwks(SUPERTAB_BASE_URL)

        assert route.call_count == 2


def test_find_key_by_kid_returns_matching_key():
    jwks = {"keys": [{"kid": "key-1", "kty": "EC"}, {"kid": "key-2", "kty": "EC"}]}

    result = find_key_by_kid(jwks, "key-2")

    assert result == {"kid": "key-2", "kty": "EC"}


def test_find_key_by_kid_raises_on_missing_kid():
    jwks = {"keys": [{"kid": "key-1", "kty": "EC"}]}

    with pytest.raises(JwksKeyNotFoundError, match="no-such-key"):
        find_key_by_kid(jwks, "no-such-key")


def test_find_key_by_kid_raises_on_empty_keys():
    with pytest.raises(JwksKeyNotFoundError):
        find_key_by_kid({"keys": []}, "any-kid")
