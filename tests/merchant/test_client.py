"""Tests for the high-level merchant client."""

from typing import Any, cast

import httpx
import pytest

from connect.merchant.client import SupertabConnect
from connect.types import (
    BlockHandlerResult,
    EnforcementMode,
    HandlerAction,
    InvalidLicenseToken,
    LicenseTokenInvalidReason,
    SupertabConnectConfig,
    ValidLicenseToken,
)

from tests.merchant.constants import REQUEST_URL, SUPERTAB_BASE_URL


def _make_request(headers: dict[str, str] | None = None, url: str = REQUEST_URL) -> httpx.Request:
    return httpx.Request("GET", url, headers=headers or {})


@pytest.fixture(autouse=True)
def _reset_supertab_connect_singleton():
    SupertabConnect.reset_instance()
    SupertabConnect.set_base_url(SUPERTAB_BASE_URL)
    yield
    SupertabConnect.reset_instance()
    SupertabConnect.set_base_url(SUPERTAB_BASE_URL)


def test_supertab_connect_returns_existing_instance_for_same_api_key():
    first = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123", enforcement=EnforcementMode.STRICT))
    second = SupertabConnect(
        SupertabConnectConfig(api_key="sk_test_123", enforcement=EnforcementMode.SOFT, debug=True)
    )

    assert first is second
    assert second.enforcement is EnforcementMode.STRICT
    assert second.debug is False


def test_supertab_connect_raises_for_different_api_key_without_reset():
    SupertabConnect(SupertabConnectConfig(api_key="sk_test_123"))

    with pytest.raises(ValueError, match="Cannot create a new instance with different configuration"):
        SupertabConnect(SupertabConnectConfig(api_key="sk_test_456"))


def test_supertab_connect_reset_replaces_singleton():
    first = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123"))
    second = SupertabConnect(SupertabConnectConfig(api_key="sk_test_456"), reset=True)

    assert first is not second
    assert second.api_key == "sk_test_456"


async def test_verify_uses_class_base_url(monkeypatch):
    captured: dict[str, Any] = {}

    async def stub_verify_license_token(token: str, *, request_url: str, supertab_base_url: str, debug: bool = False):
        captured.update(
            {
                "token": token,
                "request_url": request_url,
                "supertab_base_url": supertab_base_url,
                "debug": debug,
            }
        )
        return ValidLicenseToken(license_id="lic_test_123", payload={})

    monkeypatch.setattr("connect.merchant.client.verify_license_token", stub_verify_license_token)
    SupertabConnect.set_base_url("https://override.example")

    result = await SupertabConnect.verify(token="signed.jwt", resource_url=REQUEST_URL, debug=True)

    assert result.valid is True
    assert result.error is None
    assert captured == {
        "token": "signed.jwt",
        "request_url": REQUEST_URL,
        "supertab_base_url": "https://override.example",
        "debug": True,
    }


async def test_verify_and_record_uses_instance_base_url_override(monkeypatch):
    captured: dict[str, Any] = {}

    async def stub_verify_and_record_event(**kwargs):
        captured.update(kwargs)
        return ValidLicenseToken(license_id="lic_test_123", payload={})

    monkeypatch.setattr("connect.merchant.client.verify_and_record_event", stub_verify_and_record_event)

    client = SupertabConnect(
        SupertabConnectConfig(
            api_key="sk_test_123",
            supertab_base_url="https://merchant-override.example",
            debug=True,
        )
    )
    result = await client.verify_and_record(
        token="signed.jwt",
        resource_url=REQUEST_URL,
        user_agent="TestAgent/1.0",
        request_headers={"Accept": "text/html"},
    )

    assert result.valid is True
    assert captured["supertab_base_url"] == "https://merchant-override.example"
    assert captured["api_key"] == "sk_test_123"
    assert captured["request_headers"] == {"Accept": "text/html"}


async def test_handle_request_allows_token_when_enforcement_disabled(monkeypatch):
    async def fail_verify_and_record_event(**kwargs):
        raise AssertionError(f"verify_and_record_event should not be called: {kwargs}")

    monkeypatch.setattr("connect.merchant.client.verify_and_record_event", fail_verify_and_record_event)

    client = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123", enforcement=EnforcementMode.DISABLED))
    result = await client.handle_request(_make_request({"Authorization": "License signed.jwt"}))

    assert result == {"action": HandlerAction.ALLOW}


async def test_handle_request_blocks_invalid_token(monkeypatch):
    captured: dict[str, Any] = {}

    async def stub_verify_and_record_event(**kwargs):
        captured.update(kwargs)
        return InvalidLicenseToken(
            reason=LicenseTokenInvalidReason.INVALID_AUDIENCE,
            error="The license does not grant access to this resource",
            license_id="lic_test_123",
        )

    monkeypatch.setattr("connect.merchant.client.verify_and_record_event", stub_verify_and_record_event)

    client = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123", enforcement=EnforcementMode.STRICT))
    result = await client.handle_request(
        _make_request(
            {
                "Authorization": "License signed.jwt",
                "User-Agent": "Browser/1.0",
                "Accept": "text/html",
            }
        )
    )

    assert result["action"] is HandlerAction.BLOCK
    block_result = cast(BlockHandlerResult, result)
    assert block_result["status"] == 403
    assert captured["request_headers"]["authorization"] == "License signed.jwt"


async def test_handle_request_allows_valid_token(monkeypatch):
    async def stub_verify_and_record_event(**kwargs):
        return ValidLicenseToken(license_id="lic_test_123", payload={})

    monkeypatch.setattr("connect.merchant.client.verify_and_record_event", stub_verify_and_record_event)

    client = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123"))
    result = await client.handle_request(
        _make_request(
            {
                "Authorization": "License signed.jwt",
                "User-Agent": "Browser/1.0",
            }
        )
    )

    assert result == {"action": HandlerAction.ALLOW}


async def test_handle_request_accepts_lowercase_scheme_and_whitespace(monkeypatch):
    captured: dict[str, Any] = {}

    async def stub_verify_and_record_event(**kwargs):
        captured.update(kwargs)
        return ValidLicenseToken(license_id="lic_test_123", payload={})

    monkeypatch.setattr("connect.merchant.client.verify_and_record_event", stub_verify_and_record_event)

    client = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123"))
    result = await client.handle_request(
        _make_request(
            {
                "Authorization": "license\t  signed.jwt",
                "User-Agent": "Browser/1.0",
            }
        )
    )

    assert result == {"action": HandlerAction.ALLOW}
    assert captured["token"] == "signed.jwt"


async def test_supertab_connect_async_context_manager_closes_http_clients(monkeypatch):
    called: list[str] = []

    async def close_events():
        called.append("events")

    async def close_jwks():
        called.append("jwks")

    monkeypatch.setattr("connect.merchant.client.aclose_events_http_client", close_events)
    monkeypatch.setattr("connect.merchant.client.aclose_jwks_http_client", close_jwks)

    async with SupertabConnect(SupertabConnectConfig(api_key="sk_test_123")):
        pass

    assert called == ["events", "jwks"]


async def test_handle_request_allows_missing_token_without_bot_detector():
    client = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123", enforcement=EnforcementMode.STRICT))

    result = await client.handle_request(_make_request({"User-Agent": "Browser/1.0"}))

    assert result == {"action": HandlerAction.ALLOW}


async def test_handle_request_allows_missing_token_for_non_bot():
    client = SupertabConnect(
        SupertabConnectConfig(
            api_key="sk_test_123",
            enforcement=EnforcementMode.STRICT,
            bot_detector=lambda request: False,
        )
    )

    result = await client.handle_request(_make_request({"User-Agent": "Browser/1.0"}))

    assert result == {"action": HandlerAction.ALLOW}


async def test_handle_request_blocks_bot_in_strict_mode():
    client = SupertabConnect(
        SupertabConnectConfig(
            api_key="sk_test_123",
            enforcement=EnforcementMode.STRICT,
            bot_detector=lambda request: True,
        )
    )

    result = await client.handle_request(_make_request({"User-Agent": "curl/8.0"}))

    assert result["action"] is HandlerAction.BLOCK
    block_result = cast(BlockHandlerResult, result)
    assert block_result["status"] == 401


async def test_handle_request_signals_bot_in_soft_mode():
    client = SupertabConnect(
        SupertabConnectConfig(
            api_key="sk_test_123",
            enforcement=EnforcementMode.SOFT,
            bot_detector=lambda request: True,
        )
    )

    result = await client.handle_request(_make_request({"User-Agent": "curl/8.0"}))

    assert result["action"] is HandlerAction.ALLOW
    assert result["headers"]["X-RSL-Status"] == "token_required"


async def test_handle_request_allows_bot_in_disabled_mode():
    client = SupertabConnect(
        SupertabConnectConfig(
            api_key="sk_test_123",
            enforcement=EnforcementMode.DISABLED,
            bot_detector=lambda request: True,
        )
    )

    result = await client.handle_request(_make_request({"User-Agent": "curl/8.0"}))

    assert result == {"action": HandlerAction.ALLOW}
