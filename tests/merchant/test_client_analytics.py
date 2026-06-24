"""Tests for analytics emission wired into the high-level merchant client."""

import httpx
import pytest

from supertab_connect.analytics.types import AnalyticsEvent, AnalyticsTransport, CdnRequestSignals
from supertab_connect.merchant.client import SupertabConnect
from supertab_connect.types import (
    EnforcementMode,
    HandleRequestContext,
    HandlerAction,
    InvalidLicenseToken,
    LicenseTokenInvalidReason,
    SupertabConnectConfig,
    ValidLicenseToken,
)

from tests.merchant.constants import REQUEST_URL, SUPERTAB_BASE_URL


class RecordingTransport:
    def __init__(self) -> None:
        self.events: list[AnalyticsEvent] = []

    def emit(self, event: AnalyticsEvent) -> None:
        self.events.append(event)


class ThrowingTransport:
    def emit(self, event: AnalyticsEvent) -> None:
        raise RuntimeError("transport blew up")


@pytest.fixture(autouse=True)
def _reset_singleton():
    SupertabConnect.reset_instance()
    SupertabConnect.set_base_url(SUPERTAB_BASE_URL)
    yield
    SupertabConnect.reset_instance()
    SupertabConnect.set_base_url(SUPERTAB_BASE_URL)


def _request(headers: dict[str, str] | None = None) -> httpx.Request:
    return httpx.Request("GET", REQUEST_URL, headers=headers or {})


def _client(transport: AnalyticsTransport, **config_kwargs) -> SupertabConnect:
    return SupertabConnect(
        SupertabConnectConfig(api_key="sk_test_123", analytics_transport=transport, **config_kwargs)
    )


def test_constructs_with_only_api_key():
    # Default transport is the Noop transport; construction must not require analytics config.
    SupertabConnect(SupertabConnectConfig(api_key="sk_test_123"))


async def test_emits_observe_event_for_bot_without_token():
    transport = RecordingTransport()
    client = _client(transport, enforcement=EnforcementMode.OBSERVE, bot_detector=lambda request: True)

    result = await client.handle_request(
        _request({"User-Agent": "curl/8.0"}), HandleRequestContext(source_cdn="cloudflare")
    )

    assert result["action"] is HandlerAction.ALLOW
    assert len(transport.events) == 1
    event = transport.events[0]
    assert event.source_cdn == "cloudflare"
    assert event.final_action == "observe"
    assert event.enforcement_mode == "observe"
    assert event.has_token is False
    assert event.token_outcome == "absent"


async def test_emits_block_event_for_bot_without_token_in_enforce():
    transport = RecordingTransport()
    client = _client(transport, enforcement=EnforcementMode.ENFORCE, bot_detector=lambda request: True)

    result = await client.handle_request(_request({"User-Agent": "curl/8.0"}))

    assert result["action"] is HandlerAction.BLOCK
    assert transport.events[0].final_action == "block"
    assert transport.events[0].token_outcome == "absent"


async def test_emits_allow_event_for_non_bot_without_token():
    transport = RecordingTransport()
    client = _client(transport, enforcement=EnforcementMode.ENFORCE, bot_detector=lambda request: False)

    result = await client.handle_request(_request({"User-Agent": "Browser/1.0"}))

    assert result == {"action": HandlerAction.ALLOW}
    assert transport.events[0].final_action == "allow"
    assert transport.events[0].token_outcome == "absent"


async def test_emits_not_validated_for_token_in_disabled_mode():
    transport = RecordingTransport()
    client = _client(transport, enforcement=EnforcementMode.DISABLED)

    result = await client.handle_request(_request({"Authorization": "License some-token"}))

    assert result == {"action": HandlerAction.ALLOW}
    event = transport.events[0]
    assert event.has_token is True
    assert event.token_outcome == "not_validated"
    assert event.final_action == "allow"
    assert event.enforcement_mode == "disabled"


async def test_emits_valid_for_verified_token(monkeypatch):
    async def stub_verify_and_record_event(**kwargs):
        return ValidLicenseToken(license_id="lic_test_123", payload={})

    monkeypatch.setattr("supertab_connect.merchant.client.verify_and_record_event", stub_verify_and_record_event)
    transport = RecordingTransport()
    client = _client(transport, enforcement=EnforcementMode.ENFORCE)

    result = await client.handle_request(_request({"Authorization": "License signed.jwt"}))

    assert result == {"action": HandlerAction.ALLOW}
    assert transport.events[0].has_token is True
    assert transport.events[0].token_outcome == "valid"
    assert transport.events[0].final_action == "allow"


async def test_emits_mapped_outcome_for_invalid_token(monkeypatch):
    async def stub_verify_and_record_event(**kwargs):
        return InvalidLicenseToken(
            reason=LicenseTokenInvalidReason.EXPIRED,
            error="License token expired",
            license_id="lic_test_123",
        )

    monkeypatch.setattr("supertab_connect.merchant.client.verify_and_record_event", stub_verify_and_record_event)
    transport = RecordingTransport()
    client = _client(transport, enforcement=EnforcementMode.ENFORCE)

    result = await client.handle_request(_request({"Authorization": "License signed.jwt"}))

    assert result["action"] is HandlerAction.BLOCK
    assert transport.events[0].token_outcome == "expired"
    assert transport.events[0].final_action == "block"


async def test_forwards_classification_signals_from_context():
    transport = RecordingTransport()
    client = _client(transport, bot_detector=lambda request: True)

    await client.handle_request(
        _request({"User-Agent": "curl/8.0"}),
        HandleRequestContext(
            source_cdn="fastly",
            client_ip="1.2.3.4",
            request_id="req-xyz",
            request_country="DE",
            request_asn=3320,
            tls_fingerprint="abc123",
        ),
    )

    event = transport.events[0]
    assert event.source_cdn == "fastly"
    assert event.client_ip == "::ffff:1.2.3.4"
    assert event.request_id == "req-xyz"
    assert event.request_country == "DE"
    assert event.request_asn == 3320
    assert event.tls_fingerprint == "abc123"


async def test_forwards_cdn_signals_from_context():
    transport = RecordingTransport()
    client = _client(transport, bot_detector=lambda request: True)

    await client.handle_request(
        _request({"User-Agent": "curl/8.0"}),
        HandleRequestContext(
            source_cdn="cloudflare",
            cdn_signals=CdnRequestSignals(
                tls_version="TLSv1.3",
                cdn_verified_bot_category="AI Assistant",
            ),
        ),
    )

    event = transport.events[0]
    assert event.tls_version == "TLSv1.3"
    assert event.cdn_verified_bot_category == "AI Assistant"


async def test_analytics_failure_does_not_break_request_handling():
    client = _client(ThrowingTransport(), bot_detector=lambda request: True)

    # A throwing transport must not propagate out of handle_request.
    result = await client.handle_request(_request({"User-Agent": "curl/8.0"}))

    assert result["action"] is HandlerAction.ALLOW


async def test_no_event_emitted_without_context_still_works():
    transport = RecordingTransport()
    client = _client(transport, bot_detector=lambda request: True)

    await client.handle_request(_request({"User-Agent": "curl/8.0"}))

    # Direct SDK invocation (no context) → source_cdn is None, request_id auto-generated.
    event = transport.events[0]
    assert event.source_cdn is None
    assert event.request_id
