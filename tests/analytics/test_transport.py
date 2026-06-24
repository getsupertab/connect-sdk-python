"""Tests for analytics transports."""

import asyncio
import json

import httpx
import respx

from supertab_connect._version import _get_sdk_user_agent
from supertab_connect.analytics.transport import (
    ANALYTICS_EVENTS_PATH,
    HttpAnalyticsTransport,
    NoopAnalyticsTransport,
)
from supertab_connect.analytics.transport import _background_tasks
from supertab_connect.analytics.types import AnalyticsEvent

RELAY_URL = "https://relay.test/ingest/events"

FIXTURE_EVENT = AnalyticsEvent(
    timestamp="2026-04-29T12:00:00.000Z",
    request_id="req-1",
    schema_version=2,
    source_cdn="cloudflare",
    user_agent="ua",
    client_ip="::ffff:1.2.3.4",
    path="/p",
    method="GET",
    referer="",
    accept_language="en",
    request_country="US",
    request_asn=13335,
    tls_fingerprint="ja3hash",
    has_token=False,
    token_outcome="absent",
    final_action="allow",
    enforcement_mode="observe",
    signature_agent=None,
    signature_input=None,
    signature=None,
    sec_fetch_mode=None,
    sec_fetch_site=None,
    sec_fetch_dest=None,
    sec_fetch_user=None,
    sec_ch_ua=None,
    sec_ch_ua_mobile=None,
    sec_ch_ua_platform=None,
    accept=None,
    host="example.com",
    has_cookies=False,
    header_names=["user-agent"],
    query_length=0,
    query_param_count=0,
    query_suspicious=False,
    accept_encoding=None,
    http_protocol=None,
    tls_version=None,
    tls_cipher=None,
    tls_client_hello_length=None,
    tls_client_extensions_sha1=None,
    as_organization=None,
    client_tcp_rtt=None,
    cdn_verified_bot_category=None,
    request_priority=None,
    tls_fingerprint_ja4=None,
)


async def _flush() -> None:
    """Await all in-flight background emit tasks."""
    while _background_tasks:
        await asyncio.gather(*list(_background_tasks), return_exceptions=True)


def test_analytics_events_path_targets_the_relay_events_route():
    assert ANALYTICS_EVENTS_PATH == "/ingest/events"


async def test_posts_json_body_with_bearer_api_key_to_relay_url():
    with respx.mock:
        route = respx.post(RELAY_URL).respond(status_code=202)
        transport = HttpAnalyticsTransport(url=RELAY_URL, api_key="merchant-api-key")

        transport.emit(FIXTURE_EVENT)
        await _flush()

        assert route.called
        request = route.calls[0].request
        assert request.method == "POST"
        assert request.headers["authorization"] == "Bearer merchant-api-key"
        assert request.headers["content-type"] == "application/json"
        assert request.headers["user-agent"] == _get_sdk_user_agent()
        assert json.loads(request.content) == {
            "timestamp": "2026-04-29T12:00:00.000Z",
            "request_id": "req-1",
            "schema_version": 2,
            "source_cdn": "cloudflare",
            "user_agent": "ua",
            "client_ip": "::ffff:1.2.3.4",
            "path": "/p",
            "method": "GET",
            "referer": "",
            "accept_language": "en",
            "request_country": "US",
            "request_asn": 13335,
            "tls_fingerprint": "ja3hash",
            "has_token": False,
            "token_outcome": "absent",
            "final_action": "allow",
            "enforcement_mode": "observe",
            "signature_agent": None,
            "signature_input": None,
            "signature": None,
            "sec_fetch_mode": None,
            "sec_fetch_site": None,
            "sec_fetch_dest": None,
            "sec_fetch_user": None,
            "sec_ch_ua": None,
            "sec_ch_ua_mobile": None,
            "sec_ch_ua_platform": None,
            "accept": None,
            "host": "example.com",
            "has_cookies": False,
            "header_names": ["user-agent"],
            "query_length": 0,
            "query_param_count": 0,
            "query_suspicious": False,
            "accept_encoding": None,
            "http_protocol": None,
            "tls_version": None,
            "tls_cipher": None,
            "tls_client_hello_length": None,
            "tls_client_extensions_sha1": None,
            "as_organization": None,
            "client_tcp_rtt": None,
            "cdn_verified_bot_category": None,
            "request_priority": None,
            "tls_fingerprint_ja4": None,
        }


async def test_does_not_raise_when_request_fails():
    with respx.mock:
        respx.post(RELAY_URL).mock(side_effect=httpx.ConnectError("network down"))
        transport = HttpAnalyticsTransport(url=RELAY_URL, api_key="t")

        transport.emit(FIXTURE_EVENT)  # must not raise
        await _flush()


async def test_does_not_raise_on_non_2xx_responses():
    with respx.mock:
        respx.post(RELAY_URL).respond(status_code=500, text="err")
        transport = HttpAnalyticsTransport(url=RELAY_URL, api_key="t")

        transport.emit(FIXTURE_EVENT)  # must not raise
        await _flush()


async def test_does_not_raise_on_non_http_errors():
    # A non-HTTPError raised on the request path (e.g. unexpected runtime error) must still
    # be swallowed so the fire-and-forget task never surfaces an unhandled exception.
    with respx.mock:
        respx.post(RELAY_URL).mock(side_effect=ValueError("unexpected boom"))
        transport = HttpAnalyticsTransport(url=RELAY_URL, api_key="t")

        transport.emit(FIXTURE_EVENT)  # must not raise
        await _flush()

        # No task should retain an unretrieved exception.
        assert not _background_tasks


def test_emit_without_running_loop_is_a_noop():
    # No running event loop here (sync test) → emit silently skips scheduling.
    transport = HttpAnalyticsTransport(url=RELAY_URL, api_key="t")
    transport.emit(FIXTURE_EVENT)


def test_noop_transport_emit_never_throws():
    transport = NoopAnalyticsTransport()
    assert transport.emit(FIXTURE_EVENT) is None
