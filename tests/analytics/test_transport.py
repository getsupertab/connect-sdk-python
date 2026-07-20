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


def test_analytics_events_path_targets_the_relay_events_route():
    assert ANALYTICS_EVENTS_PATH == "/ingest/events"


async def test_posts_json_body_with_bearer_api_key_to_relay_url():
    with respx.mock:
        route = respx.post(RELAY_URL).respond(status_code=202)
        transport = HttpAnalyticsTransport(url=RELAY_URL, api_key="merchant-api-key")

        transport.emit(FIXTURE_EVENT)
        await transport.flush()

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
        await transport.flush()


async def test_does_not_raise_on_non_2xx_responses():
    with respx.mock:
        respx.post(RELAY_URL).respond(status_code=500, text="err")
        transport = HttpAnalyticsTransport(url=RELAY_URL, api_key="t")

        transport.emit(FIXTURE_EVENT)  # must not raise
        await transport.flush()


async def test_does_not_raise_on_non_http_errors():
    # A non-HTTPError raised on the request path (e.g. unexpected runtime error) must still
    # be swallowed so the fire-and-forget task never surfaces an unhandled exception.
    with respx.mock:
        respx.post(RELAY_URL).mock(side_effect=ValueError("unexpected boom"))
        transport = HttpAnalyticsTransport(url=RELAY_URL, api_key="t")

        transport.emit(FIXTURE_EVENT)  # must not raise
        await transport.flush()

        # No task should retain an unretrieved exception.
        assert not transport._tasks


def test_emit_without_running_loop_is_a_noop():
    # No running event loop here (sync test) → emit silently skips scheduling.
    transport = HttpAnalyticsTransport(url=RELAY_URL, api_key="t")
    transport.emit(FIXTURE_EVENT)


def test_noop_transport_emit_never_throws():
    transport = NoopAnalyticsTransport()
    assert transport.emit(FIXTURE_EVENT) is None


async def test_noop_transport_aclose_is_a_noop():
    transport = NoopAnalyticsTransport()
    assert await transport.aclose() is None


async def test_aclose_drains_pending_emit():
    # Regression: an emit scheduled just before aclose() must be flushed, not dropped — a task
    # must never be silently discarded by close.
    with respx.mock:
        route = respx.post(RELAY_URL).respond(status_code=202)
        transport = HttpAnalyticsTransport(url=RELAY_URL, api_key="t")

        transport.emit(FIXTURE_EVENT)
        await transport.aclose()

        assert route.called  # event was flushed, not dropped
        assert not transport._tasks
        assert transport._client is None


async def test_aclose_closes_the_underlying_client():
    # The lazily-created client must be closed by aclose() — never left open to leak.
    with respx.mock:
        respx.post(RELAY_URL).respond(status_code=202)
        transport = HttpAnalyticsTransport(url=RELAY_URL, api_key="t")

        transport.emit(FIXTURE_EVENT)
        await transport.flush()  # completes the send; client now exists
        client = transport._client
        assert client is not None and not client.is_closed

        await transport.aclose()

        assert client.is_closed
        assert transport._client is None


async def test_emit_after_aclose_is_a_noop():
    with respx.mock:
        route = respx.post(RELAY_URL).respond(status_code=202)
        transport = HttpAnalyticsTransport(url=RELAY_URL, api_key="t")

        await transport.aclose()
        transport.emit(FIXTURE_EVENT)  # closed → no-op

        assert not transport._tasks
        assert not route.called


async def test_aclose_is_bounded_when_send_hangs():
    # A send that never completes must not make aclose() hang: flush is bounded and stragglers
    # are cancelled before the client is closed.
    release = asyncio.Event()

    async def _hang(request: httpx.Request) -> httpx.Response:
        await release.wait()  # never released
        return httpx.Response(202)

    with respx.mock:
        respx.post(RELAY_URL).mock(side_effect=_hang)
        transport = HttpAnalyticsTransport(url=RELAY_URL, api_key="t", flush_timeout=0.05)

        transport.emit(FIXTURE_EVENT)
        # Let _send start and lazily create the client (it then blocks on `release`).
        for _ in range(10):
            if transport._client is not None:
                break
            await asyncio.sleep(0)
        client = transport._client
        assert client is not None

        # Overall guard well above flush_timeout: aclose must return on its own.
        await asyncio.wait_for(transport.aclose(), timeout=1)

        assert not transport._tasks
        assert transport._client is None
        assert client.is_closed
