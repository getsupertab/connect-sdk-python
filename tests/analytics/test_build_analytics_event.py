"""Tests for building relay analytics events."""

from dataclasses import asdict, replace
from datetime import datetime, timezone

import httpx
import pytest

from supertab_connect.analytics.build_analytics_event import (
    BuildAnalyticsEventContext,
    build_analytics_event,
)
from supertab_connect.analytics.types import SCHEMA_VERSION, CdnRequestSignals, Decision
from supertab_connect.types import EnforcementMode

FIXED_TIME = datetime(2026, 4, 29, 12, 0, 0, tzinfo=timezone.utc)
REQUEST_ID = "req-123"

BASE_DECISION = Decision(
    has_token=False,
    token_outcome="absent",
    final_action="allow",
    enforcement_mode=EnforcementMode.OBSERVE,
)


def _make_request(
    *,
    url: str = "https://example.com/articles/foo?x=1",
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> httpx.Request:
    return httpx.Request(method, url, headers=headers or {})


def _ctx(**extra) -> BuildAnalyticsEventContext:
    base = BuildAnalyticsEventContext(request_id=REQUEST_ID, source_cdn="cloudflare", timestamp=FIXED_TIME)
    return replace(base, **extra)


def test_returns_event_matching_relay_shape():
    request = _make_request(
        headers={
            "user-agent": "Mozilla/5.0",
            "referer": "https://example.com/",
            "accept-language": "en-US,en;q=0.9",
        }
    )

    event = build_analytics_event(request, BASE_DECISION, _ctx(client_ip="1.2.3.4"))

    assert asdict(event) == {
        "timestamp": "2026-04-29T12:00:00.000Z",
        "request_id": REQUEST_ID,
        "schema_version": SCHEMA_VERSION,
        "source_cdn": "cloudflare",
        "user_agent": "Mozilla/5.0",
        "client_ip": "::ffff:1.2.3.4",
        "path": "/articles/foo",
        "method": "GET",
        "referer": "https://example.com/",
        "accept_language": "en-US,en;q=0.9",
        "request_country": None,
        "request_asn": None,
        "tls_fingerprint": None,
        "has_token": False,
        "token_outcome": "absent",
        "final_action": "allow",
        "enforcement_mode": "observe",
        "signature_agent": None,
        "signature_input": None,
        "signature": None,
        # Capture v2 — portable header signals (none of these headers were sent).
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
        "header_names": ["accept-language", "referer", "user-agent"],
        "query_length": 3,
        "query_param_count": 1,
        "query_suspicious": False,
        # Capture v2 — CDN plumbing (no cdn_signals in context → None).
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


def test_passes_through_classification_signals():
    event = build_analytics_event(
        _make_request(),
        BASE_DECISION,
        _ctx(request_country="DE", request_asn=3320, tls_fingerprint="abc123"),
    )
    assert event.request_country == "DE"
    assert event.request_asn == 3320
    assert event.tls_fingerprint == "abc123"


def test_classification_signals_default_to_none():
    event = build_analytics_event(_make_request(), BASE_DECISION, _ctx())
    assert event.request_country is None
    assert event.request_asn is None
    assert event.tls_fingerprint is None


def test_reads_signature_headers_from_request():
    request = _make_request(
        headers={
            "signature-agent": "https://agent.example",
            "signature-input": "sig1=(...)",
            "signature": "sig1=:abc:",
        }
    )
    event = build_analytics_event(request, BASE_DECISION, _ctx())
    assert event.signature_agent == "https://agent.example"
    assert event.signature_input == "sig1=(...)"
    assert event.signature == "sig1=:abc:"


def test_signature_headers_default_to_none():
    event = build_analytics_event(_make_request(), BASE_DECISION, _ctx())
    assert event.signature_agent is None
    assert event.signature_input is None
    assert event.signature is None


@pytest.mark.parametrize("final_action", ["allow", "observe", "block"])
def test_passes_through_final_action(final_action):
    decision = replace(BASE_DECISION, final_action=final_action)
    event = build_analytics_event(_make_request(), decision, _ctx())
    assert event.final_action == final_action


@pytest.mark.parametrize(
    ("mode", "wire"),
    [
        (EnforcementMode.OBSERVE, "observe"),
        (EnforcementMode.ENFORCE, "enforce"),
        (EnforcementMode.DISABLED, "disabled"),
    ],
)
def test_serializes_enforcement_mode_to_wire(mode, wire):
    decision = replace(BASE_DECISION, enforcement_mode=mode)
    event = build_analytics_event(_make_request(), decision, _ctx())
    assert event.enforcement_mode == wire


def test_source_cdn_is_none_for_direct_sdk_invocation():
    event = build_analytics_event(_make_request(), BASE_DECISION, BuildAnalyticsEventContext())
    assert event.source_cdn is None


def test_generates_request_id_when_absent():
    event = build_analytics_event(_make_request(), BASE_DECISION, BuildAnalyticsEventContext(timestamp=FIXED_TIME))
    assert event.request_id  # a uuid4 string


def test_path_preserves_percent_encoding():
    # request.url.path would decode %2F->"/" and %20->" "; the event must keep encoded semantics.
    request = _make_request(url="https://example.com/a%2Fb/c%20d?x=1")
    event = build_analytics_event(request, BASE_DECISION, _ctx())
    assert event.path == "/a%2Fb/c%20d"


def test_path_drops_query_string():
    request = _make_request(url="https://example.com/articles/foo?x=1&y=2")
    event = build_analytics_event(request, BASE_DECISION, _ctx())
    assert event.path == "/articles/foo"


def test_missing_headers_default_to_empty_strings():
    event = build_analytics_event(_make_request(), BASE_DECISION, _ctx())
    assert event.user_agent == ""
    assert event.referer == ""
    assert event.accept_language == ""


# --- Capture v2 -------------------------------------------------------------------------------

BROWSER_HEADERS = {
    "user-agent": "Mozilla/5.0",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-dest": "document",
    "sec-fetch-user": "?1",
    "sec-ch-ua": '"Chromium";v="120", "Not(A:Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "accept": "text/html",
    "cookie": "session=abc",
}


def test_captures_sec_fetch_and_client_hints_from_browser_request():
    event = build_analytics_event(_make_request(headers=BROWSER_HEADERS), BASE_DECISION, _ctx())
    assert event.sec_fetch_mode == "navigate"
    assert event.sec_fetch_site == "none"
    assert event.sec_fetch_dest == "document"
    assert event.sec_fetch_user == "?1"
    assert event.sec_ch_ua == '"Chromium";v="120", "Not(A:Brand";v="24"'
    assert event.sec_ch_ua_mobile == "?0"
    assert event.sec_ch_ua_platform == '"macOS"'
    assert event.accept == "text/html"
    assert event.has_cookies is True


def test_curl_like_request_carries_no_browser_signals():
    event = build_analytics_event(_make_request(headers={"user-agent": "curl/8.0"}), BASE_DECISION, _ctx())
    assert event.sec_fetch_mode is None
    assert event.sec_fetch_site is None
    assert event.sec_fetch_dest is None
    assert event.sec_fetch_user is None
    assert event.sec_ch_ua is None
    assert event.sec_ch_ua_mobile is None
    assert event.sec_ch_ua_platform is None
    assert event.has_cookies is False


def test_host_falls_back_to_url_host():
    event = build_analytics_event(_make_request(url="https://pub.example.com/a"), BASE_DECISION, _ctx())
    assert event.host == "pub.example.com"


def test_truncates_accept_and_sec_ch_ua_to_512_chars():
    long = "a" * 600
    event = build_analytics_event(_make_request(headers={"accept": long, "sec-ch-ua": long}), BASE_DECISION, _ctx())
    assert event.accept == "a" * 512
    assert event.sec_ch_ua == "a" * 512


def test_header_names_lowercased_deduped_sorted():
    event = build_analytics_event(
        _make_request(headers={"User-Agent": "x", "Accept": "y", "Referer": "z"}),
        BASE_DECISION,
        _ctx(),
    )
    assert event.header_names == ["accept", "referer", "user-agent"]


def test_header_names_strips_edge_injected_headers_across_all_cdns():
    event = build_analytics_event(
        _make_request(
            headers={
                "user-agent": "x",
                # Cloudflare
                "cf-connecting-ip": "1.2.3.4",
                "cf-ray": "abc",
                # Fastly
                "fastly-client-ip": "1.2.3.4",
                "fastly-client-ja3": "deadbeef",
                # CloudFront
                "cloudfront-viewer-country": "DE",
                "cloudfront-viewer-ja3-fingerprint": "abc",
                # shared / SDK routing / synthesized
                "x-forwarded-for": "1.2.3.4",
                "x-real-ip": "1.2.3.4",
                "x-original-request-url": "https://pub.example.com/a",
            }
        ),
        BASE_DECISION,
        _ctx(),
    )
    # host is stripped too (httpx synthesizes it; the TS SDK never emits it).
    assert event.header_names == ["user-agent"]


def test_query_signals_derived_without_storing_raw_query():
    event = build_analytics_event(_make_request(url="https://x.test/p?a=1&b=2&c=3"), BASE_DECISION, _ctx())
    assert event.query_length == len("a=1&b=2&c=3")
    assert event.query_param_count == 3
    assert event.query_suspicious is False
    # The raw query string must never appear on the event.
    assert "a=1&b=2&c=3" not in str(asdict(event))


def test_query_signals_are_zero_for_query_less_url():
    event = build_analytics_event(_make_request(url="https://x.test/p"), BASE_DECISION, _ctx())
    assert event.query_length == 0
    assert event.query_param_count == 0
    assert event.query_suspicious is False


@pytest.mark.parametrize(
    "url",
    [
        "https://x.test/?f=../../etc/passwd",
        "https://x.test/?q=UNION%20SELECT%201",
        "https://x.test/?x=%3Cscript%3E",
    ],
)
def test_query_suspicious_flags_exploit_markers_raw_and_encoded(url):
    event = build_analytics_event(_make_request(url=url), BASE_DECISION, _ctx())
    assert event.query_suspicious is True


def test_cdn_signals_passthrough_with_truncation():
    event = build_analytics_event(
        _make_request(),
        BASE_DECISION,
        _ctx(
            cdn_signals=CdnRequestSignals(
                accept_encoding="gzip, br",
                http_protocol="HTTP/2",
                tls_version="TLSv1.3",
                tls_cipher="AEAD-AES128-GCM-SHA256",
                tls_client_hello_length=1811,
                tls_client_extensions_sha1="4cFD...",
                as_organization="o" * 600,
                client_tcp_rtt=50,
                cdn_verified_bot_category="Search Engine Crawler",
                request_priority="weight=256;exclusive=1",
                tls_fingerprint_ja4=None,
            )
        ),
    )
    assert event.accept_encoding == "gzip, br"
    assert event.http_protocol == "HTTP/2"
    assert event.tls_version == "TLSv1.3"
    assert event.tls_cipher == "AEAD-AES128-GCM-SHA256"
    assert event.tls_client_hello_length == 1811
    assert event.tls_client_extensions_sha1 == "4cFD..."
    assert event.as_organization == "o" * 512
    assert event.client_tcp_rtt == 50
    assert event.cdn_verified_bot_category == "Search Engine Crawler"
    assert event.request_priority == "weight=256;exclusive=1"
    assert event.tls_fingerprint_ja4 is None


def test_cdn_signals_default_to_none_when_absent():
    event = build_analytics_event(_make_request(), BASE_DECISION, _ctx())
    assert event.accept_encoding is None
    assert event.http_protocol is None
    assert event.tls_version is None
    assert event.tls_cipher is None
    assert event.tls_client_hello_length is None
    assert event.tls_client_extensions_sha1 is None
    assert event.as_organization is None
    assert event.client_tcp_rtt is None
    assert event.cdn_verified_bot_category is None
    assert event.request_priority is None
    assert event.tls_fingerprint_ja4 is None


def test_schema_version_is_2():
    event = build_analytics_event(_make_request(), BASE_DECISION, _ctx())
    assert event.schema_version == 2
