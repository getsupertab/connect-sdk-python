"""Tests for building relay analytics events."""

from dataclasses import asdict, replace
from datetime import datetime, timezone

import httpx
import pytest

from supertab_connect.analytics.build_analytics_event import (
    BuildAnalyticsEventContext,
    build_analytics_event,
)
from supertab_connect.analytics.types import SCHEMA_VERSION, Decision
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
