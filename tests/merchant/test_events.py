"""Tests for merchant event recording helpers."""

import json
import logging

import httpx
import respx

from connect.merchant.events import record_event

from tests.merchant.constants import SUPERTAB_BASE_URL

EVENTS_URL = f"{SUPERTAB_BASE_URL}/events"


async def test_record_event_posts_expected_payload(monkeypatch):
    monkeypatch.setattr("connect.merchant.events._get_sdk_user_agent", lambda: "sdk-test/1.2.3")

    with respx.mock:
        route = respx.post(EVENTS_URL).respond(status_code=201, json={"ok": True})

        await record_event(
            api_key="sk_test_123",
            base_url=SUPERTAB_BASE_URL,
            event_name="license_used",
            properties={"page_url": "https://example.com/premium/article"},
            license_id="lic_test_123",
        )

    request = route.calls[0].request
    assert request.headers["Authorization"] == "Bearer sk_test_123"
    assert request.headers["Content-Type"] == "application/json"
    assert request.headers["User-Agent"] == "sdk-test/1.2.3"
    assert json.loads(request.content) == {
        "event_name": "license_used",
        "license_id": "lic_test_123",
        "properties": {"page_url": "https://example.com/premium/article"},
    }


async def test_record_event_logs_non_2xx_responses(caplog):
    with respx.mock:
        respx.post(EVENTS_URL).respond(status_code=500)

        with caplog.at_level(logging.DEBUG, logger="connect.common"):
            await record_event(
                api_key="sk_test_123",
                base_url=SUPERTAB_BASE_URL,
                event_name="license_used",
                properties={},
                debug=True,
            )

    assert "Failed to record event: 500" in caplog.text


async def test_record_event_swallows_request_failures(caplog):
    request = httpx.Request("POST", EVENTS_URL)

    with respx.mock:
        respx.post(EVENTS_URL).mock(side_effect=httpx.ConnectError("boom", request=request))

        with caplog.at_level(logging.ERROR, logger="connect.common"):
            await record_event(
                api_key="sk_test_123",
                base_url=SUPERTAB_BASE_URL,
                event_name="license_used",
                properties={},
                debug=True,
            )

    assert "Error recording event:" in caplog.text
