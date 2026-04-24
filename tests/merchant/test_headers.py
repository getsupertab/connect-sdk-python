"""Tests for merchant event header mapping."""

from connect.merchant.headers import to_event_properties


def test_to_event_properties_lowercases_keys_and_prefixes_them():
    result = to_event_properties(
        {
            "Accept-Language": "en-US",
            "X-Custom": "value",
        }
    )

    assert result == {
        "h_accept-language": "en-US",
        "h_x-custom": "value",
    }


def test_to_event_properties_drops_denied_headers_regardless_of_casing():
    result = to_event_properties(
        {
            "Authorization": "License abc123",
            "COOKIE": "session=xyz",
            "Set-Cookie": "foo=bar",
            "Proxy-Authorization": "Basic xxx",
            "X-API-Key": "sk_123",
            "X-Amz-Security-Token": "amz-token",
            "User-Agent": "GPTBot/1.0",
            "X-License-Auth": "cf-request-id",
            "Accept": "application/json",
        }
    )

    assert result == {"h_accept": "application/json"}


def test_to_event_properties_keeps_client_ip_headers():
    result = to_event_properties(
        {
            "X-Forwarded-For": "203.0.113.1",
            "X-Real-IP": "203.0.113.2",
            "CF-Connecting-IP": "203.0.113.3",
            "True-Client-IP": "203.0.113.4",
        }
    )

    assert result == {
        "h_x-forwarded-for": "203.0.113.1",
        "h_x-real-ip": "203.0.113.2",
        "h_cf-connecting-ip": "203.0.113.3",
        "h_true-client-ip": "203.0.113.4",
    }


def test_to_event_properties_returns_empty_dict_for_empty_input():
    assert to_event_properties({}) == {}


def test_to_event_properties_preserves_values_verbatim():
    result = to_event_properties({"X-Custom": "  value with spaces  "})

    assert result["h_x-custom"] == "  value with spaces  "
