"""Tests for merchant bot detection helpers."""

import httpx

from connect.merchant.bots import default_bot_detector

from tests.merchant.constants import REQUEST_URL


def _make_request(headers: dict[str, str]) -> httpx.Request:
    return httpx.Request("GET", REQUEST_URL, headers=headers)


def test_default_bot_detector_flags_known_bot_user_agents():
    request = _make_request(
        {
            "User-Agent": "GPTBot/1.0",
            "Accept": "text/html",
            "Accept-Language": "en-US",
            "Sec-CH-UA": '"Chromium";v="123"',
        }
    )

    assert default_bot_detector(request) is True


def test_default_bot_detector_flags_missing_headers():
    request = _make_request(
        {
            "User-Agent": "CustomBrowser/1.0",
            "Sec-CH-UA": '"Chromium";v="123"',
        }
    )

    assert default_bot_detector(request) is True


def test_default_bot_detector_flags_missing_sec_ch_ua_for_non_safari_agents():
    request = _make_request(
        {
            "User-Agent": "CustomBrowser/1.0",
            "Accept": "text/html",
            "Accept-Language": "en-US",
        }
    )

    assert default_bot_detector(request) is True


def test_default_bot_detector_safari_mozilla_exception_returns_false():
    request = _make_request(
        {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
            ),
            "Accept": "text/html",
            "Accept-Language": "en-US",
        }
    )

    assert default_bot_detector(request) is False


def test_default_bot_detector_flags_completely_missing_headers():
    request = _make_request({})

    assert default_bot_detector(request) is True
