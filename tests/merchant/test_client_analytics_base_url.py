"""Tests for analytics ingest base-URL resolution.

The analytics relay targets the dedicated ingest service by default, independent of the
API base URL used for token acquisition / JWKS / verification.
"""

import pytest

from supertab_connect.analytics.transport import HttpAnalyticsTransport, NoopAnalyticsTransport
from supertab_connect.merchant.client import SupertabConnect
from supertab_connect.types import SupertabConnectConfig

from tests.merchant.constants import SUPERTAB_BASE_URL

DEFAULT_INGEST = "https://ingest-connect.supertab.co"


@pytest.fixture(autouse=True)
def _reset_singleton():
    SupertabConnect.reset_instance()
    original_base_url = SupertabConnect.get_base_url()
    original_analytics_base_url = SupertabConnect.get_analytics_base_url()
    SupertabConnect.set_base_url(SUPERTAB_BASE_URL)
    yield
    # Restore the mutable class-level hosts so a mutating test can't leak into the next.
    SupertabConnect.set_base_url(original_base_url)
    SupertabConnect.set_analytics_base_url(original_analytics_base_url)
    SupertabConnect.reset_instance()


def _relay_url(**config_kwargs) -> str:
    client = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123", **config_kwargs))
    transport = client._analytics_transport
    assert isinstance(transport, HttpAnalyticsTransport)
    return transport._url


def test_disabled_analytics_uses_noop_transport():
    client = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123"))
    assert isinstance(client._analytics_transport, NoopAnalyticsTransport)


def test_defaults_analytics_relay_to_ingest_host():
    assert _relay_url(analytics_enabled=True) == f"{DEFAULT_INGEST}/ingest/events"


def test_config_analytics_base_url_overrides_default():
    assert (
        _relay_url(analytics_enabled=True, analytics_base_url="https://ingest.example.com")
        == "https://ingest.example.com/ingest/events"
    )


def test_set_analytics_base_url_overrides_default():
    SupertabConnect.set_analytics_base_url("https://static.example.com")
    assert _relay_url(analytics_enabled=True) == "https://static.example.com/ingest/events"


def test_config_analytics_base_url_beats_set_analytics_base_url():
    SupertabConnect.set_analytics_base_url("https://static.example.com")
    assert (
        _relay_url(analytics_enabled=True, analytics_base_url="https://perinstance.example.com")
        == "https://perinstance.example.com/ingest/events"
    )


def test_analytics_host_independent_of_set_base_url():
    SupertabConnect.set_base_url("https://api.example.com")
    assert _relay_url(analytics_enabled=True) == f"{DEFAULT_INGEST}/ingest/events"


def test_get_analytics_base_url_reflects_setter():
    SupertabConnect.set_analytics_base_url("https://x.example.com")
    assert SupertabConnect.get_analytics_base_url() == "https://x.example.com"
