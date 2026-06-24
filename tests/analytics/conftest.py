"""Shared fixtures for analytics tests."""

import pytest

from supertab_connect.analytics import transport as transport_module


@pytest.fixture(autouse=True)
async def _reset_analytics_http_client():
    """Reset the module-level analytics http client around each test."""
    await transport_module.aclose_http_client()
    yield
    await transport_module.aclose_http_client()
