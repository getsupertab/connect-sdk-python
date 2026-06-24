"""Tests for client-IP normalization."""

import pytest

from supertab_connect.analytics.ip import normalize_client_ip


def test_maps_ipv4_to_ipv6_mapped_form():
    assert normalize_client_ip("1.2.3.4") == "::ffff:1.2.3.4"
    assert normalize_client_ip("192.0.2.1") == "::ffff:192.0.2.1"


def test_trims_surrounding_whitespace_before_mapping_ipv4():
    assert normalize_client_ip("  1.2.3.4  ") == "::ffff:1.2.3.4"


def test_passes_ipv6_through_unchanged():
    assert normalize_client_ip("2001:db8::1") == "2001:db8::1"
    assert normalize_client_ip("::1") == "::1"


@pytest.mark.parametrize("value", [None, "", "   "])
def test_returns_unspecified_for_empty(value):
    assert normalize_client_ip(value) == "::"


def test_returns_unspecified_for_unrecognized_value():
    assert normalize_client_ip("not-an-ip") == "::"
