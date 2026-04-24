"""Merchant-facing helpers for the Supertab Connect SDK."""

from connect.merchant.bots import default_bot_detector
from connect.merchant.client import SupertabConnect
from connect.merchant.events import record_event
from connect.merchant.headers import to_event_properties
from connect.merchant.jwks import clear_jwks_cache, fetch_platform_jwks
from connect.merchant.license import (
    build_block_result,
    build_signal_result,
    generate_license_link,
    verify_and_record_event,
    verify_license_token,
)

__all__ = [
    "build_block_result",
    "build_signal_result",
    "clear_jwks_cache",
    "default_bot_detector",
    "fetch_platform_jwks",
    "generate_license_link",
    "record_event",
    "SupertabConnect",
    "to_event_properties",
    "verify_and_record_event",
    "verify_license_token",
]
