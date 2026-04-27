"""Merchant-facing helpers for the Supertab Connect SDK."""

from connect.merchant.bots import default_bot_detector
from connect.merchant.client import SupertabConnect

__all__ = [
    "default_bot_detector",
    "SupertabConnect",
]
