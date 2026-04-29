"""Merchant-facing helpers for the Supertab Connect SDK."""

from supertab_connect.merchant.bots import default_bot_detector
from supertab_connect.merchant.client import SupertabConnect

__all__ = [
    "default_bot_detector",
    "SupertabConnect",
]
