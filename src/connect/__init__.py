"""Supertab Connect SDK."""

from connect.customer.token import obtain_license_token
from connect.exceptions import SupertabConnectError

__all__ = [
    "obtain_license_token",
    "SupertabConnectError",
]
