"""Supertab Connect SDK."""

from .customer import obtain_license_token
from .exceptions import SupertabConnectError

__all__ = [
    "obtain_license_token",
    "SupertabConnectError",
]
