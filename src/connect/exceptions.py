"""Exceptions for the Supertab Connect SDK."""


class SupertabConnectError(Exception):
    """Base exception for Supertab Connect SDK errors."""


class JwksKeyNotFoundError(SupertabConnectError):
    """Raised when a JWKS key ID is not found in the key set."""

    def __init__(self, kid: str | None) -> None:
        super().__init__(f"No matching platform key found: {kid}")
        self.kid = kid
