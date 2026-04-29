"""SDK exceptions."""


class SupertabConnectError(Exception):
    """Base exception for Supertab Connect SDK failures."""


class JwksKeyNotFoundError(SupertabConnectError):
    """Raised when no key matching the given kid is found in the JWKS."""

    def __init__(self, kid: str | None) -> None:
        self.kid = kid
        super().__init__(f"Key not found in JWKS: {kid}")
