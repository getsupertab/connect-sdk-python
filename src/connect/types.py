"""Core types for the Supertab Connect SDK."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class EnforcementMode(StrEnum):
    DISABLED = "disabled"
    SOFT = "soft"
    STRICT = "strict"


class LicenseTokenInvalidReason(StrEnum):
    MISSING_TOKEN = "missing_license_token"
    INVALID_HEADER = "invalid_license_header"
    INVALID_ALG = "invalid_license_algorithm"
    INVALID_PAYLOAD = "invalid_license_payload"
    INVALID_ISSUER = "invalid_license_issuer"
    SIGNATURE_VERIFICATION_FAILED = "license_signature_verification_failed"
    EXPIRED = "license_token_expired"
    INVALID_AUDIENCE = "invalid_license_audience"
    SERVER_ERROR = "server_error"


class HandlerAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass(frozen=True)
class ValidLicenseToken:
    valid: bool = field(default=True, init=False)
    license_id: str | None
    payload: dict[str, Any]


@dataclass(frozen=True)
class InvalidLicenseToken:
    valid: bool = field(default=False, init=False)
    reason: LicenseTokenInvalidReason
    error: str
    license_id: str | None = None


LicenseTokenVerificationResult = ValidLicenseToken | InvalidLicenseToken


@dataclass(frozen=True)
class RSLVerificationResult:
    valid: bool
    error: str | None = None


@dataclass(frozen=True)
class EventPayload:
    event_name: str
    license_id: str | None
    properties: dict[str, str]
