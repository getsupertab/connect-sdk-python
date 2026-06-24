"""Analytics event schema and transport protocol (mirrors TS `analytics/types.ts`)."""

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from supertab_connect.types import EnforcementMode, LicenseTokenInvalidReason

SCHEMA_VERSION = 1

SourceCdn = Literal["cloudflare", "fastly", "cloudfront"]

TokenOutcome = Literal[
    "absent",
    "valid",
    "expired",
    "invalid_signature",
    "invalid_audience",
    "invalid_resource",
    "invalid_issuer",
    "malformed",
    "server_error",
    "not_validated",
]

FinalAction = Literal["allow", "observe", "block"]

EnforcementWire = Literal["observe", "enforce", "disabled"]


@dataclass(frozen=True)
class Decision:
    has_token: bool
    token_outcome: TokenOutcome
    final_action: FinalAction
    enforcement_mode: EnforcementMode


@dataclass(frozen=True)
class AnalyticsEvent:
    timestamp: str
    request_id: str
    schema_version: int
    # None when the request did not pass through a CDN (e.g. invoked directly via the SDK).
    source_cdn: SourceCdn | None

    user_agent: str
    client_ip: str
    path: str
    method: str
    referer: str
    accept_language: str

    # Classification signals — supplied by the CDN layer (platform-specific). None when not exposed.
    request_country: str | None
    request_asn: int | None
    tls_fingerprint: str | None

    has_token: bool
    token_outcome: TokenOutcome
    final_action: FinalAction
    enforcement_mode: EnforcementWire

    # HTTP Message Signature headers — platform-agnostic, read directly from request headers.
    signature_agent: str | None
    signature_input: str | None
    signature: str | None


@runtime_checkable
class AnalyticsTransport(Protocol):
    def emit(self, event: AnalyticsEvent) -> None:
        """Emit an analytics event. Implementations must never block the request path or raise."""
        ...


TOKEN_OUTCOME_BY_REASON: dict[LicenseTokenInvalidReason, TokenOutcome] = {
    LicenseTokenInvalidReason.MISSING_TOKEN: "absent",
    LicenseTokenInvalidReason.EXPIRED: "expired",
    LicenseTokenInvalidReason.SIGNATURE_VERIFICATION_FAILED: "invalid_signature",
    LicenseTokenInvalidReason.INVALID_AUDIENCE: "invalid_audience",
    LicenseTokenInvalidReason.INVALID_ISSUER: "invalid_issuer",
    LicenseTokenInvalidReason.INVALID_HEADER: "malformed",
    LicenseTokenInvalidReason.INVALID_PAYLOAD: "malformed",
    LicenseTokenInvalidReason.INVALID_ALG: "malformed",
    LicenseTokenInvalidReason.SERVER_ERROR: "server_error",
}
