"""Core types for the Supertab Connect SDK."""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Literal, NotRequired, TypeAlias, TypedDict

from httpx import Request

if TYPE_CHECKING:
    from supertab_connect.analytics.types import AnalyticsTransport, CdnRequestSignals


class EnforcementMode(StrEnum):
    DISABLED = "disabled"
    OBSERVE = "observe"
    ENFORCE = "enforce"


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
    RESPOND = "respond"


class UsageType(StrEnum):
    ALL = "all"
    SEARCH = "search"
    AI_ALL = "ai-all"
    AI_TRAIN = "ai-train"
    AI_INDEX = "ai-index"
    AI_INPUT = "ai-input"


BotDetector: TypeAlias = Callable[[Request], bool]


@dataclass(frozen=True)
class SupertabConnectConfig:
    api_key: str
    enforcement: EnforcementMode = EnforcementMode.OBSERVE
    supertab_base_url: str | None = None
    bot_detector: BotDetector | None = None
    debug: bool = False
    # Enables analytics emission to the Supertab Connect relay. Default: False.
    analytics_enabled: bool = False
    # Internal dependency-injection seam: overrides the default HttpAnalyticsTransport when provided.
    # Used by tests to inject in-memory transports. Not a merchant-facing option.
    analytics_transport: "AnalyticsTransport | None" = None


@dataclass(frozen=True)
class HandleRequestContext:
    """Optional CDN-supplied request context for `handle_request`.

    All fields are omitted (None) for direct SDK invocation that did not pass through a CDN.
    """

    source_cdn: Literal["cloudflare", "fastly", "cloudfront"] | None = None
    client_ip: str | None = None
    request_id: str | None = None
    request_country: str | None = None
    request_asn: int | None = None
    tls_fingerprint: str | None = None
    # Capture-v2 CDN plumbing not derivable from the portable Request (e.g. Cloudflare request.cf).
    cdn_signals: "CdnRequestSignals | None" = None


class AllowHandlerResult(TypedDict):
    action: Literal[HandlerAction.ALLOW]
    headers: NotRequired[dict[str, str]]


class BlockHandlerResult(TypedDict):
    action: Literal[HandlerAction.BLOCK]
    status: int
    body: str
    headers: dict[str, str]


class RespondHandlerResult(TypedDict):
    """A fully-formed response the caller must serve verbatim without contacting origin.

    Emitted for the self-report status probe (`/.well-known/supertab/status`), which the
    SDK answers directly rather than forwarding.
    """

    action: Literal[HandlerAction.RESPOND]
    status: int
    body: str
    headers: dict[str, str]


HandlerResult: TypeAlias = AllowHandlerResult | BlockHandlerResult | RespondHandlerResult


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
