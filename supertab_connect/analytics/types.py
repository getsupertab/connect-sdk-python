"""Analytics event schema and transport protocol (mirrors TS `analytics/types.ts`)."""

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from supertab_connect.types import EnforcementMode, LicenseTokenInvalidReason

SCHEMA_VERSION = 2

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

    # --- Capture v2 (schema_version 2): spoof-detection signals ---
    # Portable header signals — read directly from request headers (every CDN).
    sec_fetch_mode: str | None
    sec_fetch_site: str | None
    sec_fetch_dest: str | None
    sec_fetch_user: str | None
    sec_ch_ua: str | None
    sec_ch_ua_mobile: str | None
    sec_ch_ua_platform: str | None
    accept: str | None
    host: str | None
    has_cookies: bool | None
    # Lowercased, deduped, sorted request-header names with edge-injected headers
    # (cf-*, x-forwarded-*, x-real-ip, …) and the synthesized Host stripped. Non-nullable: [] when none.
    header_names: list[str]

    # Query-string derived signals. The raw query is NEVER stored (PII gate → option b);
    # only these mechanical derivations are emitted.
    query_length: int | None
    query_param_count: int | None
    query_suspicious: bool | None

    # CDN plumbing — not derivable from the portable Request. Supplied per platform by the
    # caller via HandleRequestContext; null when not exposed.
    accept_encoding: str | None
    http_protocol: str | None
    tls_version: str | None
    tls_cipher: str | None
    tls_client_hello_length: int | None
    tls_client_extensions_sha1: str | None
    as_organization: str | None
    client_tcp_rtt: int | None
    cdn_verified_bot_category: str | None
    request_priority: str | None
    tls_fingerprint_ja4: str | None


@dataclass(frozen=True)
class CdnRequestSignals:
    """CDN-supplied request signals that cannot be read from the portable httpx ``Request``.

    Extracted per platform by the caller (Cloudflare ``request.cf``, Fastly headers, …) and
    threaded through ``HandleRequestContext``. Field names match the wire (snake_case) contract,
    so they pass straight through onto the event.
    """

    accept_encoding: str | None = None
    http_protocol: str | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None
    tls_client_hello_length: int | None = None
    tls_client_extensions_sha1: str | None = None
    as_organization: str | None = None
    client_tcp_rtt: int | None = None
    cdn_verified_bot_category: str | None = None
    request_priority: str | None = None
    tls_fingerprint_ja4: str | None = None


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
