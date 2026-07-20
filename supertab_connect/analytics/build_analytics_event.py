"""Build a relay AnalyticsEvent from a request + decision (mirrors TS `buildAnalyticsEvent.ts`)."""

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import unquote

from httpx import Request

from supertab_connect.analytics.ip import normalize_client_ip
from supertab_connect.analytics.types import (
    SCHEMA_VERSION,
    AnalyticsEvent,
    CdnRequestSignals,
    Decision,
    EnforcementWire,
    SourceCdn,
)
from supertab_connect.types import EnforcementMode

# Defensive cap on client-controlled free-form strings, applied at the edge (mirrored by the relay).
MAX_FIELD_LENGTH = 512

# Edge-injected headers are CDN artifacts, not client signals — strip them so ``header_names``
# reflects only what the client actually sent. Covers all three CDNs: Cloudflare (``cf-*``),
# Fastly (``fastly-*``), CloudFront (``cloudfront-*``), the shared ``x-forwarded-*`` / ``x-real-ip``,
# and the SDK's own routing header ``x-original-request-url``.
_EDGE_HEADER_PREFIXES = ("cf-", "fastly-", "cloudfront-", "x-forwarded-")
# ``host`` is included here because httpx synthesizes a Host header on Request construction; the JS
# fetch ``Request`` hides it as a forbidden header, so the TS SDK never emits it in ``header_names``.
# Stripping it keeps the cross-SDK header-name set consistent (host is captured in its own field).
# ``cdn-loop``/``x-varnish``/``via``/``surrogate-key``/``surrogate-control`` are portable proxy/CDN
# service-chain artifacts (esp. Fastly hops) — not client-sent, so they would pollute ``header_names``.
# Deployment-specific injected headers (e.g. x-geoip-*, x-ua-device) must be stripped at the edge
# instead; a portable SDK can't enumerate them. Mirrors the TS SDK's ``EDGE_HEADER_NAMES``.
_EDGE_HEADER_NAMES = frozenset(
    {
        "x-real-ip",
        "x-original-request-url",
        "host",
        "cdn-loop",
        "x-varnish",
        "via",
        "surrogate-key",
        "surrogate-control",
    }
)

# Mechanical exploit markers for the query-string heuristic, matched case-insensitively against the
# raw and URL-decoded query. A coarse signal only — real classification stays query-time in the
# warehouse.
_SUSPICIOUS_QUERY_MARKERS = (
    "../",
    "..\\",
    "union select",
    "<script",
    "onerror=",
    "/etc/passwd",
)


@dataclass(frozen=True)
class BuildAnalyticsEventContext:
    # Omitted (None) when the request did not pass through a CDN (e.g. invoked directly via the SDK).
    source_cdn: SourceCdn | None = None
    request_id: str | None = None
    client_ip: str | None = None
    timestamp: datetime | None = None
    request_country: str | None = None
    request_asn: int | None = None
    tls_fingerprint: str | None = None
    # CDN plumbing not derivable from the portable Request (request.cf, etc.).
    cdn_signals: CdnRequestSignals | None = None


def _iso_utc(value: datetime) -> str:
    """Format as ``YYYY-MM-DDTHH:MM:SS.mmmZ`` to match the TS `Date.toISOString()` wire form."""
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_pathname(request: Request) -> str:
    """Return the request path with percent-encoding preserved.

    ``request.url.path`` percent-*decodes* (``/a%2Fb`` → ``/a/b``), which loses encoded path
    semantics. We read ``raw_path`` (``path[?query]`` bytes), drop the query, and decode without
    URL-decoding — matching the TS SDK's ``new URL(request.url).pathname``.
    """
    path_bytes = request.url.raw_path.split(b"?", 1)[0]
    return path_bytes.decode("utf-8", "replace")


def _enforcement_to_wire(mode: EnforcementMode) -> EnforcementWire:
    # EnforcementMode values are already the wire strings ("observe"/"enforce"/"disabled").
    return mode.value  # type: ignore[return-value]


def _truncate(value: str | None, max_length: int = MAX_FIELD_LENGTH) -> str | None:
    if value is None:
        return None
    return value[:max_length] if len(value) > max_length else value


def _is_edge_header(name: str) -> bool:
    if name in _EDGE_HEADER_NAMES:
        return True
    return any(name.startswith(prefix) for prefix in _EDGE_HEADER_PREFIXES)


def _collect_header_names(request: Request) -> list[str]:
    names = {name.lower() for name in request.headers.keys()}
    return sorted(name for name in names if not _is_edge_header(name))


def _query_signals(request: Request) -> tuple[int, int, bool]:
    # request.url.query is the raw, percent-encoded query bytes (no leading "?"), matching the
    # TS SDK's ``url.search.slice(1)``. The raw query itself is never stored on the event.
    raw = request.url.query.decode("utf-8", "replace")
    params = [p for p in raw.split("&") if p] if raw else []

    haystack = raw.lower() + "\n" + unquote(raw).lower()
    suspicious = any(marker in haystack for marker in _SUSPICIOUS_QUERY_MARKERS)

    return len(raw), len(params), suspicious


def build_analytics_event(
    request: Request,
    decision: Decision,
    context: BuildAnalyticsEventContext,
) -> AnalyticsEvent:
    headers = request.headers
    timestamp = context.timestamp if context.timestamp is not None else datetime.now(timezone.utc)
    request_id = context.request_id if context.request_id is not None else str(uuid.uuid4())
    query_length, query_param_count, query_suspicious = _query_signals(request)
    cdn = context.cdn_signals if context.cdn_signals is not None else CdnRequestSignals()

    return AnalyticsEvent(
        timestamp=_iso_utc(timestamp),
        request_id=request_id,
        schema_version=SCHEMA_VERSION,
        source_cdn=context.source_cdn,
        user_agent=headers.get("user-agent", ""),
        client_ip=normalize_client_ip(context.client_ip),
        path=_safe_pathname(request),
        method=request.method,
        referer=headers.get("referer", ""),
        accept_language=headers.get("accept-language", ""),
        request_country=context.request_country,
        request_asn=context.request_asn,
        tls_fingerprint=context.tls_fingerprint,
        has_token=decision.has_token,
        token_outcome=decision.token_outcome,
        final_action=decision.final_action,
        enforcement_mode=_enforcement_to_wire(decision.enforcement_mode),
        signature_agent=headers.get("signature-agent"),
        signature_input=headers.get("signature-input"),
        signature=headers.get("signature"),
        # --- Capture v2: portable header signals ---
        sec_fetch_mode=headers.get("sec-fetch-mode"),
        sec_fetch_site=headers.get("sec-fetch-site"),
        sec_fetch_dest=headers.get("sec-fetch-dest"),
        sec_fetch_user=headers.get("sec-fetch-user"),
        sec_ch_ua=_truncate(headers.get("sec-ch-ua")),
        sec_ch_ua_mobile=headers.get("sec-ch-ua-mobile"),
        sec_ch_ua_platform=headers.get("sec-ch-ua-platform"),
        accept=_truncate(headers.get("accept")),
        # httpx synthesizes the Host header from the URL, so this is effectively the parsed host.
        host=headers.get("host") or request.url.host or None,
        has_cookies="cookie" in headers,
        header_names=_collect_header_names(request),
        # Query-string derived signals (raw query never stored).
        query_length=query_length,
        query_param_count=query_param_count,
        query_suspicious=query_suspicious,
        # --- Capture v2: CDN plumbing (passthrough from the handler context) ---
        accept_encoding=cdn.accept_encoding,
        http_protocol=cdn.http_protocol,
        tls_version=cdn.tls_version,
        tls_cipher=cdn.tls_cipher,
        tls_client_hello_length=cdn.tls_client_hello_length,
        tls_client_extensions_sha1=cdn.tls_client_extensions_sha1,
        as_organization=_truncate(cdn.as_organization),
        client_tcp_rtt=cdn.client_tcp_rtt,
        cdn_verified_bot_category=cdn.cdn_verified_bot_category,
        request_priority=cdn.request_priority,
        tls_fingerprint_ja4=cdn.tls_fingerprint_ja4,
    )
