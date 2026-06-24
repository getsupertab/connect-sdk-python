"""Build a relay AnalyticsEvent from a request + decision (mirrors TS `buildAnalyticsEvent.ts`)."""

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from httpx import Request

from supertab_connect.analytics.ip import normalize_client_ip
from supertab_connect.analytics.types import (
    SCHEMA_VERSION,
    AnalyticsEvent,
    Decision,
    EnforcementWire,
    SourceCdn,
)
from supertab_connect.types import EnforcementMode


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


def build_analytics_event(
    request: Request,
    decision: Decision,
    context: BuildAnalyticsEventContext,
) -> AnalyticsEvent:
    headers = request.headers
    timestamp = context.timestamp if context.timestamp is not None else datetime.now(timezone.utc)
    request_id = context.request_id if context.request_id is not None else str(uuid.uuid4())

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
    )
