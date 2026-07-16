"""Relay analytics for Supertab Connect (mirrors the TS SDK `analytics/` module)."""

from supertab_connect.analytics.build_analytics_event import (
    BuildAnalyticsEventContext,
    build_analytics_event,
)
from supertab_connect.analytics.ip import normalize_client_ip
from supertab_connect.analytics.transport import (
    ANALYTICS_EVENTS_PATH,
    HttpAnalyticsTransport,
    NoopAnalyticsTransport,
)
from supertab_connect.analytics.types import (
    SCHEMA_VERSION,
    TOKEN_OUTCOME_BY_REASON,
    AnalyticsEvent,
    AnalyticsTransport,
    CdnRequestSignals,
    Decision,
    FinalAction,
    SourceCdn,
    TokenOutcome,
)

__all__ = [
    "ANALYTICS_EVENTS_PATH",
    "SCHEMA_VERSION",
    "TOKEN_OUTCOME_BY_REASON",
    "AnalyticsEvent",
    "AnalyticsTransport",
    "BuildAnalyticsEventContext",
    "CdnRequestSignals",
    "Decision",
    "FinalAction",
    "HttpAnalyticsTransport",
    "NoopAnalyticsTransport",
    "SourceCdn",
    "TokenOutcome",
    "build_analytics_event",
    "normalize_client_ip",
]
