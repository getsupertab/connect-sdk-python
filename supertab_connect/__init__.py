"""Supertab Connect SDK."""

from supertab_connect.analytics.types import (
    AnalyticsEvent,
    AnalyticsTransport,
    CdnRequestSignals,
)
from supertab_connect.customer.token import obtain_license_token
from supertab_connect.exceptions import SupertabConnectError
from supertab_connect.merchant.bots import default_bot_detector
from supertab_connect.merchant.client import SupertabConnect
from supertab_connect.merchant.license import verify_license_token
from supertab_connect.types import (
    EnforcementMode,
    HandleRequestContext,
    HandlerAction,
    HandlerResult,
    RSLVerificationResult,
    SupertabConnectConfig,
    UsageType,
)

__all__ = [
    "AnalyticsEvent",
    "AnalyticsTransport",
    "CdnRequestSignals",
    "EnforcementMode",
    "HandleRequestContext",
    "HandlerAction",
    "HandlerResult",
    "RSLVerificationResult",
    "SupertabConnect",
    "SupertabConnectError",
    "SupertabConnectConfig",
    "UsageType",
    "default_bot_detector",
    "obtain_license_token",
    "verify_license_token",
]
