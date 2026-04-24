"""Supertab Connect SDK."""

from connect.customer.token import obtain_license_token
from connect.exceptions import SupertabConnectError
from connect.merchant.jwks import clear_jwks_cache, fetch_platform_jwks
from connect.merchant.license import (
    build_block_result,
    build_signal_result,
    generate_license_link,
    verify_license_token,
)
from connect.url_pattern import score_path_pattern
from connect.types import (
    AllowHandlerResult,
    BlockHandlerResult,
    BotDetector,
    EnforcementMode,
    HandlerAction,
    HandlerResult,
    InvalidLicenseToken,
    LicenseTokenInvalidReason,
    LicenseTokenVerificationResult,
    RSLVerificationResult,
    SupertabConnectConfig,
    ValidLicenseToken,
)

__all__ = [
    "AllowHandlerResult",
    "BlockHandlerResult",
    "BotDetector",
    "EnforcementMode",
    "HandlerAction",
    "HandlerResult",
    "InvalidLicenseToken",
    "LicenseTokenInvalidReason",
    "LicenseTokenVerificationResult",
    "RSLVerificationResult",
    "SupertabConnectError",
    "SupertabConnectConfig",
    "ValidLicenseToken",
    "build_block_result",
    "build_signal_result",
    "clear_jwks_cache",
    "fetch_platform_jwks",
    "generate_license_link",
    "obtain_license_token",
    "score_path_pattern",
    "verify_license_token",
]
