"""License token verification for the Supertab Connect SDK."""

import re
from typing import Any
from urllib.parse import urlparse

import jwt

from connect.common import debug_log, error_log
from connect.exceptions import JwksKeyNotFoundError
from connect.merchant.jwks import clear_jwks_cache, fetch_platform_jwks, find_key_by_kid
from connect.types import (
    HandlerAction,
    InvalidLicenseToken,
    LicenseTokenInvalidReason,
    LicenseTokenVerificationResult,
    ValidLicenseToken,
)


def _strip_trailing_slash(value: str) -> str:
    return re.sub(r"/+$", "", value.strip())


def _audience_matches(request_url: str, audience: str) -> bool:
    """Check if the request URL matches an audience value.

    The audience must be an exact match or a path prefix boundary (followed by '/').
    This prevents '/premium' from matching '/premium-evil'.
    """
    normalized_aud = _strip_trailing_slash(audience)
    if request_url == normalized_aud:
        return True
    return request_url.startswith(normalized_aud + "/")


def _generate_license_link(request_url: str) -> str:
    try:
        parsed = urlparse(request_url)
        if not parsed.scheme or not parsed.netloc:
            return "/license.xml"
        return f"{parsed.scheme}://{parsed.netloc}/license.xml"
    except Exception:
        return "/license.xml"


def _reason_to_error_description(reason: LicenseTokenInvalidReason) -> str:
    descriptions: dict[LicenseTokenInvalidReason, str] = {
        LicenseTokenInvalidReason.MISSING_TOKEN: "Authorization header missing or malformed",
        LicenseTokenInvalidReason.INVALID_ALG: "Unsupported token algorithm",
        LicenseTokenInvalidReason.EXPIRED: "The license token has expired",
        LicenseTokenInvalidReason.SIGNATURE_VERIFICATION_FAILED: "The license token signature is invalid",
        LicenseTokenInvalidReason.INVALID_HEADER: "The license token header is malformed",
        LicenseTokenInvalidReason.INVALID_PAYLOAD: "The license token payload is malformed",
        LicenseTokenInvalidReason.INVALID_ISSUER: "The license token issuer is not recognized",
        LicenseTokenInvalidReason.INVALID_AUDIENCE: "The license does not grant access to this resource",
        LicenseTokenInvalidReason.SERVER_ERROR: "The server encountered an error validating the license",
    }
    return descriptions.get(reason, "License token missing, expired, revoked, or malformed")


def _reason_to_rsl_error(reason: LicenseTokenInvalidReason | str) -> tuple[str, int]:
    """Map a reason to its RSL error string and HTTP status code."""
    mapping: dict[str, tuple[str, int]] = {
        LicenseTokenInvalidReason.MISSING_TOKEN: ("invalid_request", 401),
        LicenseTokenInvalidReason.INVALID_ALG: ("invalid_request", 401),
        LicenseTokenInvalidReason.EXPIRED: ("invalid_token", 401),
        LicenseTokenInvalidReason.SIGNATURE_VERIFICATION_FAILED: ("invalid_token", 401),
        LicenseTokenInvalidReason.INVALID_HEADER: ("invalid_token", 401),
        LicenseTokenInvalidReason.INVALID_PAYLOAD: ("invalid_token", 401),
        LicenseTokenInvalidReason.INVALID_ISSUER: ("invalid_token", 401),
        LicenseTokenInvalidReason.INVALID_AUDIENCE: ("insufficient_scope", 403),
        LicenseTokenInvalidReason.SERVER_ERROR: ("server_error", 503),
    }
    return mapping.get(str(reason), ("invalid_token", 401))


def _sanitize_header_value(value: str) -> str:
    """Sanitize a string for safe use in an HTTP header quoted-string (RFC 7230)."""
    return value.replace("\r", "").replace("\n", "").replace("\\", "\\\\").replace('"', '\\"')


async def verify_license_token(
    license_token: str,
    *,
    request_url: str,
    supertab_base_url: str,
    debug: bool = False,
) -> LicenseTokenVerificationResult:
    """Verify a Supertab license token JWT.

    Decodes and validates the token header, payload, issuer, audience,
    and cryptographic signature against the platform JWKS.
    """
    if not license_token:
        return InvalidLicenseToken(
            reason=LicenseTokenInvalidReason.MISSING_TOKEN,
            error=_reason_to_error_description(LicenseTokenInvalidReason.MISSING_TOKEN),
        )

    # Decode header
    try:
        header = jwt.get_unverified_header(license_token)
    except jwt.exceptions.DecodeError:
        debug_log(debug, "Invalid license JWT header")
        return InvalidLicenseToken(
            reason=LicenseTokenInvalidReason.INVALID_HEADER,
            error=_reason_to_error_description(LicenseTokenInvalidReason.INVALID_HEADER),
        )

    if header.get("alg") != "ES256":
        debug_log(debug, f"Unsupported license JWT alg: {header.get('alg')}")
        return InvalidLicenseToken(
            reason=LicenseTokenInvalidReason.INVALID_ALG,
            error=_reason_to_error_description(LicenseTokenInvalidReason.INVALID_ALG),
        )

    # Decode payload without verification
    try:
        unverified_payload = jwt.decode(
            license_token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
            },
            algorithms=["ES256"],
        )
    except jwt.exceptions.DecodeError:
        debug_log(debug, "Invalid license JWT payload")
        return InvalidLicenseToken(
            reason=LicenseTokenInvalidReason.INVALID_PAYLOAD,
            error=_reason_to_error_description(LicenseTokenInvalidReason.INVALID_PAYLOAD),
        )

    license_id: str | None = unverified_payload.get("license_id")

    # Validate issuer
    issuer = unverified_payload.get("iss", "")
    normalized_issuer = _strip_trailing_slash(issuer) if issuer else ""
    normalized_base_url = _strip_trailing_slash(supertab_base_url)

    if not normalized_issuer or not normalized_issuer.startswith(normalized_base_url):
        debug_log(debug, f"License JWT issuer is missing or malformed: {issuer}")
        return InvalidLicenseToken(
            reason=LicenseTokenInvalidReason.INVALID_ISSUER,
            error=_reason_to_error_description(LicenseTokenInvalidReason.INVALID_ISSUER),
            license_id=license_id,
        )

    # Validate audience
    aud = unverified_payload.get("aud", [])
    audience_values: list[str] = [a for a in (aud if isinstance(aud, list) else [aud]) if isinstance(a, str) and a]

    request_url_normalized = _strip_trailing_slash(request_url)
    matches_request_url = any(_audience_matches(request_url_normalized, a) for a in audience_values)

    if not matches_request_url:
        debug_log(debug, f"License JWT audience does not match request URL: {aud}")
        return InvalidLicenseToken(
            reason=LicenseTokenInvalidReason.INVALID_AUDIENCE,
            error=_reason_to_error_description(LicenseTokenInvalidReason.INVALID_AUDIENCE),
            license_id=license_id,
        )

    # Verify signature
    async def _verify() -> LicenseTokenVerificationResult:
        try:
            jwks = await fetch_platform_jwks(supertab_base_url, debug=debug)
        except Exception:
            error_log(debug, "Failed to fetch platform JWKS")
            return InvalidLicenseToken(
                reason=LicenseTokenInvalidReason.SERVER_ERROR,
                error=_reason_to_error_description(LicenseTokenInvalidReason.SERVER_ERROR),
                license_id=license_id,
            )

        try:
            jwk_key = find_key_by_kid(jwks, header.get("kid"))
            public_key = jwt.algorithms.ECAlgorithm.from_jwk(jwk_key)
            verified_payload = jwt.decode(
                license_token,
                key=public_key,
                algorithms=["ES256"],
                issuer=issuer,
                leeway=60,
                options={"verify_aud": False},
            )
            return ValidLicenseToken(license_id=license_id, payload=verified_payload)
        except JwksKeyNotFoundError:
            raise
        except jwt.exceptions.ExpiredSignatureError:
            debug_log(debug, "License JWT has expired")
            return InvalidLicenseToken(
                reason=LicenseTokenInvalidReason.EXPIRED,
                error=_reason_to_error_description(LicenseTokenInvalidReason.EXPIRED),
                license_id=license_id,
            )
        except Exception:
            debug_log(debug, "License JWT verification failed")
            return InvalidLicenseToken(
                reason=LicenseTokenInvalidReason.SIGNATURE_VERIFICATION_FAILED,
                error=_reason_to_error_description(LicenseTokenInvalidReason.SIGNATURE_VERIFICATION_FAILED),
                license_id=license_id,
            )

    try:
        return await _verify()
    except JwksKeyNotFoundError:
        debug_log(debug, "Key not found in cached JWKS, clearing cache and retrying...")
        clear_jwks_cache()
        try:
            return await _verify()
        except JwksKeyNotFoundError:
            debug_log(debug, "Key not found after JWKS cache refresh")
            return InvalidLicenseToken(
                reason=LicenseTokenInvalidReason.SIGNATURE_VERIFICATION_FAILED,
                error=_reason_to_error_description(LicenseTokenInvalidReason.SIGNATURE_VERIFICATION_FAILED),
                license_id=license_id,
            )


def build_block_result(
    *,
    reason: LicenseTokenInvalidReason | str,
    error: str,
    request_url: str,
) -> dict[str, Any]:
    """Build a block response with appropriate status code and headers."""
    rsl_error, status = _reason_to_rsl_error(reason)
    error_description = _sanitize_header_value(error)
    license_link = _generate_license_link(request_url)

    return {
        "action": HandlerAction.BLOCK,
        "status": status,
        "body": f"Access to this resource requires a valid license token. Error: {rsl_error} - {error}",
        "headers": {
            "Content-Type": "text/plain; charset=UTF-8",
            "WWW-Authenticate": f'License error="{rsl_error}", error_description="{error_description}"',
            "Link": f'<{license_link}>; rel="license"; type="application/rsl+xml"',
        },
    }


def build_signal_result(request_url: str) -> dict[str, Any]:
    """Build a soft enforcement signal response with license link headers."""
    license_link = _generate_license_link(request_url)
    return {
        "action": HandlerAction.ALLOW,
        "headers": {
            "Link": f'<{license_link}>; rel="license"; type="application/rsl+xml"',
            "X-RSL-Status": "token_required",
            "X-RSL-Reason": "missing",
        },
    }
