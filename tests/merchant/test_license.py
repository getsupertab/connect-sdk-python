"""Tests for license token verification and result builders."""

from datetime import timedelta

import respx

from connect.merchant.license import (
    build_block_result,
    build_signal_result,
    verify_license_token,
)
from connect.types import HandlerAction, InvalidLicenseToken, LicenseTokenInvalidReason, ValidLicenseToken

from tests.merchant.constants import JWKS_URL, REQUEST_URL, SUPERTAB_BASE_URL

EVENTS_URL = f"{SUPERTAB_BASE_URL}/events"


async def test_verify_valid_token(make_token, jwks_response):
    """Valid token returns ValidLicenseToken with correct payload."""
    token = make_token()

    with respx.mock:
        respx.get(JWKS_URL).respond(json=jwks_response)
        result = await verify_license_token(token, request_url=REQUEST_URL, supertab_base_url=SUPERTAB_BASE_URL)

    assert isinstance(result, ValidLicenseToken)
    assert result.valid is True
    assert result.license_id == "lic_test_123"
    assert result.payload["iss"] == SUPERTAB_BASE_URL


async def test_verify_missing_token(mock_jwks):
    """Empty token string returns MISSING_TOKEN reason."""
    result = await verify_license_token("", request_url=REQUEST_URL, supertab_base_url=SUPERTAB_BASE_URL)

    assert isinstance(result, InvalidLicenseToken)
    assert result.reason is LicenseTokenInvalidReason.MISSING_TOKEN


async def test_verify_expired_token(make_token, jwks_response):
    """Expired token returns EXPIRED reason with the license_id."""
    token = make_token(exp_delta=timedelta(seconds=-60))

    with respx.mock:
        respx.get(JWKS_URL).respond(json=jwks_response)
        result = await verify_license_token(token, request_url=REQUEST_URL, supertab_base_url=SUPERTAB_BASE_URL)

    assert isinstance(result, InvalidLicenseToken)
    assert result.reason is LicenseTokenInvalidReason.EXPIRED
    assert result.license_id == "lic_test_123"


async def test_verify_invalid_issuer(make_token, mock_jwks):
    """Token with wrong issuer returns INVALID_ISSUER reason."""
    token = make_token(issuer="https://evil.example.com")

    result = await verify_license_token(token, request_url=REQUEST_URL, supertab_base_url=SUPERTAB_BASE_URL)

    assert isinstance(result, InvalidLicenseToken)
    assert result.reason is LicenseTokenInvalidReason.INVALID_ISSUER


async def test_verify_invalid_audience(make_token, mock_jwks):
    """Token with non-matching audience returns INVALID_AUDIENCE reason."""
    token = make_token(audience="https://other-site.com/page")

    result = await verify_license_token(token, request_url=REQUEST_URL, supertab_base_url=SUPERTAB_BASE_URL)

    assert isinstance(result, InvalidLicenseToken)
    assert result.reason is LicenseTokenInvalidReason.INVALID_AUDIENCE


async def test_verify_invalid_algorithm(mock_jwks):
    """RS256-signed token is rejected as unsupported algorithm."""
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    token = pyjwt.encode(
        {"iss": SUPERTAB_BASE_URL, "aud": REQUEST_URL},
        pem,
        algorithm="RS256",
        headers={"kid": "test-kid-1"},
    )

    result = await verify_license_token(token, request_url=REQUEST_URL, supertab_base_url=SUPERTAB_BASE_URL)

    assert isinstance(result, InvalidLicenseToken)
    assert result.reason is LicenseTokenInvalidReason.INVALID_ALG


async def test_verify_invalid_header(mock_jwks):
    """Malformed JWT string returns INVALID_HEADER reason."""
    result = await verify_license_token("not-a-jwt", request_url=REQUEST_URL, supertab_base_url=SUPERTAB_BASE_URL)

    assert isinstance(result, InvalidLicenseToken)
    assert result.reason is LicenseTokenInvalidReason.INVALID_HEADER


async def test_verify_jwks_key_not_found_triggers_retry(make_token, jwks_response):
    """When the cached JWKS doesn't have the kid, the cache is cleared and a refetch is attempted."""
    token = make_token()
    empty_jwks = {"keys": []}

    with respx.mock:
        route = respx.get(JWKS_URL).mock(
            side_effect=[
                respx.MockResponse(json=empty_jwks),
                respx.MockResponse(json=jwks_response),
            ]
        )
        result = await verify_license_token(token, request_url=REQUEST_URL, supertab_base_url=SUPERTAB_BASE_URL)

    assert isinstance(result, ValidLicenseToken)
    assert route.call_count == 2


async def test_verify_jwks_key_not_found_after_retry_returns_invalid(make_token):
    """When the kid is missing even after a JWKS cache refresh, return an InvalidLicenseToken."""
    token = make_token()
    empty_jwks = {"keys": []}

    with respx.mock:
        respx.get(JWKS_URL).respond(json=empty_jwks)
        result = await verify_license_token(token, request_url=REQUEST_URL, supertab_base_url=SUPERTAB_BASE_URL)

    assert isinstance(result, InvalidLicenseToken)
    assert result.reason is LicenseTokenInvalidReason.SIGNATURE_VERIFICATION_FAILED


async def test_verify_jwks_fetch_failure(make_token):
    """JWKS endpoint returning 500 results in SERVER_ERROR reason."""
    token = make_token()

    with respx.mock:
        respx.get(JWKS_URL).respond(status_code=500)
        result = await verify_license_token(token, request_url=REQUEST_URL, supertab_base_url=SUPERTAB_BASE_URL)

    assert isinstance(result, InvalidLicenseToken)
    assert result.reason is LicenseTokenInvalidReason.SERVER_ERROR


async def test_verify_audience_prefix_match(make_token, jwks_response):
    """Audience matching allows deeper paths under the audience base URL."""
    token = make_token(audience="https://example.com/premium")

    with respx.mock:
        respx.get(JWKS_URL).respond(json=jwks_response)
        result = await verify_license_token(
            token, request_url="https://example.com/premium/article/123", supertab_base_url=SUPERTAB_BASE_URL
        )

    assert isinstance(result, ValidLicenseToken)


async def test_verify_audience_rejects_partial_path_match(make_token, mock_jwks):
    """Audience '/premium' must not match '/premium-evil' — only path boundaries count."""
    token = make_token(audience="https://example.com/premium")

    result = await verify_license_token(
        token, request_url="https://example.com/premium-evil", supertab_base_url=SUPERTAB_BASE_URL
    )

    assert isinstance(result, InvalidLicenseToken)
    assert result.reason is LicenseTokenInvalidReason.INVALID_AUDIENCE


def test_build_block_result_missing_token():
    """Block result for missing token returns 401 with invalid_request."""
    result = build_block_result(
        reason=LicenseTokenInvalidReason.MISSING_TOKEN,
        error="Authorization header missing or malformed",
        request_url=REQUEST_URL,
    )

    assert result["action"] is HandlerAction.BLOCK
    assert result["status"] == 401
    assert "invalid_request" in result["headers"]["WWW-Authenticate"]
    assert "license.xml" in result["headers"]["Link"]


def test_build_block_result_invalid_audience():
    """Block result for invalid audience returns 403 with insufficient_scope."""
    result = build_block_result(
        reason=LicenseTokenInvalidReason.INVALID_AUDIENCE,
        error="The license does not grant access to this resource",
        request_url=REQUEST_URL,
    )

    assert result["status"] == 403
    assert "insufficient_scope" in result["headers"]["WWW-Authenticate"]


def test_build_block_result_server_error():
    """Block result for server error returns 503."""
    result = build_block_result(
        reason=LicenseTokenInvalidReason.SERVER_ERROR,
        error="The server encountered an error validating the license",
        request_url=REQUEST_URL,
    )

    assert result["status"] == 503
    assert "server_error" in result["headers"]["WWW-Authenticate"]


def test_build_signal_result():
    """Signal result returns ALLOW action with license link headers."""
    result = build_signal_result(REQUEST_URL)

    assert result["action"] is HandlerAction.ALLOW
    assert "license.xml" in result["headers"]["Link"]
    assert result["headers"]["X-RSL-Status"] == "token_required"
    assert result["headers"]["X-RSL-Reason"] == "missing"


def test_build_block_result_sanitizes_header_value():
    """Block result strips CRLF and escapes quotes in header values."""
    result = build_block_result(
        reason=LicenseTokenInvalidReason.EXPIRED,
        error='Evil "header\r\ninjection',
        request_url=REQUEST_URL,
    )

    www_auth = result["headers"]["WWW-Authenticate"]
    assert "\r" not in www_auth
    assert "\n" not in www_auth
    assert '\\"' in www_auth
