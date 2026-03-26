"""Customer-side token helpers for Supertab Connect."""

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from connect.common import debug_log, error_log
from connect.exceptions import SupertabConnectError
from connect.customer.content_matcher import _find_best_matching_content
from connect.customer.content_parser import _parse_content_elements

_SUPPORTED_ALGS = ("ES256", "RS256")
_LICENSE_TOKEN_CACHE: dict[tuple[str, str], "_CachedToken"] = {}


@dataclass(frozen=True)
class _CachedToken:
    token: str
    exp: int


def _build_origin(resource_url: str) -> str:
    parsed = urllib.parse.urlparse(resource_url)
    if not parsed.scheme or not parsed.netloc:
        raise SupertabConnectError(f"Invalid resource URL: {resource_url}")
    return f"{parsed.scheme}://{parsed.netloc}"


def _get_cached_token(cache_key: tuple[str, str], debug: bool = False) -> str | None:
    cached = _LICENSE_TOKEN_CACHE.get(cache_key)
    if cached is None:
        return None

    now = int(time.time())
    if cached.exp > now + 30:
        debug_log(
            debug,
            f"Using cached license token (expires in {cached.exp - now}s)",
        )
        return cached.token

    debug_log(debug, "Cached license token expired or expiring soon, refreshing")
    _LICENSE_TOKEN_CACHE.pop(cache_key, None)
    return None


def _read_json_response(response: Any, debug: bool) -> dict[str, Any]:
    try:
        return json.loads(response.read().decode("utf-8"))
    except json.JSONDecodeError as error:
        error_log(debug, f"Failed to parse license token response as JSON: {error}")
        raise SupertabConnectError("Failed to parse license token response as JSON") from error


def _retrieve_license_token(
    request: urllib.request.Request,
    debug: bool = False,
) -> str:
    try:
        with urllib.request.urlopen(request) as response:
            payload = _read_json_response(response, debug)
    except urllib.error.HTTPError as error:
        error_body = error.read().decode("utf-8", errors="replace")
        suffix = f" - {error_body}" if error_body else ""
        message = (
            f"Failed to obtain license token: {error.code} {error.reason}{suffix}"
        )
        error_log(debug, f"Error generating license token: {message}")
        raise SupertabConnectError(message) from error
    except urllib.error.URLError as error:
        message = f"Failed to obtain license token: {error.reason}"
        error_log(debug, f"Error generating license token: {message}")
        raise SupertabConnectError(message) from error

    access_token = payload.get("access_token")
    if not access_token:
        raise SupertabConnectError("License token response missing access_token")

    return access_token


def _select_signing_key(
    private_key_pem: str,
    debug: bool = False,
) -> tuple[Any, str]:
    try:
        key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except (TypeError, ValueError) as error:
        error_log(debug, f"Failed to load private key: {error}")
        raise SupertabConnectError(
            "Unsupported private key format. Expected RSA or P-256 EC private key."
        ) from error

    if isinstance(key, ec.EllipticCurvePrivateKey):
        if isinstance(key.curve, ec.SECP256R1):
            return key, "ES256"
        raise SupertabConnectError(
            "Unsupported private key format. Expected RSA or P-256 EC private key."
        )

    if isinstance(key, rsa.RSAPrivateKey):
        return key, "RS256"

    debug_log(
        debug,
        f"Unsupported private key type {type(key).__name__}; expected RSA or P-256 EC private key.",
    )

    raise SupertabConnectError(
        "Unsupported private key format. Expected RSA or P-256 EC private key."
    )


def _generate_license_token(
    *,
    client_id: str,
    kid: str,
    private_key_pem: str,
    token_endpoint: str,
    resource_url: str,
    license_xml: str,
    debug: bool = False,
) -> str:
    """Generate a license token using the deprecated client assertion flow.

    This matches the older JWT client assertion flow where the caller signs a
    client assertion with a private key and exchanges it for a license token.
    This flow is currently deprecated and retained only for feature parity with
    the TypeScript SDK internals.
    """
    key, algorithm = _select_signing_key(private_key_pem, debug)
    now = int(time.time())

    client_assertion = jwt.encode(
        {
            "iss": client_id,
            "sub": client_id,
            "iat": now,
            "exp": now + 300,
            "aud": token_endpoint,
        },
        key,
        algorithm=algorithm,
        headers={"alg": algorithm, "kid": kid},
    )

    body = urllib.parse.urlencode(
        {
            "grant_type": "rsl",
            "client_assertion_type": (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            ),
            "client_assertion": client_assertion,
            "license": license_xml,
            "resource": resource_url,
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        token_endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )

    return _retrieve_license_token(request, debug)


def _fetch_license_xml(resource_url: str, debug: bool = False) -> str:
    license_xml_url = f"{_build_origin(resource_url)}/license.xml"
    request = urllib.request.Request(license_xml_url, method="GET")

    try:
        with urllib.request.urlopen(request) as response:
            xml = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        error_log(
            debug,
            f"Failed to fetch license.xml from {license_xml_url}: {error.code}",
        )
        raise SupertabConnectError(
            f"Failed to fetch license.xml from {license_xml_url}: {error.code}"
        ) from error
    except urllib.error.URLError as error:
        message = f"Failed to fetch license.xml from {license_xml_url}: {error.reason}"
        error_log(debug, message)
        raise SupertabConnectError(message) from error

    debug_log(debug, f"Fetched license.xml from {license_xml_url}")
    return xml


def obtain_license_token(
    *,
    client_id: str,
    client_secret: str,
    resource_url: str,
    debug: bool = False,
) -> str:
    """Obtain a license token using the current client credentials flow.

    This is the supported customer flow. The SDK fetches ``license.xml`` for
    the requested resource, finds the best matching ``<content>`` block, and
    exchanges the client credentials for a license token.
    """
    cache_key = (client_id, resource_url)
    cached = _get_cached_token(cache_key, debug)
    if cached is not None:
        return cached

    xml = _fetch_license_xml(resource_url, debug)
    debug_log(debug, f"Fetched license.xml ({len(xml)} chars)")
    content_blocks = _parse_content_elements(xml, debug)

    if not content_blocks:
        error_log(debug, "No valid <content> elements with <license> found in license.xml")
        raise SupertabConnectError(
            "No valid <content> elements with <license> found in license.xml"
        )

    matched_content = _find_best_matching_content(content_blocks, resource_url, debug)
    if matched_content is None:
        patterns = ", ".join(block.url_pattern for block in content_blocks)
        error_log(
            debug,
            f"No <content> element matches resource URL: {resource_url}. Available patterns: {patterns}",
        )
        raise SupertabConnectError(
            f"No <content> element in license.xml matches resource URL: {resource_url}"
        )

    token_endpoint = matched_content.server.rstrip("/") + "/token"
    debug_log(debug, f"Requesting license token from {token_endpoint}")

    auth = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "license": matched_content.license_xml,
            "resource": matched_content.url_pattern,
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        token_endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Authorization": f"Basic {auth}",
        },
    )

    token = _retrieve_license_token(request, debug)

    try:
        claims = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False,
                "verify_iss": False,
            },
            algorithms=["HS256", "RS256", "ES256", "PS256"],
        )
        exp = claims.get("exp")
        if isinstance(exp, int):
            _LICENSE_TOKEN_CACHE[cache_key] = _CachedToken(token=token, exp=exp)
    except (jwt.PyJWTError, ValueError, TypeError) as error:
        debug_log(debug, f"Failed to decode token for caching, skipping cache: {error}")

    return token


__all__ = ["obtain_license_token"]
