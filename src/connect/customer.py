"""Customer-side helpers for obtaining and generating Supertab license tokens."""

from __future__ import annotations

import base64
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .exceptions import SupertabConnectError
from .url_pattern import _score_path_pattern

LOGGER = logging.getLogger(__name__)

_SUPPORTED_ALGS = ("ES256", "RS256")
_CONTENT_RE = re.compile(r"<content\s([^>]*)>([\s\S]*?)</content>", re.IGNORECASE)
_URL_RE = re.compile(r'url\s*=\s*"([^"]*)"', re.IGNORECASE)
_SERVER_RE = re.compile(r'server\s*=\s*"([^"]*)"', re.IGNORECASE)
_LICENSE_RE = re.compile(r"<license[^>]*>[\s\S]*?</license>", re.IGNORECASE)
_LICENSE_TOKEN_CACHE: dict[str, "_CachedToken"] = {}


@dataclass(frozen=True)
class _CachedToken:
    token: str
    exp: int


@dataclass(frozen=True)
class _ContentBlock:
    url_pattern: str
    license_xml: str
    server: str


def _debug_log(enabled: bool, message: str, *args: Any) -> None:
    if enabled:
        LOGGER.debug(message, *args)


def _error_log(enabled: bool, message: str, *args: Any) -> None:
    if enabled:
        LOGGER.error(message, *args)


def _build_origin(resource_url: str) -> str:
    parsed = urllib.parse.urlparse(resource_url)
    if not parsed.scheme or not parsed.netloc:
        raise SupertabConnectError(f"Invalid resource URL: {resource_url}")
    return f"{parsed.scheme}://{parsed.netloc}"


def _get_cached_token(cache_key: str, debug: bool = False) -> str | None:
    cached = _LICENSE_TOKEN_CACHE.get(cache_key)
    if cached is None:
        return None

    now = int(time.time())
    if cached.exp > now + 30:
        _debug_log(
            debug,
            "Using cached license token (expires in %ss)",
            cached.exp - now,
        )
        return cached.token

    _debug_log(debug, "Cached license token expired or expiring soon, refreshing")
    _LICENSE_TOKEN_CACHE.pop(cache_key, None)
    return None


def _read_json_response(response: Any, debug: bool) -> dict[str, Any]:
    try:
        return json.loads(response.read().decode("utf-8"))
    except json.JSONDecodeError as error:
        _error_log(debug, "Failed to parse license token response as JSON: %s", error)
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
        _error_log(debug, "Error generating license token: %s", message)
        raise SupertabConnectError(message) from error
    except urllib.error.URLError as error:
        message = f"Failed to obtain license token: {error.reason}"
        _error_log(debug, "Error generating license token: %s", message)
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
        _error_log(debug, "Failed to load private key: %s", error)
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

    for algorithm in _SUPPORTED_ALGS:
        _debug_log(debug, "Private key did not import using %s, retrying...", algorithm)

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
        _error_log(
            debug,
            "Failed to fetch license.xml from %s: %s",
            license_xml_url,
            error.code,
        )
        raise SupertabConnectError(
            f"Failed to fetch license.xml from {license_xml_url}: {error.code}"
        ) from error
    except urllib.error.URLError as error:
        message = f"Failed to fetch license.xml from {license_xml_url}: {error.reason}"
        _error_log(debug, "%s", message)
        raise SupertabConnectError(message) from error

    _debug_log(debug, "Fetched license.xml from %s", license_xml_url)
    return xml


def _parse_content_elements(xml: str, debug: bool = False) -> list[_ContentBlock]:
    content_blocks: list[_ContentBlock] = []
    element_count = 0

    for match in _CONTENT_RE.finditer(xml):
        element_count += 1
        attrs, body = match.groups()
        url_match = _URL_RE.search(attrs)
        server_match = _SERVER_RE.search(attrs)
        license_match = _LICENSE_RE.search(body)

        if url_match and server_match and license_match:
            content_blocks.append(
                _ContentBlock(
                    url_pattern=url_match.group(1),
                    server=server_match.group(1),
                    license_xml=license_match.group(0),
                )
            )
            continue

        missing = ", ".join(
            value
            for value in (
                None if url_match else "url",
                None if server_match else "server",
                None if license_match else "<license>",
            )
            if value is not None
        )
        _debug_log(
            debug,
            "Skipping <content> element #%s: missing %s",
            element_count,
            missing,
        )

    _debug_log(
        debug,
        "Found %s <content> element(s), %s valid",
        element_count,
        len(content_blocks),
    )
    return content_blocks


def _find_best_matching_content(
    content_blocks: list[_ContentBlock],
    resource_url: str,
    debug: bool = False,
) -> _ContentBlock | None:
    parsed = urllib.parse.urlparse(resource_url)
    host = parsed.netloc
    path = parsed.path
    if not parsed.scheme or not host:
        _debug_log(debug, "Cannot parse resource URL: %s", resource_url)
        return None

    _debug_log(debug, "Matching resource URL: %s (host=%s, path=%s)", resource_url, host, path)

    best_match: _ContentBlock | None = None
    best_specificity = -1

    for block in content_blocks:
        pattern = urllib.parse.urlparse(block.url_pattern)
        if not pattern.scheme or not pattern.netloc:
            _debug_log(debug, "Skipping block with invalid URL pattern: %s", block.url_pattern)
            continue

        if pattern.netloc != host:
            _debug_log(
                debug,
                "Skipping block: host mismatch (pattern=%s, resource=%s)",
                pattern.netloc,
                host,
            )
            continue

        if pattern.path == path:
            _debug_log(debug, "Exact match found: %s", block.url_pattern)
            return block

        specificity = _score_path_pattern(pattern.path or "/", path or "/")
        if specificity > best_specificity:
            best_specificity = specificity
            best_match = block

    if best_match is not None:
        _debug_log(
            debug,
            "Wildcard match found: %s (specificity=%s)",
            best_match.url_pattern,
            best_specificity,
        )
    else:
        _debug_log(debug, "No matching content block found for %s", resource_url)

    return best_match


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
    cache_key = f"{client_id}:{resource_url}"
    cached = _get_cached_token(cache_key, debug)
    if cached is not None:
        return cached

    xml = _fetch_license_xml(resource_url, debug)
    _debug_log(debug, "Fetched license.xml (%s chars)", len(xml))
    content_blocks = _parse_content_elements(xml, debug)

    if not content_blocks:
        _error_log(debug, "No valid <content> elements with <license> found in license.xml")
        raise SupertabConnectError(
            "No valid <content> elements with <license> found in license.xml"
        )

    matched_content = _find_best_matching_content(content_blocks, resource_url, debug)
    if matched_content is None:
        patterns = ", ".join(block.url_pattern for block in content_blocks)
        _error_log(
            debug,
            "No <content> element matches resource URL: %s. Available patterns: %s",
            resource_url,
            patterns,
        )
        raise SupertabConnectError(
            f"No <content> element in license.xml matches resource URL: {resource_url}"
        )

    token_endpoint = matched_content.server.rstrip("/") + "/token"
    _debug_log(debug, "Requesting license token from %s", token_endpoint)

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
    except Exception:
        _debug_log(debug, "Failed to decode token for caching, skipping cache")

    return token


__all__ = ["obtain_license_token"]
