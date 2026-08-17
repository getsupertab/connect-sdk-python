"""Customer-side token helpers for Supertab Connect."""

import asyncio
import base64
import json
import time
import urllib.parse
from dataclasses import dataclass
from xml.etree import ElementTree
from typing import Any
from weakref import WeakKeyDictionary

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from supertab_connect._version import _get_sdk_user_agent
from supertab_connect.common import debug_log, error_log
from supertab_connect.exceptions import SupertabConnectError
from supertab_connect.customer.content_matcher import _find_best_matching_content
from supertab_connect.customer.content_parser import _ContentBlock
from supertab_connect.customer.content_parser import _parse_content_elements
from supertab_connect.types import UsageType

_SUPPORTED_ALGS = ("ES256", "RS256")
_DEFAULT_HTTP_TIMEOUT_SECONDS = 10.0
_LICENSE_TOKEN_CACHE: dict[tuple[str, str, str], "_CachedToken"] = {}
_LICENSE_TOKEN_LOCKS: WeakKeyDictionary[asyncio.AbstractEventLoop, dict[tuple[str, str, str], asyncio.Lock]] = (
    WeakKeyDictionary()
)
_LICENSE_XML_TTL_SECONDS = 15 * 60
_LICENSE_XML_CACHE: dict[str, "_CachedLicenseXml"] = {}


@dataclass(frozen=True)
class _CachedToken:
    token: str
    exp: int


@dataclass(frozen=True)
class _CachedLicenseXml:
    xml: str
    fetched_at: int


def _build_origin(resource_url: str) -> str:
    parsed = urllib.parse.urlsplit(resource_url)
    if not parsed.scheme or not parsed.netloc:
        raise SupertabConnectError(f"Invalid resource URL: {resource_url}")
    return f"{parsed.scheme}://{parsed.netloc}"


def _get_cached_token(cache_key: tuple[str, str, str], debug: bool = False) -> str | None:
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


def _get_cache_lock(cache_key: tuple[str, str, str]) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    loop_locks = _LICENSE_TOKEN_LOCKS.get(loop)
    if loop_locks is None:
        loop_locks = {}
        _LICENSE_TOKEN_LOCKS[loop] = loop_locks

    lock = loop_locks.get(cache_key)
    if lock is None:
        lock = asyncio.Lock()
        loop_locks[cache_key] = lock

    return lock


def _evict_expired_license_xml() -> None:
    now = int(time.time())
    expired_origins = [
        origin for origin, entry in _LICENSE_XML_CACHE.items() if now - entry.fetched_at >= _LICENSE_XML_TTL_SECONDS
    ]
    for origin in expired_origins:
        _LICENSE_XML_CACHE.pop(origin, None)


def _create_async_client(**kwargs: Any) -> httpx.AsyncClient:
    kwargs.setdefault("follow_redirects", True)
    kwargs.setdefault("timeout", httpx.Timeout(_DEFAULT_HTTP_TIMEOUT_SECONDS))

    headers = kwargs.pop("headers", None)
    if headers is None:
        headers = {"User-Agent": _get_sdk_user_agent()}
    else:
        headers = dict(headers)
        headers.setdefault("User-Agent", _get_sdk_user_agent())
    kwargs["headers"] = headers

    return httpx.AsyncClient(**kwargs)


def _read_json_response(response: httpx.Response, debug: bool) -> dict[str, Any]:
    try:
        payload = response.json()
    except json.JSONDecodeError as error:
        error_log(debug, f"Failed to parse license token response as JSON: {error}")
        raise SupertabConnectError("Failed to parse license token response as JSON") from error

    if not isinstance(payload, dict):
        error_log(debug, "Failed to parse license token response as JSON: expected object payload")
        raise SupertabConnectError("Failed to parse license token response as JSON")

    return payload


async def _retrieve_license_token(
    client: httpx.AsyncClient,
    *,
    token_endpoint: str,
    body: dict[str, str],
    headers: dict[str, str],
    debug: bool = False,
) -> str:
    try:
        response = await client.post(token_endpoint, data=body, headers=headers)
        response.raise_for_status()
        payload = _read_json_response(response, debug)
    except httpx.HTTPStatusError as error:
        error_body = error.response.text
        suffix = f" - {error_body}" if error_body else ""
        message = (
            f"Failed to obtain license token: {error.response.status_code} {error.response.reason_phrase}{suffix}"
        )
        error_log(debug, f"Error generating license token: {message}")
        raise SupertabConnectError(message) from error
    except httpx.RequestError as error:
        message = f"Failed to obtain license token: {error}"
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
        raise SupertabConnectError("Unsupported private key format. Expected RSA or P-256 EC private key.") from error

    if isinstance(key, ec.EllipticCurvePrivateKey):
        if isinstance(key.curve, ec.SECP256R1):
            return key, "ES256"
        raise SupertabConnectError("Unsupported private key format. Expected RSA or P-256 EC private key.")

    if isinstance(key, rsa.RSAPrivateKey):
        return key, "RS256"

    debug_log(
        debug,
        f"Unsupported private key type {type(key).__name__}; expected RSA or P-256 EC private key.",
    )

    raise SupertabConnectError("Unsupported private key format. Expected RSA or P-256 EC private key.")


async def _generate_license_token(
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

    body = {
        "grant_type": "rsl",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion,
        "license": license_xml,
        "resource": resource_url,
    }

    async with _create_async_client() as client:
        return await _retrieve_license_token(
            client,
            token_endpoint=token_endpoint,
            body=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            debug=debug,
        )


async def _fetch_license_xml(
    client: httpx.AsyncClient,
    resource_url: str,
    debug: bool = False,
) -> str:
    origin = _build_origin(resource_url)
    cached = _LICENSE_XML_CACHE.get(origin)
    if cached is not None:
        now = int(time.time())
        age = now - cached.fetched_at
        if age < _LICENSE_XML_TTL_SECONDS:
            debug_log(
                debug,
                f"Using cached license.xml for origin {origin} (expires in {_LICENSE_XML_TTL_SECONDS - age}s)",
            )
            return cached.xml

        debug_log(debug, f"Cached license.xml for origin {origin} expired, re-fetching")
        _LICENSE_XML_CACHE.pop(origin, None)

    license_xml_url = f"{origin}/license.xml"

    try:
        response = await client.get(license_xml_url)
        response.raise_for_status()
        xml = response.text
    except httpx.HTTPStatusError as error:
        error_log(
            debug,
            f"Failed to fetch license.xml from {license_xml_url}: {error.response.status_code}",
        )
        raise SupertabConnectError(
            f"Failed to fetch license.xml from {license_xml_url}: {error.response.status_code}"
        ) from error
    except httpx.RequestError as error:
        message = f"Failed to fetch license.xml from {license_xml_url}: {error}"
        error_log(debug, message)
        raise SupertabConnectError(message) from error

    debug_log(debug, f"Fetched license.xml from {license_xml_url}")
    _evict_expired_license_xml()
    _LICENSE_XML_CACHE[origin] = _CachedLicenseXml(xml=xml, fetched_at=int(time.time()))
    return xml


def _local_name(tag: str) -> str:
    return tag.rsplit("}", maxsplit=1)[-1]


def _license_permits_usage(license_xml: str, usage: UsageType | str) -> bool:
    try:
        root = ElementTree.fromstring(license_xml)
    except ElementTree.ParseError:
        return False

    usage_value = str(usage)
    is_permitted = False

    for element in root.iter():
        if element.attrib.get("type") != "usage":
            continue

        tag = _local_name(element.tag)
        if tag not in {"prohibits", "permits"}:
            continue

        usages = " ".join(element.itertext()).split()

        if UsageType.ALL not in usages and usage_value not in usages:
            continue

        if tag == "prohibits":
            return False

        is_permitted = True

    return is_permitted


def _find_serverless_usage_content(
    content_blocks: list[_ContentBlock],
    resource_url: str,
    usage: UsageType | str,
    debug: bool = False,
) -> _ContentBlock | None:
    matching_usage_blocks = [
        block for block in content_blocks if block.server is None and _license_permits_usage(block.license_xml, usage)
    ]

    return _find_best_matching_content(matching_usage_blocks, resource_url, debug)


async def obtain_license_token(
    *,
    client_id: str,
    client_secret: str,
    resource_url: str,
    usage: UsageType | str | None = None,
    debug: bool = False,
) -> str | None:
    """Obtain a license token using the current client credentials flow.

    This is the supported customer flow. The SDK fetches ``license.xml`` for
    the requested resource, finds the best matching ``<content>`` block, and
    exchanges the client credentials for a license token. If ``usage`` is
    provided and a matching serverless content block permits that usage, no
    token is needed and ``None`` is returned.
    """
    async with _create_async_client() as client:
        xml = await _fetch_license_xml(client, resource_url, debug)
        debug_log(debug, f"Fetched license.xml ({len(xml)} chars)")
        content_blocks = _parse_content_elements(xml, debug)

        if not content_blocks:
            error_log(debug, "No valid <content> elements with <license> found in license.xml")
            raise SupertabConnectError("No valid <content> elements with <license> found in license.xml")

        if usage is not None:
            serverless_usage_content = _find_serverless_usage_content(content_blocks, resource_url, usage, debug)
            if serverless_usage_content is not None:
                debug_log(
                    debug,
                    "Matched serverless content to usage and resource URL combination, skipping license token request.",
                )
                debug_log(debug, f"URL: {resource_url}, Usage: {usage}")
                return None

        token_content_blocks = [block for block in content_blocks if block.server]
        matched_content = _find_best_matching_content(token_content_blocks, resource_url, debug)
        if matched_content is None or matched_content.server is None:
            patterns = ", ".join(block.url_pattern for block in token_content_blocks)
            error_log(
                debug,
                f"No <content> element matches resource URL: {resource_url}. Available patterns: {patterns}",
            )
            raise SupertabConnectError(f"No <content> element in license.xml matches resource URL: {resource_url}")

        debug_log(debug, f"Matched content block for resource URL: {resource_url}")
        debug_log(debug, f"Using license XML: {matched_content.license_xml}")

        cache_key = (client_id, matched_content.server, matched_content.url_pattern)
        cached = _get_cached_token(cache_key, debug)
        if cached is not None:
            return cached

        lock = _get_cache_lock(cache_key)
        async with lock:
            cached = _get_cached_token(cache_key, debug)
            if cached is not None:
                return cached

            token_endpoint = matched_content.server.rstrip("/") + "/token"
            debug_log(debug, f"Requesting license token from {token_endpoint}")

            auth = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
            token = await _retrieve_license_token(
                client,
                token_endpoint=token_endpoint,
                body={
                    "grant_type": "client_credentials",
                    "license": matched_content.license_xml,
                    "resource": matched_content.url_pattern,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "Authorization": f"Basic {auth}",
                },
                debug=debug,
            )

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
