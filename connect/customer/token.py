"""Customer-side token helpers for Supertab Connect."""

import asyncio
import base64
import json
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any
from weakref import WeakKeyDictionary

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from connect.common import debug_log, error_log
from connect.exceptions import SupertabConnectError
from connect.customer.content_matcher import _find_best_matching_content
from connect.customer.content_parser import _parse_content_elements

_SUPPORTED_ALGS = ("ES256", "RS256")
_DEFAULT_HTTP_TIMEOUT_SECONDS = 10.0
_LICENSE_TOKEN_CACHE: dict[tuple[str, str], "_CachedToken"] = {}
_LICENSE_TOKEN_LOCKS: WeakKeyDictionary[asyncio.AbstractEventLoop, dict[tuple[str, str], asyncio.Lock]] = (
    WeakKeyDictionary()
)


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


def _get_cache_lock(cache_key: tuple[str, str]) -> asyncio.Lock:
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


def _create_async_client(**kwargs: Any) -> httpx.AsyncClient:
    kwargs.setdefault("follow_redirects", True)
    kwargs.setdefault("timeout", httpx.Timeout(_DEFAULT_HTTP_TIMEOUT_SECONDS))
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
    license_xml_url = f"{_build_origin(resource_url)}/license.xml"

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
    return xml


async def obtain_license_token(
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

    lock = _get_cache_lock(cache_key)
    async with lock:
        cached = _get_cached_token(cache_key, debug)
        if cached is not None:
            return cached

        async with _create_async_client() as client:
            xml = await _fetch_license_xml(client, resource_url, debug)
            debug_log(debug, f"Fetched license.xml ({len(xml)} chars)")
            content_blocks = _parse_content_elements(xml, debug)

            if not content_blocks:
                error_log(debug, "No valid <content> elements with <license> found in license.xml")
                raise SupertabConnectError("No valid <content> elements with <license> found in license.xml")

            matched_content = _find_best_matching_content(content_blocks, resource_url, debug)
            if matched_content is None:
                patterns = ", ".join(block.url_pattern for block in content_blocks)
                error_log(
                    debug,
                    f"No <content> element matches resource URL: {resource_url}. Available patterns: {patterns}",
                )
                raise SupertabConnectError(f"No <content> element in license.xml matches resource URL: {resource_url}")

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
