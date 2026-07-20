"""Tests for the self-report status endpoint and its challenge verification."""

import json
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import patch

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from supertab_connect.analytics.types import AnalyticsEvent
from supertab_connect.merchant.client import SupertabConnect
from supertab_connect.merchant.status import verify_status_challenge
from supertab_connect.types import (
    EnforcementMode,
    HandlerAction,
    RespondHandlerResult,
    SupertabConnectConfig,
)

from tests.merchant.constants import JWKS_URL, SUPERTAB_BASE_URL

SITE_ORIGIN = "https://acme.com"
STATUS_URL = f"{SITE_ORIGIN}/.well-known/supertab/status"


class RecordingTransport:
    def __init__(self) -> None:
        self.events: list[AnalyticsEvent] = []

    def emit(self, event: AnalyticsEvent) -> None:
        self.events.append(event)


def _sign_challenge(
    private_key,
    *,
    kid: str = "test-kid-1",
    audience: str = SITE_ORIGIN,
    purpose: str = "status-probe",
    exp_delta: timedelta = timedelta(seconds=60),
) -> str:
    now = datetime.now(UTC)
    payload = {"aud": audience, "purpose": purpose, "iat": now, "exp": now + exp_delta}
    pem_bytes = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return jwt.encode(payload, pem_bytes, algorithm="ES256", headers={"kid": kid})


@pytest.fixture()
def sign_challenge(ec_key_pair):
    private_key, _ = ec_key_pair
    return lambda **kwargs: _sign_challenge(private_key, **kwargs)


@pytest.fixture(autouse=True)
def _reset_singleton():
    SupertabConnect.reset_instance()
    SupertabConnect.set_base_url(SUPERTAB_BASE_URL)
    yield
    SupertabConnect.reset_instance()
    SupertabConnect.set_base_url(SUPERTAB_BASE_URL)


def _status_request(token: str | None = None) -> httpx.Request:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return httpx.Request("GET", STATUS_URL, headers=headers)


# --- verify_status_challenge --------------------------------------------------


async def test_accepts_valid_challenge(sign_challenge, mock_jwks):
    token = sign_challenge()
    assert await verify_status_challenge(token, expected_audience=SITE_ORIGIN, base_url=SUPERTAB_BASE_URL) is True


async def test_rejects_wrong_purpose(sign_challenge, mock_jwks):
    token = sign_challenge(purpose="nope")
    assert await verify_status_challenge(token, expected_audience=SITE_ORIGIN, base_url=SUPERTAB_BASE_URL) is False


async def test_rejects_wrong_audience(sign_challenge, mock_jwks):
    token = sign_challenge(audience="https://evil.com")
    assert await verify_status_challenge(token, expected_audience=SITE_ORIGIN, base_url=SUPERTAB_BASE_URL) is False


async def test_rejects_expired_challenge(sign_challenge, mock_jwks):
    token = sign_challenge(exp_delta=timedelta(seconds=-30))
    assert await verify_status_challenge(token, expected_audience=SITE_ORIGIN, base_url=SUPERTAB_BASE_URL) is False


async def test_rejects_challenge_without_exp(ec_key_pair, mock_jwks):
    # A "short-lived" challenge must carry an expiry; one signed without exp verifies otherwise
    # (PyJWT validates exp only when present) and would be replayable forever.
    private_key, _ = ec_key_pair
    now = datetime.now(UTC)
    payload = {"aud": SITE_ORIGIN, "purpose": "status-probe", "iat": now}  # no exp
    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    token = jwt.encode(payload, pem, algorithm="ES256", headers={"kid": "test-kid-1"})
    assert await verify_status_challenge(token, expected_audience=SITE_ORIGIN, base_url=SUPERTAB_BASE_URL) is False


async def test_rejects_challenge_without_iat(ec_key_pair, mock_jwks):
    private_key, _ = ec_key_pair
    now = datetime.now(UTC)
    payload = {"aud": SITE_ORIGIN, "purpose": "status-probe", "exp": now + timedelta(seconds=60)}  # no iat
    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    token = jwt.encode(payload, pem, algorithm="ES256", headers={"kid": "test-kid-1"})
    assert await verify_status_challenge(token, expected_audience=SITE_ORIGIN, base_url=SUPERTAB_BASE_URL) is False


async def test_retries_after_jwks_refresh_on_key_rotation(sign_challenge, jwks_response):
    # First fetch returns a stale key set (missing the signing kid); the second returns the fresh one.
    stale = {"keys": [{**jwks_response["keys"][0], "kid": "old-kid"}]}
    token = sign_challenge()
    with respx.mock:
        route = respx.get(JWKS_URL)
        route.side_effect = [httpx.Response(200, json=stale), httpx.Response(200, json=jwks_response)]
        result = await verify_status_challenge(token, expected_audience=SITE_ORIGIN, base_url=SUPERTAB_BASE_URL)
    assert result is True
    assert route.call_count == 2


async def test_bogus_probes_with_rotating_kids_do_not_amplify_jwks_fetches(sign_challenge, jwks_response):
    # An unauthenticated caller submitting challenges with rotating unknown kids must not bypass
    # the cache and force a backend JWKS fetch per probe. After the first (cooldown-spending)
    # refresh, further misses are throttled to the cache.
    with respx.mock:
        route = respx.get(JWKS_URL).respond(json=jwks_response)

        for i in range(5):
            token = sign_challenge(kid=f"rotating-{i}")
            result = await verify_status_challenge(token, expected_audience=SITE_ORIGIN, base_url=SUPERTAB_BASE_URL)
            assert result is False  # unknown kid never verifies

        # First probe: warm fetch + one refresh; every later probe is throttled → 2 fetches total.
        assert route.call_count == 2


# --- handle_request status branch --------------------------------------------


async def test_status_branch_responds_200_with_payload(sign_challenge, mock_jwks):
    transport = RecordingTransport()
    client = SupertabConnect(
        SupertabConnectConfig(
            api_key="sk_test_123",
            enforcement=EnforcementMode.ENFORCE,
            analytics_enabled=True,
            analytics_transport=transport,
        )
    )

    result = cast(RespondHandlerResult, await client.handle_request(_status_request(sign_challenge())))

    assert result["action"] is HandlerAction.RESPOND
    assert result["status"] == 200
    assert result["headers"]["Cache-Control"] == "no-store"
    assert result["headers"]["Content-Type"] == "application/json"

    body = json.loads(result["body"])
    assert body["enforcement"] == EnforcementMode.ENFORCE.value
    assert body["eventReporting"] is True
    assert body["runtime"] is None
    assert body["component"]["kind"] == "python-sdk"
    assert isinstance(body["component"]["version"], str)
    assert "sdkVersion" not in body

    # No analytics is emitted for a status probe.
    assert transport.events == []


async def test_status_branch_reports_runtime_and_event_reporting_off(sign_challenge, mock_jwks):
    from supertab_connect.types import HandleRequestContext

    client = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123"))
    result = cast(
        RespondHandlerResult,
        await client.handle_request(_status_request(sign_challenge()), HandleRequestContext(source_cdn="cloudflare")),
    )

    body = json.loads(result["body"])
    assert body["runtime"] == "cloudflare"
    assert body["eventReporting"] is False


async def test_status_branch_reports_event_reporting_on_for_custom_transport(sign_challenge, mock_jwks):
    # A custom transport emits regardless of the analytics_enabled flag, so eventReporting must
    # report True even though analytics_enabled defaults to False — otherwise status would claim
    # "eventReporting": false while events flow through the injected transport.
    transport = RecordingTransport()
    client = SupertabConnect(
        SupertabConnectConfig(
            api_key="sk_test_123",
            analytics_transport=transport,
        )
    )

    result = cast(RespondHandlerResult, await client.handle_request(_status_request(sign_challenge())))

    body = json.loads(result["body"])
    assert body["eventReporting"] is True


async def test_status_branch_responds_404_on_invalid_challenge(sign_challenge, mock_jwks):
    client = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123"))
    result = cast(
        RespondHandlerResult,
        await client.handle_request(_status_request(sign_challenge(purpose="nope"))),
    )

    assert result["action"] is HandlerAction.RESPOND
    assert result["status"] == 404
    assert json.loads(result["body"]) == {"supertab": True}
    assert result["headers"]["Cache-Control"] == "no-store"


async def test_status_branch_404_when_authorization_absent():
    client = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123"))
    with patch("supertab_connect.merchant.client.verify_status_challenge") as verify:
        result = cast(RespondHandlerResult, await client.handle_request(_status_request()))

    assert result["action"] is HandlerAction.RESPOND
    assert result["status"] == 404
    verify.assert_not_called()


async def test_non_get_to_status_path_is_not_intercepted():
    # Only GET is the status probe; other methods to the same path must reach the application.
    client = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123"))
    request = httpx.Request("POST", STATUS_URL, headers={"Authorization": "Bearer whatever"})
    with patch("supertab_connect.merchant.client.verify_status_challenge") as verify:
        result = await client.handle_request(request)

    assert result["action"] is not HandlerAction.RESPOND
    verify.assert_not_called()


async def test_encoded_lookalike_path_is_not_intercepted():
    # request.url.path percent-decodes, but the probe must match the raw path only — an encoded
    # look-alike (%2E for '.') is a different route and must flow through to the application.
    client = SupertabConnect(SupertabConnectConfig(api_key="sk_test_123"))
    encoded_url = f"{SITE_ORIGIN}/%2Ewell-known/supertab/status"
    request = httpx.Request("GET", encoded_url, headers={"Authorization": "Bearer whatever"})
    with patch("supertab_connect.merchant.client.verify_status_challenge") as verify:
        result = await client.handle_request(request)

    assert result["action"] is not HandlerAction.RESPOND
    verify.assert_not_called()
