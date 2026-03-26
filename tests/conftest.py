"""Shared test fixtures for the Supertab Connect SDK test suite."""

import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

SUPERTAB_BASE_URL = "https://connect.supertab.co"
REQUEST_URL = "https://example.com/premium/article"
JWKS_URL = f"{SUPERTAB_BASE_URL}/.well-known/jwks.json/platform"


@pytest.fixture()
def ec_key_pair():
    """Generate a fresh EC P-256 key pair for signing test JWTs."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture()
def jwk_dict(ec_key_pair):
    """Build a JWK dict (public key) suitable for a JWKS response."""
    _, public_key = ec_key_pair
    jwk_data = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(public_key))
    jwk_data["kid"] = "test-kid-1"
    jwk_data["use"] = "sig"
    jwk_data["alg"] = "ES256"
    return jwk_data


@pytest.fixture()
def jwks_response(jwk_dict):
    """A JWKS JSON response containing the test public key."""
    return {"keys": [jwk_dict]}


def _make_token(
    private_key,
    *,
    kid: str = "test-kid-1",
    alg: str = "ES256",
    issuer: str = SUPERTAB_BASE_URL,
    audience: str = REQUEST_URL,
    license_id: str = "lic_test_123",
    exp_delta: timedelta = timedelta(hours=1),
    extra_claims: dict | None = None,
) -> str:
    """Helper to create a signed JWT for testing."""
    now = datetime.now(UTC)
    payload = {
        "iss": issuer,
        "aud": audience,
        "license_id": license_id,
        "iat": now,
        "exp": now + exp_delta,
    }
    if extra_claims:
        payload.update(extra_claims)

    pem_bytes = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return jwt.encode(payload, pem_bytes, algorithm=alg, headers={"kid": kid})


@pytest.fixture()
def make_token(ec_key_pair):
    """Fixture returning a callable that creates signed test JWTs."""
    private_key, _ = ec_key_pair
    return lambda **kwargs: _make_token(private_key, **kwargs)


@pytest.fixture()
def mock_jwks(jwks_response):
    """Set up a respx mock for the JWKS endpoint."""
    with respx.mock:
        respx.get(JWKS_URL).respond(json=jwks_response)
        yield


@pytest.fixture(autouse=True)
def _clear_jwks_cache():
    """Ensure JWKS cache is cleared before each test."""
    from connect.merchant.jwks import clear_jwks_cache

    clear_jwks_cache()
