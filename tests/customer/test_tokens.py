import base64
from http.client import HTTPMessage
import io
import json
import time
import urllib.error
import urllib.parse

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from connect.customer.token import _generate_license_token, obtain_license_token
from connect.exceptions import SupertabConnectError

from tests.customer.conftest import FakeResponse, SAMPLE_XML


def test_obtain_license_token_fetches_and_caches_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exp = int(time.time()) + 3600
    access_token = jwt.encode({"exp": exp}, "x" * 32, algorithm="HS256")
    calls = {"license_xml": 0, "token": 0}
    client_id = "client"
    client_secret = "secret"
    resource_url = "http://127.0.0.1:7676/article/foo"
    license_xml_url = "http://127.0.0.1:7676/license.xml"
    matched_resource_pattern = "http://127.0.0.1:7676/article/*"
    token_endpoint = "http://127.0.0.1:8787/token"
    expected_basic_auth = base64.b64encode(
        f"{client_id}:{client_secret}".encode("utf-8")
    ).decode("ascii")

    def fake_urlopen(request):  # type: ignore[no-untyped-def]
        url = request.full_url
        if url == license_xml_url:
            calls["license_xml"] += 1
            return FakeResponse(SAMPLE_XML)

        if url == token_endpoint:
            calls["token"] += 1
            assert request.headers["Authorization"] == f"Basic {expected_basic_auth}"
            body = urllib.parse.parse_qs(request.data.decode("utf-8"))
            assert body["grant_type"] == ["client_credentials"]
            assert body["resource"] == [matched_resource_pattern]
            assert "<license" in body["license"][0]
            return FakeResponse(json.dumps({"access_token": access_token}))

        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr("connect.customer.token.urllib.request.urlopen", fake_urlopen)

    token = obtain_license_token(
        client_id=client_id,
        client_secret=client_secret,
        resource_url=resource_url,
    )
    cached = obtain_license_token(
        client_id=client_id,
        client_secret=client_secret,
        resource_url=resource_url,
    )

    assert token == access_token
    assert cached == access_token
    assert calls == {"license_xml": 1, "token": 1}


@pytest.mark.parametrize(
    ("algorithm", "key_factory"),
    [
        (
            "RS256",
            lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
        ),
        ("ES256", lambda: ec.generate_private_key(ec.SECP256R1())),
    ],
)
def test_generate_license_token_builds_client_assertion_with_matching_alg(
    monkeypatch: pytest.MonkeyPatch,
    algorithm: str,
    key_factory,
) -> None:
    client_id = "client-123"
    kid = "kid-123"
    token_endpoint = "https://license.example/token"
    resource_url = "https://publisher.example/content/item"
    license_xml = "<license/>"
    issued_token = "issued-token"
    private_key = key_factory()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    def fake_urlopen(request):  # type: ignore[no-untyped-def]
        assert request.full_url == token_endpoint
        body = urllib.parse.parse_qs(request.data.decode("utf-8"))
        assert body["grant_type"] == ["rsl"]
        assert body["resource"] == [resource_url]
        assert body["license"] == [license_xml]

        assertion = body["client_assertion"][0]
        header = jwt.get_unverified_header(assertion)
        claims = jwt.decode(
            assertion,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False,
                "verify_iss": False,
            },
            algorithms=[algorithm],
        )

        assert header["alg"] == algorithm
        assert header["kid"] == kid
        assert claims["iss"] == client_id
        assert claims["sub"] == client_id
        assert claims["aud"] == token_endpoint

        return FakeResponse(json.dumps({"access_token": issued_token}))

    monkeypatch.setattr("connect.customer.token.urllib.request.urlopen", fake_urlopen)

    token = _generate_license_token(
        client_id=client_id,
        kid=kid,
        private_key_pem=pem,
        token_endpoint=token_endpoint,
        resource_url=resource_url,
        license_xml=license_xml,
    )

    assert token == issued_token


def test_obtain_license_token_raises_on_invalid_resource_url() -> None:
    with pytest.raises(SupertabConnectError, match="Invalid resource URL"):
        obtain_license_token(
            client_id="client",
            client_secret="secret",
            resource_url="not-a-url",
        )


def test_obtain_license_token_raises_on_license_xml_http_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(request):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(
            request.full_url,
            404,
            "Not Found",
            hdrs=HTTPMessage(),
            fp=io.BytesIO(b"Not Found"),
        )

    monkeypatch.setattr("connect.customer.token.urllib.request.urlopen", fake_urlopen)

    with pytest.raises(SupertabConnectError, match="Failed to fetch license.xml"):
        obtain_license_token(
            client_id="client",
            client_secret="secret",
            resource_url="http://127.0.0.1:7676/article/foo",
        )


def test_obtain_license_token_raises_when_no_content_elements(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(request):  # type: ignore[no-untyped-def]
        return FakeResponse("<rsl></rsl>")

    monkeypatch.setattr("connect.customer.token.urllib.request.urlopen", fake_urlopen)

    with pytest.raises(
        SupertabConnectError,
        match="No valid <content> elements with <license> found in license.xml",
    ):
        obtain_license_token(
            client_id="client",
            client_secret="secret",
            resource_url="http://127.0.0.1:7676/article/foo",
        )


def test_obtain_license_token_raises_when_no_matching_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xml = """
    <rsl>
      <content url="http://other-host.com/*" server="http://token.other.com">
        <license type="test"><link rel="self" /></license>
      </content>
    </rsl>
    """

    def fake_urlopen(request):  # type: ignore[no-untyped-def]
        return FakeResponse(xml)

    monkeypatch.setattr("connect.customer.token.urllib.request.urlopen", fake_urlopen)

    with pytest.raises(
        SupertabConnectError,
        match="No <content> element in license.xml matches resource URL",
    ):
        obtain_license_token(
            client_id="client",
            client_secret="secret",
            resource_url="http://127.0.0.1:7676/article/foo",
        )


def test_obtain_license_token_raises_on_token_endpoint_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_endpoint = "http://127.0.0.1:8787/token"

    def fake_urlopen(request):  # type: ignore[no-untyped-def]
        if request.full_url.endswith("/license.xml"):
            return FakeResponse(SAMPLE_XML)
        if request.full_url == token_endpoint:
            raise urllib.error.HTTPError(
                request.full_url,
                500,
                "Internal Server Error",
                hdrs=HTTPMessage(),
                fp=io.BytesIO(b"Internal Server Error"),
            )
        raise AssertionError(f"Unexpected URL: {request.full_url}")

    monkeypatch.setattr("connect.customer.token.urllib.request.urlopen", fake_urlopen)

    with pytest.raises(
        SupertabConnectError, match="Failed to obtain license token: 500"
    ):
        obtain_license_token(
            client_id="client",
            client_secret="secret",
            resource_url="http://127.0.0.1:7676/article/foo",
        )


def test_obtain_license_token_raises_on_invalid_json_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(request):  # type: ignore[no-untyped-def]
        if request.full_url.endswith("/license.xml"):
            return FakeResponse(SAMPLE_XML)
        if request.full_url.endswith("/token"):
            return FakeResponse("not json")
        raise AssertionError(f"Unexpected URL: {request.full_url}")

    monkeypatch.setattr("connect.customer.token.urllib.request.urlopen", fake_urlopen)

    with pytest.raises(
        SupertabConnectError, match="Failed to parse license token response as JSON"
    ):
        obtain_license_token(
            client_id="client",
            client_secret="secret",
            resource_url="http://127.0.0.1:7676/article/foo",
        )


def test_obtain_license_token_raises_when_access_token_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(request):  # type: ignore[no-untyped-def]
        if request.full_url.endswith("/license.xml"):
            return FakeResponse(SAMPLE_XML)
        if request.full_url.endswith("/token"):
            return FakeResponse(json.dumps({"token_type": "bearer"}))
        raise AssertionError(f"Unexpected URL: {request.full_url}")

    monkeypatch.setattr("connect.customer.token.urllib.request.urlopen", fake_urlopen)

    with pytest.raises(
        SupertabConnectError, match="License token response missing access_token"
    ):
        obtain_license_token(
            client_id="client",
            client_secret="secret",
            resource_url="http://127.0.0.1:7676/article/foo",
        )
