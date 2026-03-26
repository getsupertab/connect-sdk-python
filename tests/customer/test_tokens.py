import asyncio
import base64
import time
from collections.abc import Callable, Coroutine
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from connect.customer.token import _create_async_client, _generate_license_token, obtain_license_token
from connect.exceptions import SupertabConnectError

from tests.customer.conftest import SAMPLE_XML

AsyncHandler = Callable[[httpx.Request], Coroutine[Any, Any, httpx.Response]]


def _install_mock_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler: AsyncHandler,
) -> None:
    def create_mock_client(**kwargs: Any) -> httpx.AsyncClient:
        kwargs.setdefault("follow_redirects", True)
        kwargs.setdefault("timeout", httpx.Timeout(10.0))
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(
        "connect.customer.token._create_async_client",
        create_mock_client,
    )


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
    expected_basic_auth = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")

    async def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == license_xml_url:
            calls["license_xml"] += 1
            return httpx.Response(200, text=SAMPLE_XML, request=request)

        if str(request.url) == token_endpoint:
            calls["token"] += 1
            assert request.headers["Authorization"] == f"Basic {expected_basic_auth}"
            body = dict(httpx.QueryParams(request.content.decode("utf-8")).multi_items())
            assert body["grant_type"] == "client_credentials"
            assert body["resource"] == matched_resource_pattern
            assert "<license" in body["license"]
            return httpx.Response(200, json={"access_token": access_token}, request=request)

        raise AssertionError(f"Unexpected URL: {request.url!s}")

    _install_mock_transport(monkeypatch, handler)

    token = asyncio.run(
        obtain_license_token(
            client_id=client_id,
            client_secret=client_secret,
            resource_url=resource_url,
        )
    )
    cached = asyncio.run(
        obtain_license_token(
            client_id=client_id,
            client_secret=client_secret,
            resource_url=resource_url,
        )
    )

    assert token == access_token
    assert cached == access_token
    assert calls == {"license_xml": 1, "token": 1}


def test_create_async_client_uses_safe_defaults() -> None:
    async def run() -> None:
        async with _create_async_client() as client:
            assert client.follow_redirects is True
            assert client.timeout.connect == 10.0
            assert client.timeout.read == 10.0
            assert client.timeout.write == 10.0
            assert client.timeout.pool == 10.0

    asyncio.run(run())


def test_obtain_license_token_follows_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exp = int(time.time()) + 3600
    access_token = jwt.encode({"exp": exp}, "x" * 32, algorithm="HS256")
    resource_url = "http://127.0.0.1:7676/article/foo"
    initial_license_xml_url = "http://127.0.0.1:7676/license.xml"
    redirected_license_xml_url = "http://127.0.0.1:7676/redirected-license.xml"
    initial_token_endpoint = "http://127.0.0.1:8787/token"
    redirected_token_endpoint = "http://127.0.0.1:8787/redirected-token"
    calls = {"license_redirect": 0, "license_final": 0, "token_redirect": 0, "token_final": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == initial_license_xml_url:
            calls["license_redirect"] += 1
            return httpx.Response(
                307,
                headers={"Location": redirected_license_xml_url},
                request=request,
            )
        if url == redirected_license_xml_url:
            calls["license_final"] += 1
            return httpx.Response(200, text=SAMPLE_XML, request=request)
        if url == initial_token_endpoint:
            calls["token_redirect"] += 1
            return httpx.Response(
                307,
                headers={"Location": redirected_token_endpoint},
                request=request,
            )
        if url == redirected_token_endpoint:
            calls["token_final"] += 1
            return httpx.Response(200, json={"access_token": access_token}, request=request)

        raise AssertionError(f"Unexpected URL: {url}")

    _install_mock_transport(monkeypatch, handler)

    token = asyncio.run(
        obtain_license_token(
            client_id="client",
            client_secret="secret",
            resource_url=resource_url,
        )
    )

    assert token == access_token
    assert calls == {
        "license_redirect": 1,
        "license_final": 1,
        "token_redirect": 1,
        "token_final": 1,
    }


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

    async def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == token_endpoint
        body = dict(httpx.QueryParams(request.content.decode("utf-8")).multi_items())
        assert body["grant_type"] == "rsl"
        assert body["resource"] == resource_url
        assert body["license"] == license_xml

        assertion = body["client_assertion"]
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

        return httpx.Response(200, json={"access_token": issued_token}, request=request)

    _install_mock_transport(monkeypatch, handler)

    token = asyncio.run(
        _generate_license_token(
            client_id=client_id,
            kid=kid,
            private_key_pem=pem,
            token_endpoint=token_endpoint,
            resource_url=resource_url,
            license_xml=license_xml,
        )
    )

    assert token == issued_token


def test_obtain_license_token_raises_on_invalid_resource_url() -> None:
    with pytest.raises(SupertabConnectError, match="Invalid resource URL"):
        asyncio.run(
            obtain_license_token(
                client_id="client",
                client_secret="secret",
                resource_url="not-a-url",
            )
        )


def test_obtain_license_token_raises_on_license_xml_http_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="Not Found", request=request)

    _install_mock_transport(monkeypatch, handler)

    with pytest.raises(SupertabConnectError, match="Failed to fetch license.xml"):
        asyncio.run(
            obtain_license_token(
                client_id="client",
                client_secret="secret",
                resource_url="http://127.0.0.1:7676/article/foo",
            )
        )


def test_obtain_license_token_raises_when_no_content_elements(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<rsl></rsl>", request=request)

    _install_mock_transport(monkeypatch, handler)

    with pytest.raises(
        SupertabConnectError,
        match="No valid <content> elements with <license> found in license.xml",
    ):
        asyncio.run(
            obtain_license_token(
                client_id="client",
                client_secret="secret",
                resource_url="http://127.0.0.1:7676/article/foo",
            )
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

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=xml, request=request)

    _install_mock_transport(monkeypatch, handler)

    with pytest.raises(
        SupertabConnectError,
        match="No <content> element in license.xml matches resource URL",
    ):
        asyncio.run(
            obtain_license_token(
                client_id="client",
                client_secret="secret",
                resource_url="http://127.0.0.1:7676/article/foo",
            )
        )


def test_obtain_license_token_raises_on_token_endpoint_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_endpoint = "http://127.0.0.1:8787/token"

    async def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/license.xml"):
            return httpx.Response(200, text=SAMPLE_XML, request=request)
        if str(request.url) == token_endpoint:
            return httpx.Response(500, text="Internal Server Error", request=request)
        raise AssertionError(f"Unexpected URL: {request.url!s}")

    _install_mock_transport(monkeypatch, handler)

    with pytest.raises(SupertabConnectError, match="Failed to obtain license token: 500"):
        asyncio.run(
            obtain_license_token(
                client_id="client",
                client_secret="secret",
                resource_url="http://127.0.0.1:7676/article/foo",
            )
        )


def test_obtain_license_token_raises_on_invalid_json_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/license.xml"):
            return httpx.Response(200, text=SAMPLE_XML, request=request)
        if str(request.url).endswith("/token"):
            return httpx.Response(200, text="not json", request=request)
        raise AssertionError(f"Unexpected URL: {request.url!s}")

    _install_mock_transport(monkeypatch, handler)

    with pytest.raises(SupertabConnectError, match="Failed to parse license token response as JSON"):
        asyncio.run(
            obtain_license_token(
                client_id="client",
                client_secret="secret",
                resource_url="http://127.0.0.1:7676/article/foo",
            )
        )


def test_obtain_license_token_raises_when_access_token_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/license.xml"):
            return httpx.Response(200, text=SAMPLE_XML, request=request)
        if str(request.url).endswith("/token"):
            return httpx.Response(200, json={"token_type": "bearer"}, request=request)
        raise AssertionError(f"Unexpected URL: {request.url!s}")

    _install_mock_transport(monkeypatch, handler)

    with pytest.raises(SupertabConnectError, match="License token response missing access_token"):
        asyncio.run(
            obtain_license_token(
                client_id="client",
                client_secret="secret",
                resource_url="http://127.0.0.1:7676/article/foo",
            )
        )


def test_obtain_license_token_raises_on_license_xml_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    _install_mock_transport(monkeypatch, handler)

    with pytest.raises(SupertabConnectError, match="Failed to fetch license.xml"):
        asyncio.run(
            obtain_license_token(
                client_id="client",
                client_secret="secret",
                resource_url="http://127.0.0.1:7676/article/foo",
            )
        )
