# Supertab Connect SDK

Python SDK for [Supertab Connect](https://www.supertab.co/supertab-connect).

[![PyPI](https://img.shields.io/pypi/v/supertab-connect-sdk.svg)](https://pypi.org/project/supertab-connect-sdk/)
[![License](https://img.shields.io/pypi/l/supertab-connect-sdk.svg)](https://github.com/getsupertab/connect-sdk-python/blob/main/LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/getsupertab/connect-sdk-python/ci.yml)](https://github.com/getsupertab/connect-sdk-python/actions/workflows/ci.yml)
[![Python Versions](https://img.shields.io/pypi/pyversions/supertab-connect-sdk.svg)](https://pypi.org/project/supertab-connect-sdk/)
[![Ruff](https://img.shields.io/badge/lint-ruff-46a2f1.svg)](https://docs.astral.sh/ruff/)

Use this package to obtain Supertab license tokens on the customer side and verify
or enforce them on the merchant side.

## Installation

```bash
pip install supertab-connect-sdk
```

Requires Python 3.12 or newer.

## Customer Usage

Obtain a license token for a resource URL:

```python
import asyncio

from supertab_connect import obtain_license_token


async def main() -> None:
    token = await obtain_license_token(
        client_id="your_client_id",
        client_secret="your_client_secret",
        resource_url="https://example.com/premium/article",
    )

    if token is None:
        print("No token required for this usage")
        return

    print(token)


asyncio.run(main())
```

The SDK fetches `license.xml` from the resource origin, finds the best matching
`<content>` entry, and exchanges the client credentials for a license token.

## Merchant Usage

Verify and record license-token usage:

```python
import asyncio

from supertab_connect import SupertabConnect, SupertabConnectConfig


async def main() -> None:
    client = SupertabConnect(
        SupertabConnectConfig(
            api_key="your_api_key",
        )
    )

    async with client:
        result = await client.verify_and_record(
            token="your.jwt.token",
            resource_url="https://example.com/premium/article",
            user_agent="Mozilla/5.0",
            request_headers={"Accept": "text/html"},
        )

    if not result.valid:
        print(f"DENY access: {result.error}")
        return

    print("ALLOW access")


asyncio.run(main())
```

For request-level enforcement, use `SupertabConnect.handle_request()` with an
`httpx.Request`. It extracts the license token from the `Authorization` header,
verifies it, optionally emits a relay analytics event, and applies bot detection
and enforcement mode when no token is present. It returns either
`{"action": HandlerAction.ALLOW, ...}` or
`{"action": HandlerAction.BLOCK, "status": ..., "body": ..., "headers": ...}`.

`handle_request()` accepts an optional second argument, a `HandleRequestContext`,
which carries per-request signals supplied by an upstream CDN/proxy
(`source_cdn`, `client_ip`, `request_id`, `request_country`, `request_asn`,
`tls_fingerprint`). These are recorded on the analytics event when present; for
direct SDK use the context can be omitted.

See the `examples` directory for complete merchant and customer examples.

## Analytics

The SDK can emit one analytics event per request to the Supertab Connect
**relay** endpoint at `{base_url}/ingest/events`. This is **off by default** —
enable it by passing `analytics_enabled=True`:

```python
from supertab_connect import SupertabConnect, SupertabConnectConfig

client = SupertabConnect(
    SupertabConnectConfig(
        api_key="stc_live_your_api_key",
        analytics_enabled=True,
    )
)
```

**No extra credentials are required.** Analytics requests are authenticated with
your configured merchant `api_key` using `Authorization: Bearer <api_key>`. The
backend derives merchant identity from the API key, so the SDK sends **no
merchant identifier** in the analytics payload.

Each `AnalyticsEvent` captures the request id, source CDN, a normalized client
IP, the request path (with percent-encoding preserved), method, and selected
headers — plus, when an upstream CDN exposes them via `HandleRequestContext`, the
request country, ASN, TLS fingerprint, and HTTP Message Signature headers — along
with the verification/enforcement decision for the request.

**Fail-open:** analytics emission is fire-and-forget and can never block, slow,
or alter request handling. If emission fails, the error is swallowed and the
request proceeds exactly as it would with analytics disabled. Analytics is sent
only to the relay at `/ingest/events`, independent of billing event recording.

Point analytics at another environment by setting `supertab_base_url` on the
config (or `SupertabConnect.set_base_url(...)`).

For advanced use, the `AnalyticsTransport` protocol lets you inject a custom
transport (for example, an in-memory recorder in tests) via the internal
`analytics_transport` config field; `AnalyticsEvent` and `HandleRequestContext`
are exported from the package root.

### Native Fastly logging (not applicable to the Python SDK)

The TypeScript SDK can deliver analytics through a **native Fastly Compute
logging endpoint** (`FastlyLogTransport` / the `logEndpoint` option on
`fastlyHandleRequests`) instead of the HTTP relay, letting Fastly ship events
off-path to S3. That path is intentionally **not ported here**: Python does not
run on Fastly Compute (the `fastly:logger` built-in has no Python equivalent),
and — consistent with this SDK's design — the Python SDK does not embed CDN edge
handlers, receiving CDN-derived signals through `HandleRequestContext` instead.

If you need to deliver analytics somewhere other than the relay (for example, to
a log shipper that forwards to S3/Tinybird), implement the `AnalyticsTransport`
protocol and pass it via the `analytics_transport` config field.

## Error Handling

Customer-side token retrieval raises `SupertabConnectError` when `license.xml`
cannot be fetched or parsed, no matching content block exists, or the token
endpoint fails.

Merchant-side token verification returns typed result objects instead of raising
for normal invalid-token cases. Invalid tokens include a reason and a human
readable error.

## Typing

This package ships inline type hints and includes a `py.typed` marker for type
checkers.

## Documentation

See the [Supertab Connect Python SDK docs](https://connect-docs.supertab.co/reference/sdk/python)
for the full API reference.

## Development

This project uses `hatchling` as the build backend.

See [DEVELOPMENT.md](DEVELOPMENT.md) for local setup, Git hooks, and CI-aligned development commands.

## Links

- [Documentation](https://connect-docs.supertab.co/reference/sdk/python)
- [Repository](https://github.com/getsupertab/connect-sdk-python)
- [Issues](https://github.com/getsupertab/connect-sdk-python/issues)
- [License](LICENSE)
