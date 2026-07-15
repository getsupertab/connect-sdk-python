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
`{"action": HandlerAction.ALLOW, ...}`,
`{"action": HandlerAction.BLOCK, "status": ..., "body": ..., "headers": ...}`, or
`{"action": HandlerAction.RESPOND, "status": ..., "body": ..., "headers": ...}`
(see [Self-report status endpoint](#self-report-status-endpoint) below).

`handle_request()` accepts an optional second argument, a `HandleRequestContext`,
which carries per-request signals supplied by an upstream CDN/proxy
(`source_cdn`, `client_ip`, `request_id`, `request_country`, `request_asn`,
`tls_fingerprint`, and `cdn_signals`). These are recorded on the analytics event
when present; for direct SDK use the context can be omitted.

`cdn_signals` is a `CdnRequestSignals` object carrying the richer
spoof-detection signals that cannot be read from the portable request — TLS
fingerprinting fields, the verified-bot category, the negotiated protocol, and
so on. These are platform-specific (for example, Cloudflare exposes them on
`request.cf`), so the SDK takes them from the caller rather than extracting them
itself. Everything left unset stays `null` on the event.

See the `examples` directory for complete merchant and customer examples.

## Self-report status endpoint

`handle_request()` also answers the platform's self-report probe at
`GET /.well-known/supertab/status`, which powers the portal's live-health view.
When the request carries a valid backend-signed challenge
(`Authorization: Bearer <challenge>`, an ES256 JWT scoped to the site origin with
`purpose: status-probe`), the SDK returns a `RESPOND` result reporting its live
config:

```json
{
  "runtime": "cloudflare",
  "component": { "kind": "python-sdk", "version": "1.0.0" },
  "enforcement": "observe",
  "eventReporting": false
}
```

`runtime` comes from `HandleRequestContext.source_cdn` (or `null` for direct
invocation). Without a valid challenge the SDK returns a minimal
`{"supertab": true}` with a `404` status, disclosing nothing about the
deployment. The probe short-circuits ahead of token verification, bot detection,
and analytics — no event is emitted. Both responses set `Cache-Control:
no-store`.

A `RESPOND` result must be served to the caller **verbatim** (status, body, and
headers) without forwarding to origin; it is distinguished from `ALLOW` / `BLOCK`
by `result["action"] == HandlerAction.RESPOND`.

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

Events emit at **`schema_version: 2`** ("capture v2"), which adds raw
spoof-detection signals for query-time classification in the warehouse (the SDK
never classifies — it emits raw signals only):

- **Portable header signals**, read directly from the request: `sec_fetch_*`,
  the `sec_ch_ua*` client hints, `accept`, `host`, `has_cookies`, and
  `header_names` — the lowercased, deduped, sorted set of request-header names
  with edge-injected headers (`cf-*`, `fastly-*`, `cloudfront-*`,
  `x-forwarded-*`, `x-real-ip`, the synthesized `Host`, …) stripped so it
  reflects only what the client sent.
- **Query-string derived signals**: `query_length`, `query_param_count`, and
  `query_suspicious` (a coarse exploit-marker heuristic). The raw query string
  is **never** stored.
- **CDN plumbing** supplied via `HandleRequestContext.cdn_signals`:
  `accept_encoding`, `http_protocol`, `tls_version`, `tls_cipher`,
  `tls_client_hello_length`, `tls_client_extensions_sha1`, `as_organization`,
  `client_tcp_rtt`, `cdn_verified_bot_category`, `request_priority`, and
  `tls_fingerprint_ja4`.

`accept`, `sec_ch_ua`, and `as_organization` are truncated to 512 characters.
Every capture-v2 field is fail-open: anything unavailable is emitted as `null`.

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
