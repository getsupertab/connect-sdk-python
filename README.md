# Supertab Connect SDK

Python SDK for [Supertab Connect](https://www.supertab.co/supertab-connect).

[![PyPI](https://img.shields.io/pypi/v/supertab-connect-sdk.svg)](https://pypi.org/project/supertab-connect-sdk/)
[![License](https://img.shields.io/pypi/l/supertab-connect-sdk.svg)](LICENSE)
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
`httpx.Request`. See the `examples` directory for complete merchant and customer
examples.

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

See the [Supertab Connect Python SDK docs](https://supertab-connect.mintlify.app/reference/sdk/python)
for the full API reference.

## Development

This project uses `hatchling` as the build backend.

See [DEVELOPMENT.md](DEVELOPMENT.md) for local setup, Git hooks, and CI-aligned development commands.

## Links

- [Documentation](https://supertab-connect.mintlify.app/reference/sdk/python)
- [Repository](https://github.com/getsupertab/connect-sdk-python)
- [Issues](https://github.com/getsupertab/connect-sdk-python/issues)
- [License](LICENSE)
