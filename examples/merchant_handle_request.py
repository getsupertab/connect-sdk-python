"""Example of using `SupertabConnect.handle_request` for request enforcement."""

import asyncio
import logging

import httpx

from supertab_connect import EnforcementMode, HandlerAction, SupertabConnect, SupertabConnectConfig

logging.basicConfig(level=logging.DEBUG)

REQUEST_URL = "https://example.com/premium/article"


async def main() -> None:
    client = SupertabConnect(
        SupertabConnectConfig(
            api_key="your_api_key",
            enforcement=EnforcementMode.ENFORCE,
            debug=True,
        )
    )

    request = httpx.Request(
        "GET",
        REQUEST_URL,
        headers={
            "Authorization": "License your.jwt.token",
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html",
            "Accept-Language": "en-US",
            "Sec-CH-UA": '"Chromium";v="123"',
        },
    )

    async with client:
        result = await client.handle_request(request)

    if result["action"] is HandlerAction.BLOCK:
        print("BLOCK request")
        print(result["status"])  # type: ignore
        print(result["headers"]["WWW-Authenticate"])
        return

    # A RESPOND result (e.g. the self-report status probe at /.well-known/supertab/status)
    # must be served to the caller verbatim — status, body, and headers — and never forwarded
    # to origin. Treating it as ALLOW would leak the probe through to the application.
    if result["action"] is HandlerAction.RESPOND:
        print("RESPOND request")
        print(result["status"])  # type: ignore
        print(result["headers"])  # type: ignore
        print(result["body"])  # type: ignore
        return

    print("ALLOW request")
    if "headers" in result:
        print(result["headers"])


if __name__ == "__main__":
    asyncio.run(main())
