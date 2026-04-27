"""Example of custom request handling with `SupertabConnect.verify_and_record`."""

import asyncio
import logging

from connect import EnforcementMode, SupertabConnect, SupertabConnectConfig

logging.basicConfig(level=logging.DEBUG)

REQUEST_URL = "https://example.com/premium/article"


async def main() -> None:
    client = SupertabConnect(
        SupertabConnectConfig(
            api_key="your_api_key",
            enforcement=EnforcementMode.SOFT,
            debug=True,
        )
    )

    token = "your.jwt.token"
    user_agent = "Mozilla/5.0"
    request_headers = {
        "Accept": "text/html",
        "Accept-Language": "en-US",
        "X-Forwarded-For": "203.0.113.1",
    }

    async with client:
        result = await client.verify_and_record(
            token=token,
            resource_url=REQUEST_URL,
            user_agent=user_agent,
            request_headers=request_headers,
        )

    if not result.valid:
        print(f"DENY access: {result.error}")
        return

    print("ALLOW access")


if __name__ == "__main__":
    asyncio.run(main())
