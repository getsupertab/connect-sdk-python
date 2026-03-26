"""Minimal example for generating a customer license token."""

import asyncio
import logging

from connect import obtain_license_token

logging.basicConfig(level=logging.DEBUG)


async def main() -> None:
    token = await obtain_license_token(
        client_id="your_client_id",
        client_secret="your_client_secret",
        resource_url="https://example.com",
        debug=True,
    )

    print(f"Generated license token: {token}")


if __name__ == "__main__":
    asyncio.run(main())
