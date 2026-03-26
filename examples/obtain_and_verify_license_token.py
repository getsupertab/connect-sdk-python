"""Minimal example for obtaining and verifying a license token."""

import asyncio
import logging

from connect import obtain_license_token, verify_license_token

logging.basicConfig(level=logging.DEBUG)


async def main() -> None:
    token = obtain_license_token(
        client_id="your_client_id",
        client_secret="your_client_secret",
        resource_url="https://example.com",
        debug=True,
    )

    print(f"Generated license token: {token}")

    result = await verify_license_token(
        token,
        request_url="https://example.com",
        supertab_base_url="https://your-connect-instance.example.com",
        debug=True,
    )

    if result.valid:
        print(f"Token is VALID (license_id={result.license_id})")
    else:
        print(f"Token is INVALID: {result.reason} — {result.error}")


if __name__ == "__main__":
    asyncio.run(main())
