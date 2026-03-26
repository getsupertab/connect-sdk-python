"""Minimal example for generating a customer license token."""

import logging

from connect import obtain_license_token

logging.basicConfig(level=logging.DEBUG)


def main() -> None:
    token = obtain_license_token(
        client_id="stc.549d1c48-90b3-47b7-8ff8-b6bb8ec02614",
        client_secret="stc_secret_D_EuYUw3PLBy6TgmmXVcjDKHoQyaAHhFBnMi4kPfIvc",
        resource_url="https://d1klfqmhp1tqhv.cloudfront.net/",
        debug=True,
    )

    print(f"Generated license token: {token}")


if __name__ == "__main__":
    main()
