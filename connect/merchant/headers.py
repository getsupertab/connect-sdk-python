"""Header helpers for merchant event analytics."""

from collections.abc import Mapping

_DENIED_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-amz-security-token",
    "user-agent",
    "x-license-auth",
}


def to_event_properties(
    headers: Mapping[str, str],
) -> dict[str, str]:
    """Convert request headers into event properties."""
    result: dict[str, str] = {}

    for key, value in headers.items():
        normalized_key = key.lower()
        if normalized_key in _DENIED_HEADERS:
            continue
        result[f"h_{normalized_key}"] = value

    return result
