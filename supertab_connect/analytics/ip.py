"""Client-IP normalization (mirrors TS `analytics/ip.ts`).

IPv4 addresses are mapped to their IPv6-mapped form (``::ffff:<v4>``); valid IPv6
addresses pass through unchanged; anything else collapses to the unspecified address.
"""

import ipaddress

UNSPECIFIED = "::"


def normalize_client_ip(raw: str | None) -> str:
    if not raw:
        return UNSPECIFIED
    trimmed = raw.strip()
    if not trimmed:
        return UNSPECIFIED

    try:
        parsed = ipaddress.ip_address(trimmed)
    except ValueError:
        return UNSPECIFIED

    if parsed.version == 4:
        return f"::ffff:{trimmed}"
    # IPv6 passes through unchanged (the original textual form, not a re-compressed one).
    return trimmed
