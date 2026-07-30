"""Conformance runner for the Python SDK.

Reads one scenario JSON on stdin, drives the REAL SDK entrypoint for the
scenario's surface, and prints the normalized decision as JSON on stdout.
Mirrors connect-sdk-typescript/conformance/run.ts. The private selection
helpers imported below are exactly the ones obtain_license_token uses; the
customer-match surface has no single public entrypoint (same limitation the
spec notes for the TypeScript runner).
"""

import asyncio
import json
import re
import sys

import httpx

from supertab_connect import (
    EnforcementMode,
    SupertabConnect,
    SupertabConnectConfig,
    default_bot_detector,
    obtain_license_token,
    verify_license_token,
)
from supertab_connect.customer.content_matcher import _find_best_matching_content
from supertab_connect.customer.content_parser import _parse_content_elements
from supertab_connect.customer.token import _find_serverless_usage_content

MOCK_ORIGIN = "http://localhost:9999"


def _rsl_headers(headers: dict[str, str]) -> dict[str, str | None]:
    lower = {k.lower(): v for k, v in headers.items()}
    wa = re.search(r'error="([^"]+)"', lower.get("www-authenticate", ""))
    link = re.search(r"<([^>]+)>", lower.get("link", ""))
    return {
        "www_authenticate_error": wa.group(1) if wa else None,
        "link_license_url": link.group(1) if link else None,
        "x_rsl_status": lower.get("x-rsl-status"),
        "x_rsl_reason": lower.get("x-rsl-reason"),
    }


async def _verify(inp: dict) -> dict:
    res = await verify_license_token(
        inp.get("token", ""),
        request_url=inp["resource_url"],
        supertab_base_url=MOCK_ORIGIN,
        debug=False,
    )
    return {"valid": res.valid, "reason": None if res.valid else str(res.reason)}


async def _enforce(inp: dict) -> dict:
    SupertabConnect.set_base_url(MOCK_ORIGIN)
    inst = SupertabConnect(
        SupertabConnectConfig(
            api_key="test",
            enforcement=EnforcementMode(inp["enforcement"]),
            supertab_base_url=MOCK_ORIGIN,
            bot_detector=default_bot_detector if inp.get("use_default_bot_detector") else None,
        ),
        reset=True,
    )
    req = inp["request"]
    request = httpx.Request("GET", req["url"], headers=req.get("headers", {}))
    res = await inst.handle_request(request)
    return {
        "action": str(res["action"]),
        "status": res.get("status"),
        "headers": _rsl_headers(res.get("headers", {})),
    }


def _customer_match(inp: dict) -> dict:
    blocks = _parse_content_elements(inp["license_xml"], False)
    usage = inp.get("usage")
    if usage is not None:
        serverless = _find_serverless_usage_content(blocks, inp["resource_url"], usage, False)
        if serverless is not None:
            return {
                "matched": True,
                "matched_url_pattern": serverless.url_pattern,
                "token_server": None,
                "requires_token": False,
            }
    token_blocks = [b for b in blocks if b.server]
    best = _find_best_matching_content(token_blocks, inp["resource_url"], False)
    if best is None or best.server is None:
        return {"matched": False, "matched_url_pattern": None, "token_server": None, "requires_token": False}
    return {
        "matched": True,
        "matched_url_pattern": best.url_pattern,
        "token_server": best.server,
        "requires_token": True,
    }


async def _customer_obtain(inp: dict) -> dict:
    SupertabConnect.set_base_url(MOCK_ORIGIN)
    try:
        token = await obtain_license_token(
            client_id=inp["client_id"],
            client_secret=inp["client_secret"],
            resource_url=inp["resource_url"],
            usage=inp.get("usage"),
        )
    except Exception:
        return {"outcome": "error"}
    return {"outcome": "mint" if token else "no_token"}


async def _main() -> None:
    scn = json.loads(sys.stdin.read())
    surface = scn["surface"]
    inp = scn["input"]
    if surface == "verify":
        out = await _verify(inp)
    elif surface == "enforce":
        out = await _enforce(inp)
    elif surface == "customer-match":
        out = _customer_match(inp)
    elif surface == "customer-obtain":
        out = await _customer_obtain(inp)
    else:
        raise SystemExit(f"unhandled surface: {surface}")
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    asyncio.run(_main())
