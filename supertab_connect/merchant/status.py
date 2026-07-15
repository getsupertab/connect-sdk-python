"""Verification of backend-signed status-probe challenges.

Powers the self-report endpoint (`/.well-known/supertab/status`): the backend signs a
short-lived challenge JWT scoped to the site origin, and the SDK proves it is live and
reports its config only when that challenge verifies. Mirrors the TS SDK `status.ts`.
"""

from typing import cast

import jwt
import jwt.algorithms
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from supertab_connect.common import debug_log, error_log
from supertab_connect.exceptions import JwksKeyNotFoundError
from supertab_connect.merchant.jwks import _find_key_by_kid, clear_jwks_cache, fetch_platform_jwks

_STATUS_PROBE_PURPOSE = "status-probe"
# Clock skew tolerance for the challenge's exp/iat, matching the TS SDK's 5s.
_CLOCK_TOLERANCE_SECONDS = 5


async def verify_status_challenge(
    token: str,
    *,
    expected_audience: str,
    base_url: str,
    debug: bool = False,
) -> bool:
    """Verify a backend-signed status-probe challenge.

    Returns True only when the token is a valid ES256 JWT signed by the platform JWKS,
    scoped to ``expected_audience`` (the site origin), and carrying ``purpose:
    status-probe``. Any failure resolves to False rather than raising — the endpoint
    falls back to a minimal 404. A stale-key miss triggers one JWKS cache refresh + retry.
    """

    async def _verify() -> bool:
        jwks = await fetch_platform_jwks(base_url, debug=debug)
        header = jwt.get_unverified_header(token)
        jwk_key = _find_key_by_kid(jwks, header.get("kid"))
        public_key = cast(EllipticCurvePublicKey, jwt.algorithms.ECAlgorithm.from_jwk(jwk_key))
        payload = jwt.decode(
            token,
            key=public_key,
            algorithms=["ES256"],
            audience=expected_audience,
            leeway=_CLOCK_TOLERANCE_SECONDS,
        )
        return payload.get("purpose") == _STATUS_PROBE_PURPOSE

    try:
        return await _verify()
    except JwksKeyNotFoundError:
        debug_log(debug, "Key not found in cached JWKS, clearing cache and retrying...")
        clear_jwks_cache()
        try:
            return await _verify()
        except Exception as error:  # noqa: BLE001 — status probe fails closed to a minimal 404
            error_log(debug, f"Status challenge verification failed after JWKS refresh: {error}")
            return False
    except Exception as error:  # noqa: BLE001 — status probe fails closed to a minimal 404
        error_log(debug, f"Status challenge verification failed: {error}")
        return False
