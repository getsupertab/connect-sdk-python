"""High-level merchant client for Supertab Connect."""

import json
from collections.abc import Mapping
from typing import ClassVar

from httpx import Request

from supertab_connect._version import _get_sdk_version
from supertab_connect.analytics.build_analytics_event import (
    BuildAnalyticsEventContext,
    build_analytics_event,
)
from supertab_connect.analytics.transport import (
    ANALYTICS_EVENTS_PATH,
    HttpAnalyticsTransport,
    NoopAnalyticsTransport,
)
from supertab_connect.analytics.transport import aclose_http_client as aclose_analytics_http_client
from supertab_connect.analytics.types import (
    TOKEN_OUTCOME_BY_REASON,
    AnalyticsTransport,
    Decision,
    FinalAction,
    TokenOutcome,
)
from supertab_connect.common import error_log
from supertab_connect.merchant.events import aclose_http_client as aclose_events_http_client
from supertab_connect.merchant.license import (
    build_block_result,
    build_signal_result,
    verify_and_record_event,
    verify_license_token,
)
from supertab_connect.merchant.jwks import aclose_http_client as aclose_jwks_http_client
from supertab_connect.merchant.status import verify_status_challenge
from supertab_connect.types import (
    BotDetector,
    EnforcementMode,
    HandleRequestContext,
    HandlerAction,
    HandlerResult,
    InvalidLicenseToken,
    LicenseTokenInvalidReason,
    RSLVerificationResult,
    SupertabConnectConfig,
)

_DEFAULT_BASE_URL = "https://api-connect.supertab.co"
# Analytics is served by the dedicated ingest service, not the API host. Kept separate from
# _base_url (mirroring set_base_url/get_base_url) so the relay can be pointed at a different
# host — or at localhost in dev — without moving token/JWKS/verify traffic.
_DEFAULT_ANALYTICS_BASE_URL = "https://ingest-connect.supertab.co"
_STATUS_PATH = "/.well-known/supertab/status"


class SupertabConnect:
    _instance: ClassVar["SupertabConnect | None"] = None
    _base_url: ClassVar[str] = _DEFAULT_BASE_URL
    _analytics_base_url: ClassVar[str] = _DEFAULT_ANALYTICS_BASE_URL

    def __new__(cls, config: SupertabConnectConfig, reset: bool = False) -> "SupertabConnect":
        if not reset and cls._instance is not None:
            if config.api_key != cls._instance.api_key:
                raise ValueError(
                    "Cannot create a new instance with different configuration. "
                    "Use reset_instance to clear the existing instance."
                )
            return cls._instance

        if reset and cls._instance is not None:
            cls.reset_instance()

        return super().__new__(cls)

    def __init__(self, config: SupertabConnectConfig, reset: bool = False) -> None:
        if getattr(self, "_initialized", False) and not reset:
            return

        if not config.api_key:
            raise ValueError("Missing required configuration: api_key is required")

        self.api_key = config.api_key
        self.enforcement = config.enforcement
        self.bot_detector = config.bot_detector
        self.debug = config.debug
        self._base_url_override = config.supertab_base_url
        self._analytics_enabled = config.analytics_enabled
        self._analytics_transport = self._build_analytics_transport(config)
        self._initialized = True
        type(self)._instance = self

    def _build_analytics_transport(self, config: SupertabConnectConfig) -> AnalyticsTransport:
        if config.analytics_transport is not None:
            return config.analytics_transport
        if not config.analytics_enabled:
            return NoopAnalyticsTransport()
        # Precedence: per-instance analytics_base_url > set_analytics_base_url() > the ingest default.
        analytics_base_url = config.analytics_base_url or type(self)._analytics_base_url
        return HttpAnalyticsTransport(
            url=f"{analytics_base_url.rstrip('/')}{ANALYTICS_EVENTS_PATH}",
            api_key=config.api_key,
            debug=config.debug,
        )

    @classmethod
    def reset_instance(cls) -> None:
        cls._instance = None

    @classmethod
    def set_base_url(cls, url: str) -> None:
        cls._base_url = url

    @classmethod
    def get_base_url(cls) -> str:
        return cls._base_url

    @classmethod
    def set_analytics_base_url(cls, url: str) -> None:
        """Override the analytics ingest relay host (e.g. for a non-prod environment or local
        development). Independent of set_base_url — token/JWKS/verify traffic is unaffected.
        Can also be set per-instance via the ``analytics_base_url`` config option.
        """
        cls._analytics_base_url = url

    @classmethod
    def get_analytics_base_url(cls) -> str:
        return cls._analytics_base_url

    @property
    def base_url(self) -> str:
        return self._base_url_override or type(self)._base_url

    async def aclose(self) -> None:
        await aclose_events_http_client()
        await aclose_jwks_http_client()
        await aclose_analytics_http_client()

    async def __aenter__(self) -> "SupertabConnect":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    @classmethod
    async def verify(
        cls,
        *,
        token: str,
        resource_url: str,
        base_url: str | None = None,
        debug: bool = False,
    ) -> RSLVerificationResult:
        result = await verify_license_token(
            token,
            request_url=resource_url,
            supertab_base_url=base_url or cls._base_url,
            debug=debug,
        )

        if not isinstance(result, InvalidLicenseToken):
            return RSLVerificationResult(valid=True)

        return RSLVerificationResult(valid=False, error=result.error)

    async def verify_and_record(
        self,
        *,
        token: str,
        resource_url: str,
        user_agent: str = "unknown",
        request_headers: Mapping[str, str] | None = None,
        debug: bool | None = None,
    ) -> RSLVerificationResult:
        result = await verify_and_record_event(
            token=token,
            url=resource_url,
            user_agent=user_agent,
            supertab_base_url=self.base_url,
            debug=self.debug if debug is None else debug,
            api_key=self.api_key,
            request_headers=request_headers,
        )

        if not isinstance(result, InvalidLicenseToken):
            return RSLVerificationResult(valid=True)

        return RSLVerificationResult(valid=False, error=result.error)

    def _detect_bot(self, request: Request) -> bool:
        detector: BotDetector | None = self.bot_detector
        if detector is None:
            return False

        return detector(request)

    def _emit_analytics(
        self,
        request: Request,
        context: HandleRequestContext | None,
        *,
        has_token: bool,
        token_outcome: TokenOutcome,
        final_action: FinalAction,
    ) -> None:
        try:
            event = build_analytics_event(
                request,
                Decision(
                    has_token=has_token,
                    token_outcome=token_outcome,
                    final_action=final_action,
                    enforcement_mode=self.enforcement,
                ),
                BuildAnalyticsEventContext(
                    source_cdn=context.source_cdn if context else None,
                    request_id=context.request_id if context else None,
                    client_ip=context.client_ip if context else None,
                    request_country=context.request_country if context else None,
                    request_asn=context.request_asn if context else None,
                    tls_fingerprint=context.tls_fingerprint if context else None,
                    cdn_signals=context.cdn_signals if context else None,
                ),
            )
            self._analytics_transport.emit(event)
        except Exception as error:  # noqa: BLE001 — analytics must never break request handling
            error_log(self.debug, f"failed to build/emit analytics event: {error}")

    @staticmethod
    def _request_origin(request: Request) -> str:
        """The scheme://host[:port] origin of the request, matching JS `URL.origin`.

        httpx normalizes away default ports (80/443), so they are never appended.
        """
        url = request.url
        origin = f"{url.scheme}://{url.host}"
        if url.port is not None:
            origin += f":{url.port}"
        return origin

    async def _handle_status_request(self, request: Request, context: HandleRequestContext | None) -> HandlerResult:
        """Answer the self-report status probe.

        Serves the live SDK config to a valid backend-signed challenge, else a minimal
        404. Short-circuits ahead of token verification, bot detection, and analytics.
        """
        headers = {"Content-Type": "application/json", "Cache-Control": "no-store"}
        auth = request.headers.get("authorization", "")
        token = auth[len("Bearer ") :] if auth.startswith("Bearer ") else ""
        ok = (
            await verify_status_challenge(
                token,
                expected_audience=self._request_origin(request),
                base_url=self.base_url,
                debug=self.debug,
            )
            if token
            else False
        )
        if not ok:
            return {
                "action": HandlerAction.RESPOND,
                "status": 404,
                "body": json.dumps({"supertab": True}),
                "headers": headers,
            }
        body = json.dumps(
            {
                "runtime": context.source_cdn if context else None,
                "component": {"kind": "python-sdk", "version": _get_sdk_version()},
                "enforcement": self.enforcement.value,
                "eventReporting": self._analytics_enabled,
            }
        )
        return {
            "action": HandlerAction.RESPOND,
            "status": 200,
            "body": body,
            "headers": headers,
        }

    async def handle_request(self, request: Request, context: HandleRequestContext | None = None) -> HandlerResult:
        # The self-report status probe short-circuits ahead of everything else: it is answered
        # directly (never forwarded to origin) and emits no analytics.
        if request.url.path == _STATUS_PATH:
            return await self._handle_status_request(request, context)

        auth = request.headers.get("authorization", "")
        token = None
        auth_parts = auth.split(None, 1)
        if len(auth_parts) == 2 and auth_parts[0].lower() == "license":
            token = auth_parts[1]
        has_token = token is not None
        url = str(request.url)
        user_agent = request.headers.get("user-agent", "unknown")

        # Token present → validate, regardless of bot detection — except in DISABLED
        # mode, which short-circuits to ALLOW without verification.
        if token:
            if self.enforcement is EnforcementMode.DISABLED:
                # DISABLED short-circuits to ALLOW without verifying the token, so we cannot
                # honestly claim "valid"; emit "not_validated" so it is not counted as licensed.
                self._emit_analytics(
                    request,
                    context,
                    has_token=has_token,
                    token_outcome="not_validated",
                    final_action="allow",
                )
                return {"action": HandlerAction.ALLOW}

            verification = await verify_and_record_event(
                token=token,
                url=url,
                user_agent=user_agent,
                supertab_base_url=self.base_url,
                debug=self.debug,
                api_key=self.api_key,
                request_headers=dict(request.headers.items()),
            )
            if isinstance(verification, InvalidLicenseToken):
                self._emit_analytics(
                    request,
                    context,
                    has_token=has_token,
                    token_outcome=TOKEN_OUTCOME_BY_REASON.get(verification.reason, "malformed"),
                    final_action="block",
                )
                return build_block_result(
                    reason=verification.reason,
                    error=verification.error,
                    request_url=url,
                )
            self._emit_analytics(
                request,
                context,
                has_token=has_token,
                token_outcome="valid",
                final_action="allow",
            )
            return {"action": HandlerAction.ALLOW}

        if not self._detect_bot(request):
            self._emit_analytics(
                request,
                context,
                has_token=has_token,
                token_outcome="absent",
                final_action="allow",
            )
            return {"action": HandlerAction.ALLOW}

        if self.enforcement is EnforcementMode.ENFORCE:
            self._emit_analytics(
                request,
                context,
                has_token=has_token,
                token_outcome="absent",
                final_action="block",
            )
            return build_block_result(
                reason=LicenseTokenInvalidReason.MISSING_TOKEN,
                error="Authorization header missing or malformed",
                request_url=url,
            )
        if self.enforcement is EnforcementMode.OBSERVE:
            self._emit_analytics(
                request,
                context,
                has_token=has_token,
                token_outcome="absent",
                final_action="observe",
            )
            return build_signal_result(url)
        self._emit_analytics(
            request,
            context,
            has_token=has_token,
            token_outcome="absent",
            final_action="allow",
        )
        return {"action": HandlerAction.ALLOW}
