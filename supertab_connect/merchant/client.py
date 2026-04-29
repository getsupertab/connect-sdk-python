"""High-level merchant client for Supertab Connect."""

from collections.abc import Mapping
from typing import ClassVar

from httpx import Request

from supertab_connect.merchant.events import aclose_http_client as aclose_events_http_client
from supertab_connect.merchant.license import (
    build_block_result,
    build_signal_result,
    verify_and_record_event,
    verify_license_token,
)
from supertab_connect.merchant.jwks import aclose_http_client as aclose_jwks_http_client
from supertab_connect.types import (
    BotDetector,
    EnforcementMode,
    HandlerAction,
    HandlerResult,
    InvalidLicenseToken,
    LicenseTokenInvalidReason,
    RSLVerificationResult,
    SupertabConnectConfig,
)

_DEFAULT_BASE_URL = "https://api-connect.supertab.co"


class SupertabConnect:
    _instance: ClassVar["SupertabConnect | None"] = None
    _base_url: ClassVar[str] = _DEFAULT_BASE_URL

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
        self._initialized = True
        type(self)._instance = self

    @classmethod
    def reset_instance(cls) -> None:
        cls._instance = None

    @classmethod
    def set_base_url(cls, url: str) -> None:
        cls._base_url = url

    @classmethod
    def get_base_url(cls) -> str:
        return cls._base_url

    @property
    def base_url(self) -> str:
        return self._base_url_override or type(self)._base_url

    async def aclose(self) -> None:
        await aclose_events_http_client()
        await aclose_jwks_http_client()

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

    async def handle_request(self, request: Request) -> HandlerResult:
        auth = request.headers.get("authorization", "")
        token = None
        auth_parts = auth.split(None, 1)
        if len(auth_parts) == 2 and auth_parts[0].lower() == "license":
            token = auth_parts[1]
        url = str(request.url)
        user_agent = request.headers.get("user-agent", "unknown")

        if token:
            if self.enforcement is EnforcementMode.DISABLED:
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
                return build_block_result(
                    reason=verification.reason,
                    error=verification.error,
                    request_url=url,
                )
            return {"action": HandlerAction.ALLOW}

        if not self._detect_bot(request):
            return {"action": HandlerAction.ALLOW}

        if self.enforcement is EnforcementMode.STRICT:
            return build_block_result(
                reason=LicenseTokenInvalidReason.MISSING_TOKEN,
                error="Authorization header missing or malformed",
                request_url=url,
            )
        if self.enforcement is EnforcementMode.SOFT:
            return build_signal_result(url)
        return {"action": HandlerAction.ALLOW}
