"""Core types for the Supertab Connect SDK."""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal, NotRequired, TypeAlias, TypedDict

from httpx import Request


class EnforcementMode(StrEnum):
    DISABLED = "disabled"
    SOFT = "soft"
    STRICT = "strict"


class LicenseTokenInvalidReason(StrEnum):
    MISSING_TOKEN = "missing_license_token"
    INVALID_HEADER = "invalid_license_header"
    INVALID_ALG = "invalid_license_algorithm"
    INVALID_PAYLOAD = "invalid_license_payload"
    INVALID_ISSUER = "invalid_license_issuer"
    SIGNATURE_VERIFICATION_FAILED = "license_signature_verification_failed"
    EXPIRED = "license_token_expired"
    INVALID_AUDIENCE = "invalid_license_audience"
    SERVER_ERROR = "server_error"


class HandlerAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


class UsageType(StrEnum):
    ALL = "all"
    SEARCH = "search"
    AI_ALL = "ai-all"
    AI_TRAIN = "ai-train"
    AI_INDEX = "ai-index"
    AI_INPUT = "ai-input"


BotDetector: TypeAlias = Callable[[Request], bool]


@dataclass(frozen=True)
class SupertabConnectConfig:
    api_key: str
    enforcement: EnforcementMode = EnforcementMode.SOFT
    supertab_base_url: str | None = None
    bot_detector: BotDetector | None = None
    debug: bool = False


class AllowHandlerResult(TypedDict):
    action: Literal[HandlerAction.ALLOW]
    headers: NotRequired[dict[str, str]]


class BlockHandlerResult(TypedDict):
    action: Literal[HandlerAction.BLOCK]
    status: int
    body: str
    headers: dict[str, str]


HandlerResult: TypeAlias = AllowHandlerResult | BlockHandlerResult


@dataclass(frozen=True)
class ValidLicenseToken:
    valid: bool = field(default=True, init=False)
    license_id: str | None
    payload: dict[str, Any]


@dataclass(frozen=True)
class InvalidLicenseToken:
    valid: bool = field(default=False, init=False)
    reason: LicenseTokenInvalidReason
    error: str
    license_id: str | None = None


LicenseTokenVerificationResult = ValidLicenseToken | InvalidLicenseToken


@dataclass(frozen=True)
class RSLVerificationResult:
    valid: bool
    error: str | None = None
