"""Internal SDK version helpers."""

from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version

_PACKAGE_NAME = "supertab-connect-sdk"
_SDK_NAME = "supertab-connect-sdk-python"


@lru_cache(maxsize=1)
def _get_sdk_version() -> str:
    try:
        return version(_PACKAGE_NAME)
    except PackageNotFoundError:
        return "unknown"


@lru_cache(maxsize=1)
def _get_sdk_user_agent() -> str:
    return f"{_SDK_NAME}/{_get_sdk_version()}"
