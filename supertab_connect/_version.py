"""Internal SDK version helpers."""

from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version

_PACKAGE_NAME = "supertab-connect-sdk"
_SDK_NAME = "supertab-connect-sdk-python"


@lru_cache(maxsize=1)
def _get_sdk_user_agent() -> str:
    try:
        package_version = version(_PACKAGE_NAME)
    except PackageNotFoundError:
        package_version = "unknown"

    return f"{_SDK_NAME}/{package_version}"
