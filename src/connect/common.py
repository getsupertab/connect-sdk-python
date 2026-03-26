import logging
from typing import Any

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


def debug_log(enabled: bool, message: str, *args: Any) -> None:
    if enabled:
        LOGGER.debug(message, *args)


def error_log(enabled: bool, message: str, *args: Any) -> None:
    if enabled:
        LOGGER.error(message, *args)
