"""Parsing helpers for customer-side license.xml content blocks."""

import logging
import re
from dataclasses import dataclass
from typing import Any

LOGGER = logging.getLogger(__name__)

_CONTENT_RE = re.compile(r"<content\s([^>]*)>([\s\S]*?)</content>", re.IGNORECASE)
_URL_RE = re.compile(r'url\s*=\s*"([^"]*)"', re.IGNORECASE)
_SERVER_RE = re.compile(r'server\s*=\s*"([^"]*)"', re.IGNORECASE)
_LICENSE_RE = re.compile(r"<license[^>]*>[\s\S]*?</license>", re.IGNORECASE)


@dataclass(frozen=True)
class _ContentBlock:
    url_pattern: str
    license_xml: str
    server: str


def _debug_log(enabled: bool, message: str, *args: Any) -> None:
    if enabled:
        LOGGER.debug(message, *args)


def _parse_content_elements(xml: str, debug: bool = False) -> list[_ContentBlock]:
    content_blocks: list[_ContentBlock] = []
    element_count = 0

    for match in _CONTENT_RE.finditer(xml):
        element_count += 1
        attrs, body = match.groups()
        url_match = _URL_RE.search(attrs)
        server_match = _SERVER_RE.search(attrs)
        license_match = _LICENSE_RE.search(body)

        if url_match and server_match and license_match:
            content_blocks.append(
                _ContentBlock(
                    url_pattern=url_match.group(1),
                    server=server_match.group(1),
                    license_xml=license_match.group(0),
                )
            )
            continue

        missing = ", ".join(
            value
            for value in (
                None if url_match else "url",
                None if server_match else "server",
                None if license_match else "<license>",
            )
            if value is not None
        )
        _debug_log(
            debug,
            "Skipping <content> element #%s: missing %s",
            element_count,
            missing,
        )

    _debug_log(
        debug,
        "Found %s <content> element(s), %s valid",
        element_count,
        len(content_blocks),
    )
    return content_blocks
