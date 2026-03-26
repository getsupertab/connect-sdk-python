"""Matching helpers for customer-side license content blocks."""

import logging
import urllib.parse
from typing import Any

from connect.url_pattern import _score_path_pattern
from connect.customer.content_parser import _ContentBlock

LOGGER = logging.getLogger(__name__)


def _debug_log(enabled: bool, message: str, *args: Any) -> None:
    if enabled:
        LOGGER.debug(message, *args)


def _find_best_matching_content(
    content_blocks: list[_ContentBlock],
    resource_url: str,
    debug: bool = False,
) -> _ContentBlock | None:
    parsed = urllib.parse.urlparse(resource_url)
    host = parsed.netloc
    path = parsed.path
    if not parsed.scheme or not host:
        _debug_log(debug, "Cannot parse resource URL: %s", resource_url)
        return None

    _debug_log(
        debug, "Matching resource URL: %s (host=%s, path=%s)", resource_url, host, path
    )

    best_match: _ContentBlock | None = None
    best_specificity = -1

    for block in content_blocks:
        pattern = urllib.parse.urlparse(block.url_pattern)
        if not pattern.scheme or not pattern.netloc:
            _debug_log(
                debug, "Skipping block with invalid URL pattern: %s", block.url_pattern
            )
            continue

        if pattern.netloc != host:
            _debug_log(
                debug,
                "Skipping block: host mismatch (pattern=%s, resource=%s)",
                pattern.netloc,
                host,
            )
            continue

        if pattern.path == path:
            _debug_log(debug, "Exact match found: %s", block.url_pattern)
            return block

        specificity = _score_path_pattern(pattern.path or "/", path or "/")
        if specificity > best_specificity:
            best_specificity = specificity
            best_match = block

    if best_match is not None:
        _debug_log(
            debug,
            "Wildcard match found: %s (specificity=%s)",
            best_match.url_pattern,
            best_specificity,
        )
    else:
        _debug_log(debug, "No matching content block found for %s", resource_url)

    return best_match
