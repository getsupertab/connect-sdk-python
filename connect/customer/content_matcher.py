"""Matching helpers for customer-side license content blocks."""

import urllib.parse

from connect.common import debug_log
from connect.url_pattern import _score_path_pattern
from connect.customer.content_parser import _ContentBlock


def _find_best_matching_content(
    content_blocks: list[_ContentBlock],
    resource_url: str,
    debug: bool = False,
) -> _ContentBlock | None:
    parsed = urllib.parse.urlparse(resource_url)
    host = parsed.netloc
    path = parsed.path
    if not parsed.scheme or not host:
        debug_log(debug, f"Cannot parse resource URL: {resource_url}")
        return None

    debug_log(debug, f"Matching resource URL: {resource_url} (host={host}, path={path})")

    best_match: _ContentBlock | None = None
    best_specificity = -1

    for block in content_blocks:
        is_path_only = block.url_pattern.startswith("/")

        if is_path_only:
            pattern_path = block.url_pattern
        else:
            pattern = urllib.parse.urlparse(block.url_pattern)
            if not pattern.scheme or not pattern.netloc:
                debug_log(debug, f"Skipping block with invalid URL pattern: {block.url_pattern}")
                continue

            if pattern.netloc != host:
                debug_log(
                    debug,
                    f"Skipping block: host mismatch (pattern={pattern.netloc}, resource={host})",
                )
                continue

            pattern_path = pattern.path or "/"

        if pattern_path == path:
            debug_log(debug, f"Exact match found: {block.url_pattern}")
            return block

        specificity = _score_path_pattern(pattern_path, path or "/")
        if specificity > best_specificity:
            best_specificity = specificity
            best_match = block

    if best_match is not None:
        debug_log(
            debug,
            f"Wildcard match found: {best_match.url_pattern} (specificity={best_specificity})",
        )
    else:
        debug_log(debug, f"No matching content block found for {resource_url}")

    return best_match
