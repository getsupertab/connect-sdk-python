"""Utilities for matching resource URLs against license URL patterns."""

from __future__ import annotations

import re


def _score_path_pattern(pattern: str, path: str) -> int:
    """Return a specificity score for a matching path pattern, or ``-1``."""
    anchored = pattern.endswith("$")
    normalized_pattern = pattern[:-1] if anchored else pattern
    has_wildcard = "*" in normalized_pattern

    escaped = re.escape(normalized_pattern).replace(r"\*", ".*")

    if anchored:
        regex = rf"^{escaped}$"
    elif has_wildcard:
        regex = rf"^{escaped}"
    elif normalized_pattern == "/":
        regex = r"^/"
    else:
        regex = rf"^{escaped}(/|$)"

    if re.search(regex, path):
        return len(normalized_pattern.replace("*", ""))

    return -1


__all__ = []
