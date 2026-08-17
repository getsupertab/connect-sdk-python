import pytest

from supertab_connect.customer.content_matcher import (
    _ContentBlock,
    _find_best_matching_content,
)
from supertab_connect.customer.content_parser import _parse_content_elements
from supertab_connect.url_pattern import score_path_pattern

from tests.customer.conftest import SAMPLE_XML


@pytest.mark.parametrize(
    ("resource_url", "expected_pattern"),
    [
        ("http://127.0.0.1:7676/article/", "http://127.0.0.1:7676/article/*"),
        ("http://127.0.0.1:7676/article/foo", "http://127.0.0.1:7676/article/*"),
        ("http://127.0.0.1:7676/other", "http://127.0.0.1:7676/*"),
        ("http://127.0.0.1:7676/content/article", "http://127.0.0.1:7676/content"),
        ("http://127.0.0.1:7676/content-other", "http://127.0.0.1:7676/*"),
    ],
)
def test_find_best_matching_content_prefers_the_most_specific_pattern(
    resource_url: str, expected_pattern: str
) -> None:
    """Selects the content block with the most specific URL pattern."""
    blocks = _parse_content_elements(SAMPLE_XML)

    match = _find_best_matching_content(blocks, resource_url)

    assert match is not None
    assert match.url_pattern == expected_pattern


def test_find_best_matching_content_rejects_different_host() -> None:
    """Returns None when the resource host doesn't match any pattern."""
    blocks = _parse_content_elements(SAMPLE_XML)

    assert _find_best_matching_content(blocks, "http://other-host:7676/article/foo") is None


def test_find_best_matching_content_rejects_different_port() -> None:
    """Returns None when the resource port doesn't match any pattern."""
    blocks = _parse_content_elements(SAMPLE_XML)

    assert _find_best_matching_content(blocks, "http://127.0.0.1:9999/article/foo") is None


def test_find_best_matching_content_skips_invalid_patterns() -> None:
    """Invalid URL patterns are skipped; valid ones still match."""
    blocks = [
        _ContentBlock(url_pattern="not-a-valid-url", server="http://x", license_xml="<license/>"),
        *_parse_content_elements(SAMPLE_XML),
    ]

    match = _find_best_matching_content(blocks, "http://127.0.0.1:7676/article/foo")

    assert match is not None
    assert match.url_pattern == "http://127.0.0.1:7676/article/*"


def test_find_best_matching_content_handles_port_specific_host_matching() -> None:
    """Matching is port-specific: localhost:3000 doesn't match localhost:3001."""
    blocks = [
        _ContentBlock(
            url_pattern="http://localhost:3000/*",
            server="http://localhost:4000",
            license_xml="<license/>",
        )
    ]

    assert _find_best_matching_content(blocks, "http://localhost:3000/page") is not None
    assert _find_best_matching_content(blocks, "http://localhost:3001/page") is None


def test_find_best_matching_content_matches_path_only_pattern() -> None:
    """Path-only patterns (starting with /) match regardless of host."""
    blocks = [
        _ContentBlock(url_pattern="/article/*", server="http://127.0.0.1:8787", license_xml="<license/>"),
    ]

    match = _find_best_matching_content(blocks, "http://127.0.0.1:7676/article/foo")

    assert match is not None
    assert match.url_pattern == "/article/*"


def test_find_best_matching_content_exact_path_only_wins_over_wildcard() -> None:
    """Exact path-only match beats a path-only wildcard."""
    blocks = [
        _ContentBlock(url_pattern="/*", server="http://127.0.0.1:8787", license_xml="<license/>"),
        _ContentBlock(url_pattern="/article/foo", server="http://127.0.0.1:8787", license_xml="<license/>"),
    ]

    match = _find_best_matching_content(blocks, "http://127.0.0.1:7676/article/foo")

    assert match is not None
    assert match.url_pattern == "/article/foo"


def test_find_best_matching_content_path_only_matches_any_host() -> None:
    """Path-only patterns match any host."""
    blocks = [
        _ContentBlock(url_pattern="/article/*", server="http://127.0.0.1:8787", license_xml="<license/>"),
    ]

    match = _find_best_matching_content(blocks, "http://totally-different-host.com/article/foo")

    assert match is not None
    assert match.url_pattern == "/article/*"


def test_find_best_matching_content_mixes_full_url_and_path_only() -> None:
    """Path-only pattern with higher specificity wins over full-URL pattern."""
    blocks = [
        _ContentBlock(url_pattern="http://127.0.0.1:7676/*", server="http://127.0.0.1:8787", license_xml="<license/>"),
        _ContentBlock(url_pattern="/article/*", server="http://127.0.0.1:8787", license_xml="<license/>"),
    ]

    match = _find_best_matching_content(blocks, "http://127.0.0.1:7676/article/foo")

    assert match is not None
    assert match.url_pattern == "/article/*"


def test_find_best_matching_content_matches_root_url_without_trailing_slash() -> None:
    """A resource URL with no path (e.g. http://host) matches a / pattern."""
    blocks = [
        _ContentBlock(url_pattern="/", server="http://127.0.0.1:8787", license_xml="<license/>"),
    ]

    match = _find_best_matching_content(blocks, "http://127.0.0.1:7676")

    assert match is not None
    assert match.url_pattern == "/"


def test_find_best_matching_content_returns_none_for_empty_blocks() -> None:
    """Returns None when no content blocks are provided."""
    assert _find_best_matching_content([], "http://example.com/page") is None


def test_find_best_matching_content_keeps_path_params_in_the_resource_url() -> None:
    """RFC 2396 path params stay in the resource path, so /news;v=1 does not match /news."""
    blocks = [
        _ContentBlock(url_pattern="/news", server="http://127.0.0.1:8787", license_xml="<license/>"),
    ]

    assert _find_best_matching_content(blocks, "http://127.0.0.1:7676/news;v=1") is None
    assert _find_best_matching_content(blocks, "http://127.0.0.1:7676/news") is not None


def test_find_best_matching_content_keeps_path_params_in_the_url_pattern() -> None:
    """Path params stay in the pattern path too, so a /news;v=1 pattern does not match /news."""
    blocks = [
        _ContentBlock(
            url_pattern="http://127.0.0.1:7676/news;v=1",
            server="http://127.0.0.1:8787",
            license_xml="<license/>",
        ),
    ]

    assert _find_best_matching_content(blocks, "http://127.0.0.1:7676/news") is None

    match = _find_best_matching_content(blocks, "http://127.0.0.1:7676/news;v=1")
    assert match is not None
    assert match.url_pattern == "http://127.0.0.1:7676/news;v=1"


@pytest.mark.parametrize(
    "resource_url",
    [
        "http://127.0.0.1:7676/content",
        "http://127.0.0.1:7676/content?v=1",
        "http://127.0.0.1:7676/content#section",
    ],
)
def test_find_best_matching_content_unchanged_without_path_params(resource_url: str) -> None:
    """Resource URLs without path params match exactly as before."""
    blocks = _parse_content_elements(SAMPLE_XML)

    match = _find_best_matching_content(blocks, resource_url)

    assert match is not None
    assert match.url_pattern == "http://127.0.0.1:7676/content"


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("/content", "/content", 8),
        ("/content", "/content/article", 8),
        ("/content", "/content-other", -1),
        ("/", "/anything", 1),
        ("/content/*", "/content/article", 9),
        ("/content/*", "/content/a/b", 9),
        ("/content/*", "/other", -1),
        ("/content/*/article", "/content/news/article", 17),
        ("/content/*/article", "/content/a/b/article", 17),
        ("/content/*/article", "/content/news/other", -1),
        ("/content/*/article", "/content/news/article/comments", 17),
        ("/*", "/anything", 1),
        ("/*", "/a/b/c", 1),
        ("/page$", "/page", 5),
        ("/page$", "/page/more", -1),
        ("/content/*/article$", "/content/news/article", 17),
        ("/content/*/article$", "/content/news/article/extra", -1),
        ("/pa$ge", "/pa$ge", 6),
        ("/page.html$", "/page.html", 10),
        ("/page.html$", "/pagexhtml", -1),
    ],
)
def test_score_path_pattern_handles_all_cases(pattern: str, path: str, expected: int) -> None:
    """Pattern scoring returns expected specificity for each pattern/path pair."""
    assert score_path_pattern(pattern, path) == expected


def test_score_path_pattern_prefers_more_literal_characters() -> None:
    """More literal characters in the pattern yield a higher score."""
    path = "/content/news/article"

    broad = score_path_pattern("/*", path)
    mid = score_path_pattern("/content/*", path)
    specific = score_path_pattern("/content/*/article", path)

    assert broad < mid < specific
