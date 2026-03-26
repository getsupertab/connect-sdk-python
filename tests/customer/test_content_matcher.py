import pytest

from connect.customer.content_matcher import (
    _ContentBlock,
    _find_best_matching_content,
)
from connect.customer.content_parser import _parse_content_elements
from connect.url_pattern import _score_path_pattern

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
    blocks = _parse_content_elements(SAMPLE_XML)

    match = _find_best_matching_content(blocks, resource_url)

    assert match is not None
    assert match.url_pattern == expected_pattern


def test_find_best_matching_content_rejects_different_host() -> None:
    blocks = _parse_content_elements(SAMPLE_XML)

    assert _find_best_matching_content(blocks, "http://other-host:7676/article/foo") is None


def test_find_best_matching_content_rejects_different_port() -> None:
    blocks = _parse_content_elements(SAMPLE_XML)

    assert _find_best_matching_content(blocks, "http://127.0.0.1:9999/article/foo") is None


def test_find_best_matching_content_skips_invalid_patterns() -> None:
    blocks = [
        _ContentBlock(url_pattern="not-a-valid-url", server="http://x", license_xml="<license/>"),
        *_parse_content_elements(SAMPLE_XML),
    ]

    match = _find_best_matching_content(blocks, "http://127.0.0.1:7676/article/foo")

    assert match is not None
    assert match.url_pattern == "http://127.0.0.1:7676/article/*"


def test_find_best_matching_content_handles_port_specific_host_matching() -> None:
    blocks = [
        _ContentBlock(
            url_pattern="http://localhost:3000/*",
            server="http://localhost:4000",
            license_xml="<license/>",
        )
    ]

    assert _find_best_matching_content(blocks, "http://localhost:3000/page") is not None
    assert _find_best_matching_content(blocks, "http://localhost:3001/page") is None


def test_find_best_matching_content_returns_none_for_empty_blocks() -> None:
    assert _find_best_matching_content([], "http://example.com/page") is None


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
    assert _score_path_pattern(pattern, path) == expected


def test_score_path_pattern_prefers_more_literal_characters() -> None:
    path = "/content/news/article"

    broad = _score_path_pattern("/*", path)
    mid = _score_path_pattern("/content/*", path)
    specific = _score_path_pattern("/content/*/article", path)

    assert broad < mid < specific
