import pytest

from connect.customer.content_parser import _ContentBlock, _parse_content_elements

from tests.customer.conftest import SAMPLE_XML


def test_parse_content_elements_parses_multiple_blocks() -> None:
    blocks = _parse_content_elements(SAMPLE_XML)

    assert len(blocks) == 3
    assert blocks[0].url_pattern == "http://127.0.0.1:7676/*"
    assert blocks[0].server == "http://127.0.0.1:8787"
    assert "<license" in blocks[0].license_xml

    assert blocks[1].url_pattern == "http://127.0.0.1:7676/article/*"
    assert blocks[2].url_pattern == "http://127.0.0.1:7676/content"


@pytest.mark.parametrize(
    ("xml", "expected"),
    [
        (
            """
            <content url="http://example.com/*" server="http://example.com">
              <p>No license here</p>
            </content>
            """,
            [],
        ),
        (
            """
            <content server="http://example.com">
              <license type="test"><link /></license>
            </content>
            """,
            [],
        ),
        (
            """
            <content url="http://example.com/*">
              <license type="test"><link /></license>
            </content>
            """,
            [],
        ),
        ("<root><other>stuff</other></root>", []),
    ],
)
def test_parse_content_elements_skips_invalid_content(
    xml: str, expected: list[_ContentBlock]
) -> None:
    assert _parse_content_elements(xml) == expected
