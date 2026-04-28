import pytest

from connect.customer.content_parser import _parse_content_elements

from tests.customer.conftest import SAMPLE_XML


def test_parse_content_elements_parses_multiple_blocks() -> None:
    """Parses all valid content blocks from a multi-content license.xml."""
    blocks = _parse_content_elements(SAMPLE_XML)

    assert len(blocks) == 3
    assert blocks[0].url_pattern == "http://127.0.0.1:7676/*"
    assert blocks[0].server == "http://127.0.0.1:8787"
    assert blocks[0].license_xml.startswith('<license xmlns="https://rslstandard.org/rsl"')

    assert blocks[1].url_pattern == "http://127.0.0.1:7676/article/*"
    assert blocks[2].url_pattern == "http://127.0.0.1:7676/content"


@pytest.mark.parametrize(
    "xml",
    [
        # Missing <license> child inside an otherwise well-formed <content> block.
        """
        <content url="http://example.com/*" server="http://example.com">
          <p>No license here</p>
        </content>
        """,
        # Missing required url attribute on the <content> element.
        """
        <content server="http://example.com">
          <license type="test"><link /></license>
        </content>
        """,
        # Reject whitespace-only attributes that are present but effectively empty.
        """
        <content url="   " server="http://example.com">
          <license type="test"><link /></license>
        </content>
        """,
        # XML with no <content> elements should produce no content blocks.
        "<root><other>stuff</other></root>",
        # Malformed XML should fail parsing cleanly and return no content blocks.
        "<rsl><content>",
    ],
)
def test_parse_content_elements_skips_invalid_content(xml: str) -> None:
    """Invalid or incomplete content elements produce no blocks."""
    assert _parse_content_elements(xml) == []


def test_parse_content_elements_keeps_serverless_content() -> None:
    """Serverless content is valid for usage grants."""
    xml = """
    <rsl>
      <content url="http://example.com/*">
        <license type="test"><link /></license>
      </content>
    </rsl>
    """

    blocks = _parse_content_elements(xml)

    assert len(blocks) == 1
    assert blocks[0].url_pattern == "http://example.com/*"
    assert blocks[0].server is None
    assert blocks[0].license_xml == '<license type="test"><link /></license>'
