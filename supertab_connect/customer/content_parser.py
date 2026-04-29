"""Parsing helpers for customer-side license.xml content blocks."""

from dataclasses import dataclass
from xml.etree import ElementTree

from supertab_connect.common import debug_log

_RSL_NAMESPACE = "https://rslstandard.org/rsl"
_NS = {"rsl": _RSL_NAMESPACE}
ElementTree.register_namespace("", _RSL_NAMESPACE)


@dataclass(frozen=True)
class _ContentBlock:
    url_pattern: str
    license_xml: str
    server: str | None = None


def _clean_attribute(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _parse_content_elements(xml: str, debug: bool = False) -> list[_ContentBlock]:
    """Parse valid ``<content>`` elements from license XML into content block records."""
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as error:
        debug_log(debug, f"Failed to parse license.xml as XML: {error}")
        return []

    content_blocks: list[_ContentBlock] = []

    # Find namespaced <content> first, fall back to non-namespaced if necessary
    content_elements = root.findall("rsl:content", namespaces=_NS)
    if not len(content_elements):
        content_elements = root.findall("content", namespaces=_NS)

    for element_count, content_el in enumerate(content_elements, start=1):
        url_pattern = _clean_attribute(content_el.attrib.get("url"))
        server = _clean_attribute(content_el.attrib.get("server"))

        license_el = content_el.find("rsl:license", namespaces=_NS)
        if license_el is None:
            license_el = content_el.find("license", namespaces=_NS)

        license_xml = ElementTree.tostring(license_el, encoding="unicode").strip() if license_el is not None else None

        if url_pattern and license_xml:
            content_blocks.append(
                _ContentBlock(
                    url_pattern=url_pattern,
                    server=server,
                    license_xml=license_xml,
                )
            )
            continue

        missing = ", ".join(
            value
            for value in (
                None if url_pattern else "url",
                None if license_xml else "<license>",
            )
            if value is not None
        )
        debug_log(
            debug,
            f"Skipping <content> element #{element_count}: missing {missing}",
        )

    debug_log(
        debug,
        f"Found {len(content_elements)} <content> element(s), {len(content_blocks)} valid",
    )
    return content_blocks
