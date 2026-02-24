"""Search query parser and builder."""

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SearchQuery:
    """Parsed search query."""

    text: str | None = None
    file_type: str | None = None
    verdict: str | None = None
    tag: str | None = None
    severity: str | None = None
    ioc_type: str | None = None
    ioc_value: str | None = None
    date_from: str | None = None
    date_to: str | None = None
    page: int = 1
    per_page: int = 20


def parse_query(query_str: str) -> SearchQuery:
    """
    Parse search query string into structured query.

    Supports filters:
    - type:<file_type>
    - verdict:<verdict>
    - tag:<tag>
    - severity:<severity>
    - ioc:<type>:<value>
    - from:<date>
    - to:<date>

    Args:
        query_str: Query string

    Returns:
        Parsed SearchQuery
    """
    result = SearchQuery()
    remaining = query_str

    # Pattern for filters
    filter_pattern = re.compile(r'(\w+):(\S+)')

    for match in filter_pattern.finditer(query_str):
        key = match.group(1).lower()
        value = match.group(2)

        if key == "type":
            result.file_type = value
        elif key == "verdict":
            result.verdict = value
        elif key == "tag":
            result.tag = value
        elif key == "severity":
            result.severity = value
        elif key == "ioc":
            # Parse ioc:type:value or ioc:value
            if ":" in value:
                ioc_parts = value.split(":", 1)
                result.ioc_type = ioc_parts[0]
                result.ioc_value = ioc_parts[1]
            else:
                result.ioc_value = value
        elif key == "from":
            result.date_from = value
        elif key == "to":
            result.date_to = value

    # Remove filters from remaining text
    remaining = filter_pattern.sub("", remaining).strip()
    result.text = remaining if remaining else None

    return result


def build_search_filters(query: SearchQuery) -> dict[str, Any]:
    """
    Build search filters from parsed query.

    Args:
        query: Parsed SearchQuery

    Returns:
        Dictionary of filters
    """
    filters = {}

    if query.file_type:
        filters["file_type"] = query.file_type

    if query.verdict:
        filters["verdict"] = query.verdict

    if query.tag:
        filters["tag"] = query.tag

    if query.severity:
        filters["severity"] = query.severity

    if query.ioc_type:
        filters["ioc_type"] = query.ioc_type

    if query.ioc_value:
        filters["ioc_value"] = query.ioc_value

    if query.date_from:
        filters["date_from"] = query.date_from

    if query.date_to:
        filters["date_to"] = query.date_to

    return filters
