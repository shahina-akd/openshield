from datetime import datetime, timezone

import httpx
import pytest
import respx

from openshield.collect.osv import (
    MAX_PAGES,
    OSV_QUERY_URL,
    collect_osv,
    fixed_versions,
    parse_vulns,
    severity_of,
)
from openshield.models import PackageRef, SourceRef

TS = datetime(2026, 1, 1, tzinfo=timezone.utc)
SOURCE = SourceRef(name="osv", fetched_at=TS)
REF = PackageRef(name="axios", version="1.7.2")


def _vuln(**fields) -> dict:
    """A minimal OSV record. Hand-written literal dicts, not saved API
    responses -- M1 Step 1.4 caches raw responses precisely because parsers
    change weekly, and an eight-line fixture that isolates one extraction path
    localises a failure in a way a 400-line real advisory does not."""
    return {"id": "GHSA-test", **fields}

from openshield.collect.osv import _word

@pytest.mark.parametrize("value,expected", [
    ("HIGH", "high"), ("high", "high"), ("  Moderate  ", "moderate"),
    ("MEDIUM", "moderate"),          # CVSS's word for GHSA's "moderate"
    ("SEVERE", None), ("", None), (None, None), (7, None), ({"s": "high"}, None),
])
def test_word(value, expected):
    assert _word(value) == expected