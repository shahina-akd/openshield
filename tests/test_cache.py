"""Tests for cache.py, in isolation and as wired into collect().

The `isolated_cache` fixture gives each test its own empty cache database.
"""
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from openshield import cache
from openshield.collect import collect
from openshield.models import PackageRef

REF = PackageRef(name="axios", version="1.7.2")
REF2 = PackageRef(name="axios", version="1.7.3")
PAYLOAD = {"vulns": [{"id": "GHSA-x"}]}

OSV_URL = "https://api.osv.dev/v1/query"
REGISTRY_URL = "https://registry.npmjs.org/axios"
DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-week/axios"


def registry_time(days_ago: int) -> str:
    moment = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


PACKUMENT = {
    "name": "axios",
    "maintainers": [{"name": "a"}],
    "versions": {"1.7.2": {"license": "MIT"}, "1.7.3": {"license": "MIT"}},
    "time": {"1.7.2": registry_time(30), "1.7.3": registry_time(10)},
}


@pytest.fixture
def no_github(monkeypatch):
    """Skips GitHub so only OSV and npm are exercised."""
    monkeypatch.delenv("OPENSHIELD_GITHUB_TOKEN", raising=False)


def mock_all():
    """Mock every host; return the OSV route for call counting."""
    osv = respx.post(OSV_URL).respond(200, json=PAYLOAD)
    respx.get(REGISTRY_URL).respond(200, json=PACKUMENT)
    respx.get(DOWNLOADS_URL).respond(200, json={"downloads": 51_000_000})
    return osv


# ------------------------------------------------------------------------------
# 1. Keys
# ------------------------------------------------------------------------------

def test_the_key_is_source_plus_canonical_identity():
    assert cache.key_for("osv", "npm:axios@1.7.2") == "osv:npm:axios@1.7.2"


def test_two_sources_never_share_an_entry():
    cache.put("osv", REF.canonical, {"a": 1})
    cache.put("npm-registry", REF.canonical, {"b": 2})
    assert cache.get("osv", REF.canonical) == {"a": 1}
    assert cache.get("npm-registry", REF.canonical) == {"b": 2}


def test_two_versions_never_share_an_entry():
    cache.put("osv", REF.canonical, {"v": "1.7.2"})
    cache.put("osv", REF2.canonical, {"v": "1.7.3"})
    assert cache.get("osv", REF.canonical) == {"v": "1.7.2"}
    assert cache.get("osv", REF2.canonical) == {"v": "1.7.3"}


def test_a_miss_is_None_not_an_empty_dict():
    """{} is a valid OSV payload meaning no known vulnerabilities."""
    assert cache.get("osv", "npm:nothing@1.0.0") is None


# ------------------------------------------------------------------------------
# 2. Round trip and TTL
# ------------------------------------------------------------------------------

def test_a_payload_survives_a_round_trip():
    cache.put("osv", REF.canonical, PAYLOAD)
    assert cache.get("osv", REF.canonical) == PAYLOAD


def test_a_second_put_replaces_the_first():
    cache.put("osv", REF.canonical, {"v": 1})
    cache.put("osv", REF.canonical, {"v": 2})
    assert cache.get("osv", REF.canonical) == {"v": 2}


def test_an_entry_older_than_the_ttl_is_a_miss():
    cache.put("osv", REF.canonical, PAYLOAD)
    assert cache.get("osv", REF.canonical, ttl_hours=0) is None


def test_an_entry_inside_the_ttl_is_a_hit():
    cache.put("osv", REF.canonical, PAYLOAD)
    assert cache.get("osv", REF.canonical, ttl_hours=24) == PAYLOAD


def test_an_expiry_is_a_miss_not_an_error():
    cache.put("osv", REF.canonical, PAYLOAD)
    assert cache.get("osv", REF.canonical, ttl_hours=0) is None
    assert cache.get("osv", "npm:never@1.0.0", ttl_hours=0) is None


def test_a_naive_stored_timestamp_is_a_miss(monkeypatch):
    """A naive timestamp would shift the TTL by the local UTC offset."""
    with sqlite3.connect(cache.cache_path()) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS cache "
                     "(key TEXT PRIMARY KEY, fetched_at TEXT, payload TEXT)")
        conn.execute("INSERT INTO cache VALUES (?, ?, ?)",
                     (cache.key_for("osv", REF.canonical),
                      "2026-10-09T12:00:00", json.dumps(PAYLOAD)))
    assert cache.get("osv", REF.canonical) is None


# ------------------------------------------------------------------------------
# 3. Cache errors never break the tool
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("stored", ["not json", "[]", '"a string"', "7", "null"])
def test_an_unreadable_payload_is_a_miss(stored):
    with sqlite3.connect(cache.cache_path()) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS cache "
                     "(key TEXT PRIMARY KEY, fetched_at TEXT, payload TEXT)")
        conn.execute("INSERT INTO cache VALUES (?, ?, ?)",
                     (cache.key_for("osv", REF.canonical),
                      datetime.now(timezone.utc).isoformat(), stored))
    assert cache.get("osv", REF.canonical) is None


def test_a_corrupt_database_file_is_a_miss(monkeypatch, tmp_path):
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"this is not a sqlite database at all")
    monkeypatch.setenv("OPENSHIELD_CACHE_DB", str(corrupt))
    assert cache.get("osv", REF.canonical) is None
    cache.put("osv", REF.canonical, PAYLOAD)        # must not raise


def test_an_unserialisable_payload_is_simply_not_stored():
    class Opaque:
        pass
    cache.put("osv", REF.canonical, {"bad": Opaque()})
    assert cache.get("osv", REF.canonical) is None


def test_a_non_dict_payload_is_refused():
    cache.put("osv", REF.canonical, ["a", "list"])
    assert cache.get("osv", REF.canonical) is None


def test_the_directory_is_created_on_first_use(monkeypatch, tmp_path):
    nested = tmp_path / "does" / "not" / "exist" / "cache.db"
    monkeypatch.setenv("OPENSHIELD_CACHE_DB", str(nested))
    cache.put("osv", REF.canonical, PAYLOAD)
    assert nested.exists()


# ------------------------------------------------------------------------------
# 4. clear and stats
# ------------------------------------------------------------------------------

def test_clear_empties_the_cache_and_reports_how_many():
    cache.put("osv", REF.canonical, PAYLOAD)
    cache.put("npm-registry", REF.canonical, PAYLOAD)
    assert cache.clear() == 2
    assert cache.get("osv", REF.canonical) is None
    assert cache.clear() == 0


def test_stats_counts_entries():
    assert cache.stats()["entries"] == 0
    cache.put("osv", REF.canonical, PAYLOAD)
    stats = cache.stats()
    assert stats["entries"] == 1
    assert stats["oldest"] is not None
    assert "cache.db" in stats["path"]


# ------------------------------------------------------------------------------
# 5. Integration with collect()
# ------------------------------------------------------------------------------

@respx.mock
def test_a_cold_run_makes_requests_and_a_warm_run_does_not(no_github):
    """Counts route calls: with respx active the network guard cannot detect
    a refetch."""
    osv = mock_all()

    first = collect([REF])[0]
    assert osv.call_count == 1
    assert first.partial is False

    second = collect([REF])[0]
    assert osv.call_count == 1, "a warm run refetched"
    assert second.partial is False


@respx.mock
def test_a_warm_run_marks_its_sources_as_cached(no_github):
    mock_all()
    collect([REF])

    warm = collect([REF])[0]

    assert warm.sources
    assert all(s.from_cache for s in warm.sources)


@respx.mock
def test_a_cold_run_marks_its_sources_as_live(no_github):
    mock_all()
    cold = collect([REF])[0]
    assert cold.sources
    assert not any(s.from_cache for s in cold.sources)


@respx.mock
def test_the_same_evidence_comes_back_from_the_cache(no_github):
    mock_all()
    cold = collect([REF])[0]
    warm = collect([REF])[0]

    assert [v.id for v in warm.vulnerabilities] == [v.id for v in cold.vulnerabilities]
    assert warm.registry == cold.registry
    assert {s.name for s in warm.sources} == {s.name for s in cold.sources}


@respx.mock
def test_the_age_is_recomputed_on_a_cache_hit_not_frozen(no_github):
    """Raw timestamps are cached and ages are derived on each read, so the
    same package scores the same regardless of cache state."""
    import openshield.collect.npm as npm_module

    mock_all()
    cold = collect([REF])[0]
    assert cold.registry.days_since_last_publish == 30

    real_parse_iso = npm_module._parse_iso

    def ten_days_later(value):
        """Simulate the clock advancing ten days."""
        parsed = real_parse_iso(value)
        return parsed - timedelta(days=10) if parsed else None

    npm_module._parse_iso = ten_days_later
    try:
        warm = collect([REF])[0]
    finally:
        npm_module._parse_iso = real_parse_iso

    assert all(s.from_cache for s in warm.sources), "should have been a hit"
    assert warm.registry.days_since_last_publish == 40, \
        "the age came from the cache instead of being recomputed"


@respx.mock
def test_a_failed_fetch_is_never_cached(no_github):
    osv = respx.post(OSV_URL).respond(503)
    respx.get(REGISTRY_URL).respond(200, json=PACKUMENT)
    respx.get(DOWNLOADS_URL).respond(200, json={"downloads": 1})

    first = collect([REF])[0]
    assert first.partial is True
    assert osv.call_count == 1

    second = collect([REF])[0]
    assert osv.call_count == 2, "a failure was cached"
    assert second.partial is True


@respx.mock
def test_an_empty_osv_result_IS_cached(no_github):
    """An empty result is a successful answer and must be cacheable."""
    osv = respx.post(OSV_URL).respond(200, json={"vulns": []})
    respx.get(REGISTRY_URL).respond(200, json=PACKUMENT)
    respx.get(DOWNLOADS_URL).respond(200, json={"downloads": 1})

    collect([REF])
    collect([REF])

    assert osv.call_count == 1, "a clean result was not cached"


@respx.mock
def test_different_versions_do_not_share_a_cache_entry(no_github):
    osv = mock_all()

    collect([REF])
    assert osv.call_count == 1

    other = collect([REF2])[0]
    assert osv.call_count == 2
    assert other.package.version == "1.7.3"


@respx.mock
def test_a_batch_shares_one_cache_lookup_per_package(no_github):
    osv = mock_all()
    respx.get("https://registry.npmjs.org/lodash").respond(
        200, json={"name": "lodash", "versions": {"4.17.11": {}}, "time": {}})
    respx.get("https://api.npmjs.org/downloads/point/last-week/lodash").respond(
        200, json={"downloads": 1})
    lodash = PackageRef(name="lodash", version="4.17.11")

    collect([REF, lodash])
    assert osv.call_count == 2

    collect([REF, lodash])
    assert osv.call_count == 2


def test_the_store_guard_checks_ok_not_just_emptiness():
    """A failure that carries data must still not be cached.

    Current collectors return empty data on failure, so
    test_a_failed_fetch_is_never_cached would pass even if the guard only
    checked for data.
    """
    import asyncio

    from openshield.collect import _cached
    from openshield.collect.base import CollectorResult

    async def half_failed():
        return CollectorResult(ok=False, data={"partial": "payload"},
                               error="503 with a body")

    result = asyncio.run(_cached("osv", REF, half_failed))

    assert result.ok is False
    assert cache.get("osv", REF.canonical) is None, \
        "a failure carrying data was cached"