"""A read-through cache for raw collector responses. SQLite, one table.

Three rules, each preventing a specific bug (NOTES-M1 B.2, B.3; §14):

1. KEYED ON CANONICAL IDENTITY, never the specifier. `axios` and `axios@1.7.2`
   resolve to the same package, so they must share one entry. Appendix B lists
   "the second run isn't faster" with exactly this cause.

2. SUCCESSES ONLY. A 503 stored under a 24-hour TTL is a source that stays
   broken for a day after it recovered -- and `from_cache=True` on a failure
   would render as "as of nine hours ago" about something that never succeeded.

3. RAW PAYLOADS, parsed on read. Parsers change weekly during development and a
   cached raw response survives that. It is also what keeps age integers
   correct across a hit: the clock read lives in each collector's parse(),
   which runs on every request (B.2).

This module does no network and holds no collector knowledge. It is a dict with
a disk behind it.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_TTL_HOURS = 24          # Step 1.6 moves this to config.toml

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
  key         TEXT PRIMARY KEY,
  fetched_at  TEXT NOT NULL,
  payload     TEXT NOT NULL
);
"""


def cache_path() -> Path:
    """`~/.openshield/cache.db`, or wherever OPENSHIELD_CACHE_DB points.

    The override exists for tests: a test that wrote to the real cache would
    pass or fail depending on whether you had run the tool that morning, which
    is the definition of a test you cannot trust. Same rule M2 applies to the
    shim directory.
    """
    override = os.environ.get("OPENSHIELD_CACHE_DB")
    if override:
        return Path(override)
    return Path.home() / ".openshield" / "cache.db"


def key_for(source: str, canonical: str) -> str:
    """'osv' + 'npm:axios@1.7.2' -> 'osv:npm:axios@1.7.2'.

    The canonical identity, which exists only AFTER resolve() has run -- which
    is why resolution itself cannot be cached by this scheme (NOTES-0_3's
    recorded gap, and B.14).
    """
    return f"{source}:{canonical}"


def _connect() -> sqlite3.Connection:
    path = cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(_SCHEMA)
    return connection


def get(source: str, canonical: str, ttl_hours: int = DEFAULT_TTL_HOURS) -> dict | None:
    """The stored payload, or None for a miss, an expiry, or anything unreadable.

    NEVER RAISES. A corrupt or unreadable cache must degrade to a miss, not to
    a crash: the cache is an optimisation, and an optimisation that can break
    the tool is a liability. §14's "the cache is never the reason the tool
    fails".
    """
    try:
        with _connect() as connection:
            row = connection.execute(
                "SELECT fetched_at, payload FROM cache WHERE key = ?",
                (key_for(source, canonical),),
            ).fetchone()
    except sqlite3.Error:
        return None

    if row is None:
        return None

    fetched_at, payload = row
    stored = _parse_stamp(fetched_at)
    if stored is None:
        return None
    if datetime.now(timezone.utc) - stored > timedelta(hours=ttl_hours):
        return None          # expired: a miss, not an error

    try:
        value = json.loads(payload)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def put(source: str, canonical: str, payload: dict) -> None:
    """Store a payload. Silent on failure, for the same reason get() is.

    Callers must only reach this for a SUCCESSFUL fetch (rule 2). The guard
    lives at the call site rather than here, because this module has no way to
    know what a given collector considers success.
    """
    if not isinstance(payload, dict):
        return
    try:
        serialised = json.dumps(payload)
    except (TypeError, ValueError):
        return
    try:
        with _connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO cache (key, fetched_at, payload) "
                "VALUES (?, ?, ?)",
                (key_for(source, canonical),
                 datetime.now(timezone.utc).isoformat(),
                 serialised),
            )
    except sqlite3.Error:
        return


def clear() -> int:
    """Empty the cache; returns the number of rows removed.

    `openshield cache --clear` calls this. You will want it constantly while
    parsers are still moving.
    """
    try:
        with _connect() as connection:
            count = connection.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            connection.execute("DELETE FROM cache")
        return int(count)
    except sqlite3.Error:
        return 0


def stats() -> dict:
    """Row count and the oldest entry, for `openshield cache` with no flag."""
    try:
        with _connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*), MIN(fetched_at) FROM cache").fetchone()
    except sqlite3.Error:
        return {"entries": 0, "oldest": None, "path": str(cache_path())}
    return {"entries": int(row[0] or 0), "oldest": row[1],
            "path": str(cache_path())}


def _parse_stamp(value: object) -> datetime | None:
    """Stored stamps are our own isoformat() output, so this is simpler than
    the collectors' _parse_iso -- but it still refuses naive results (§17): a
    naive stamp read back would silently shift the TTL by the UTC offset."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None