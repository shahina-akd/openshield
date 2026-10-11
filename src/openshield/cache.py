"""Read-through SQLite cache for raw collector responses.

Entries are keyed on source plus canonical package identity, only successful
responses are stored, and payloads are stored raw and parsed on read.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_TTL_HOURS = 24

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
  key         TEXT PRIMARY KEY,
  fetched_at  TEXT NOT NULL,
  payload     TEXT NOT NULL
);
"""


def cache_path() -> Path:
    """`~/.openshield/cache.db`, or OPENSHIELD_CACHE_DB if set (used by tests)."""
    override = os.environ.get("OPENSHIELD_CACHE_DB")
    if override:
        return Path(override)
    return Path.home() / ".openshield" / "cache.db"


def key_for(source: str, canonical: str) -> str:
    """'osv' + 'npm:axios@1.7.2' -> 'osv:npm:axios@1.7.2'."""
    return f"{source}:{canonical}"


def _connect() -> sqlite3.Connection:
    path = cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(_SCHEMA)
    return connection


def get(source: str, canonical: str, ttl_hours: int = DEFAULT_TTL_HOURS) -> dict | None:
    """The stored payload, or None for a miss, expiry or unreadable entry.

    Never raises: cache errors degrade to a miss.
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
        return None

    try:
        value = json.loads(payload)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def put(source: str, canonical: str, payload: dict) -> None:
    """Store a payload; silently does nothing on failure.

    Callers are responsible for only storing successful responses.
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
    """Empty the cache and return the number of rows removed."""
    try:
        with _connect() as connection:
            count = connection.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            connection.execute("DELETE FROM cache")
        return int(count)
    except sqlite3.Error:
        return 0


def stats() -> dict:
    """Entry count, oldest entry and database path."""
    try:
        with _connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*), MIN(fetched_at) FROM cache").fetchone()
    except sqlite3.Error:
        return {"entries": 0, "oldest": None, "path": str(cache_path())}
    return {"entries": int(row[0] or 0), "oldest": row[1],
            "path": str(cache_path())}


def _parse_stamp(value: object) -> datetime | None:
    """Parse a stored timestamp, refusing naive values that would skew the TTL."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None