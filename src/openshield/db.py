"""SQLite store for decisions and the audit log."""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

# `decisions` holds current state; `audit` is append-only history. Revoking
# deletes from `decisions` but the audit trail keeps the original decision.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    project_id      TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,
    action          TEXT NOT NULL CHECK (action IN ('approve', 'reject')),
    decided_at      TEXT NOT NULL,
    scoring_version TEXT,
    trust_score     INTEGER,
    reason          TEXT,
    project_path    TEXT,
    is_global       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, ecosystem, name, version)
);

CREATE TABLE IF NOT EXISTS audit (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              TEXT NOT NULL,
    event           TEXT NOT NULL,
    project_id      TEXT,
    identity        TEXT,
    trust_score     INTEGER,
    scoring_version TEXT,
    detail          TEXT
);
"""


def _path() -> Path:
    override = os.environ.get("OPENSHIELD_DB")
    if override:
        return Path(override)
    return Path.home() / ".openshield" / "openshield.db"


def connect() -> sqlite3.Connection:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


@contextmanager
def session():
    """Commit on success, roll back on error, and always close.

    Unlike `with sqlite3.connect(...)`, which commits but never closes.
    """
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()