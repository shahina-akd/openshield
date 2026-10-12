
import os
import sqlite3
from pathlib import Path


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

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package TEXT NOT NULL,
            version TEXT NOT NULL,
            project TEXT NOT NULL,
            decision TEXT NOT NULL
                CHECK (decision IN ('approve', 'reject')),
            decided_at TEXT NOT NULL,
            expires_at TEXT,
            UNIQUE(package, version, project)
        );

        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            package TEXT NOT NULL,
            version TEXT,
            project TEXT,
            action TEXT NOT NULL,
            details TEXT
        );
        """
    )
    conn.commit()
    return conn
