"""Tests for the database schema."""
import sqlite3

import pytest

from openshield.db import connect, session


def test_both_tables_exist():
    with session() as conn:
        tables = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"decisions", "audit"} <= tables


def test_connecting_twice_is_safe():
    connect().close()
    connect().close()


def test_the_db_path_honours_the_environment(tmp_path, monkeypatch):
    target = tmp_path / "nested" / "openshield.db"
    monkeypatch.setenv("OPENSHIELD_DB", str(target))
    connect().close()
    assert target.exists()


def test_an_invalid_action_is_rejected_by_the_schema():
    """The schema enforces this even for direct inserts that bypass
    save_decision."""
    with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
        with session() as conn:
            conn.execute(
                "INSERT INTO decisions (project_id, ecosystem, name, version, "
                "action, decided_at) VALUES (?,?,?,?,?,?)",
                ("p", "npm", "demo", "1.0.0", "maybe", "2026-01-01"),
            )


def test_one_identity_has_one_decision_row():
    row = ("p", "npm", "demo", "1.0.0")
    with session() as conn:
        for action in ("approve", "reject"):
            conn.execute(
                "INSERT OR REPLACE INTO decisions (project_id, ecosystem, "
                "name, version, action, decided_at) VALUES (?,?,?,?,?,?)",
                (*row, action, "2026-01-01"),
            )
        assert conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 1


def test_the_same_package_in_two_projects_is_two_rows():
    with session() as conn:
        for project in ("p1", "p2"):
            conn.execute(
                "INSERT INTO decisions (project_id, ecosystem, name, version, "
                "action, decided_at) VALUES (?,?,?,?,?,?)",
                (project, "npm", "demo", "1.0.0", "approve", "2026-01-01"),
            )
        assert conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 2


def test_audit_keeps_every_event():
    with session() as conn:
        for event in ("approve", "revoke"):
            conn.execute(
                "INSERT INTO audit (at, event, identity) VALUES (?,?,?)",
                ("2026-01-01", event, "npm:demo@1.0.0"),
            )
        assert conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 2


def test_session_rolls_back_on_error():
    with pytest.raises(RuntimeError):
        with session() as conn:
            conn.execute(
                "INSERT INTO audit (at, event) VALUES ('2026-01-01', 'approve')")
            raise RuntimeError("boom")

    with session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 0