
from openshield.db import connect


def test_connect_creates_tables():
    conn = connect()

    try:
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table'"
            )
        }

        assert "decisions" in tables
        assert "audit" in tables
    finally:
        conn.close()


def test_decisions_table_rejects_invalid_decision():
    conn = connect()

    try:
        try:
            conn.execute(
                """
                INSERT INTO decisions
                    (package, version, project, decision, decided_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                ("demo", "1.0.0", "/tmp/project", "maybe", "2026-01-01"),
            )
            conn.commit()
            assert False, "Expected invalid decision to be rejected"
        except Exception as exc:
            assert "CHECK constraint failed" in str(exc)
    finally:
        conn.close()
