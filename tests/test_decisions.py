
from datetime import datetime, timedelta, timezone

import pytest

from openshield.db import connect
from openshield.decisions import get_decision, save_decision


def test_saved_approval_is_retrieved():
    save_decision("demo", "1.0.0", "/project", "approve")

    assert get_decision("demo", "1.0.0", "/project") == "approve"


def test_decision_is_project_specific():
    save_decision("demo", "1.0.0", "/project-a", "reject")

    assert get_decision("demo", "1.0.0", "/project-b") is None


def test_rejection_does_not_expire():
    save_decision("demo", "1.0.0", "/project", "reject")

    with connect() as conn:
        old_date = (
            datetime.now(timezone.utc) - timedelta(days=365)
        ).isoformat()
        conn.execute(
            """
            UPDATE decisions SET decided_at = ?
            WHERE package = ? AND version = ? AND project = ?
            """,
            (old_date, "demo", "1.0.0", "/project"),
        )

    assert get_decision("demo", "1.0.0", "/project") == "reject"


def test_invalid_decision_is_rejected():
    with pytest.raises(ValueError):
        save_decision("demo", "1.0.0", "/project", "maybe")
