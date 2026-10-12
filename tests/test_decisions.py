from datetime import datetime, timedelta, timezone

import pytest

from openshield.db import session
from openshield.decisions import GLOBAL, audit, get_decision, revoke, save_decision
from openshield.models import PackageRef

TTL = 90
PROJECT = "project-a"
OTHER = "project-b"


def ref(name="demo", version="1.0.0") -> PackageRef:
    return PackageRef(name=name, version=version)


def age(ref: PackageRef, project: str, days: int) -> None:
    """Backdate a decision so TTL behaviour can be tested without sleeping."""
    when = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with session() as conn:
        conn.execute(
            "UPDATE decisions SET decided_at=? WHERE project_id=? AND name=?",
            (when, project, ref.name),
        )


def test_a_saved_approval_is_retrieved():
    save_decision(ref(), PROJECT, "approve")
    assert get_decision(ref(), PROJECT, ttl_days=TTL).action == "approve"


def test_a_decision_is_project_specific():
    save_decision(ref(), PROJECT, "reject")
    assert get_decision(ref(), OTHER, ttl_days=TTL) is None


def test_a_new_version_is_a_new_decision():
    """SPEC §7: the unit of risk is a specific published version. Approving
    1.0.0 says nothing about 1.0.1."""
    save_decision(ref(version="1.0.0"), PROJECT, "approve")
    assert get_decision(ref(version="1.0.1"), PROJECT, ttl_days=TTL) is None


def test_an_approval_expires():
    save_decision(ref(), PROJECT, "approve")
    age(ref(), PROJECT, days=TTL + 1)
    assert get_decision(ref(), PROJECT, ttl_days=TTL) is None


def test_a_rejection_does_not_expire():
    save_decision(ref(), PROJECT, "reject")
    age(ref(), PROJECT, days=4000)
    assert get_decision(ref(), PROJECT, ttl_days=TTL).action == "reject"


def test_a_global_decision_applies_everywhere():
    save_decision(ref(), GLOBAL, "approve", is_global=True)
    assert get_decision(ref(), OTHER, ttl_days=TTL).action == "approve"


def test_a_global_rejection_beats_a_project_approval():
    """Fail closed."""
    save_decision(ref(), GLOBAL, "reject", is_global=True)
    save_decision(ref(), PROJECT, "approve")
    assert get_decision(ref(), PROJECT, ttl_days=TTL).action == "reject"


def test_a_project_rejection_beats_a_global_approval():
    """Fail closed, the other way round."""
    save_decision(ref(), GLOBAL, "approve", is_global=True)
    save_decision(ref(), PROJECT, "reject")
    assert get_decision(ref(), PROJECT, ttl_days=TTL).action == "reject"


def test_the_score_and_scoring_version_are_stored():
    """Without these, history shows a date and no reasoning."""
    save_decision(ref(), PROJECT, "approve", trust_score=71,
                  scoring_version="0.3.0")
    decision = get_decision(ref(), PROJECT, ttl_days=TTL)
    assert (decision.trust_score, decision.scoring_version) == (71, "0.3.0")


def test_an_invalid_action_raises():
    with pytest.raises(ValueError):
        save_decision(ref(), PROJECT, "maybe")


def test_deciding_twice_leaves_one_decision_and_two_audit_rows():
    """`decisions` is state, `audit` is history."""
    save_decision(ref(), PROJECT, "approve")
    save_decision(ref(), PROJECT, "reject")
    with session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 2


def test_revoke_removes_the_decision_and_keeps_the_audit():
    save_decision(ref(), PROJECT, "reject")
    assert revoke(ref(), PROJECT) is True
    assert get_decision(ref(), PROJECT, ttl_days=TTL) is None
    with session() as conn:
        events = [r[0] for r in conn.execute("SELECT event FROM audit")]
    assert events == ["reject", "revoke"]


def test_revoking_nothing_returns_false():
    assert revoke(ref(), PROJECT) is False


def test_audit_never_raises(monkeypatch):
    """A failed audit write must not turn a working install into exit 20."""
    monkeypatch.setattr("openshield.db.connect",
                        lambda: (_ for _ in ()).throw(RuntimeError("disk full")))
    audit("bypass", project=PROJECT)