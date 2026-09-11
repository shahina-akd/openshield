import ast
import inspect
from datetime import datetime, timezone
from typing import get_args

import pytest

from typer.testing import CliRunner

from openshield.cli import app

import openshield.render
from openshield.models import (
    Assessment, Evidence, PackageRef, Severity, SourceRef, Unresolvable, Vulnerability,
)
from openshield.render import _ORDER, render_assessment, render_unresolvable
from openshield.score import score

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
SOURCE = SourceRef(name="osv", fetched_at=TS)
REF = PackageRef(name="axios", version="1.7.2")


def _vuln(severity, id="GHSA-x", fixed=("9.9.9",), summary="a summary"):
    return Vulnerability(id=id, severity=severity, summary=summary,
                         fixed_versions=list(fixed), source=SOURCE)


def _rendered(*vulns, partial=False, degraded=(), sources=(SOURCE,)):
    ev = Evidence(package=REF, vulnerabilities=list(vulns), sources=list(sources),
                  partial=partial, degraded_sources=list(degraded))
    return render_assessment(score(ev))

# ---------- constraints ----------
def test_output_is_plain_ascii():
    """No emoji, no box-drawing, no ANSI. Rich arrives in M3; through M2 the
    output must survive a pipe, a log file, and a terminal that is not yours."""
    text = _rendered(_vuln("critical"), _vuln("low"))
    assert text.isascii()
    assert "\x1b" not in text


def test_no_line_assumes_a_terminal_width():
    """A wrapped line in a security tool reads as corruption. Nothing here
    should be padding to a guessed width."""
    text = _rendered(*[_vuln("moderate", id=f"GHSA-{i}") for i in range(20)])
    assert max(len(line) for line in text.splitlines()) < 100

# ------------ invariant -------------
def test_the_degraded_warning_precedes_the_score():
    """§9.1: a degraded result must be visually distinct from a clean one --
    and the warning has to arrive BEFORE the number it qualifies, or it is
    read after the reader has already formed a view."""
    text = _rendered(partial=True, degraded=["osv: 503 from api.osv.dev"])
    lines = text.splitlines()
    warning = next(i for i, l in enumerate(lines) if "DEGRADED" in l)
    identity = next(i for i, l in enumerate(lines) if "npm:axios@1.7.2" in l)
    assert warning < identity


def test_the_failing_source_is_named():
    text = _rendered(partial=True, degraded=["osv: 503 from api.osv.dev"])
    assert "osv: 503 from api.osv.dev" in text


def test_no_evidence_is_not_rendered_as_a_clean_result():
    """The failure mode §15 calls the one that makes the tool actively
    harmful. These two states must not produce similar-looking output."""
    nothing_known = _rendered(partial=True, degraded=["osv: timeout"], sources=())
    genuinely_clean = _rendered()
    assert "no evidence" in nothing_known
    assert "no known vulnerabilities" not in nothing_known
    assert "no known vulnerabilities" in genuinely_clean


def test_a_clean_result_states_the_limitation():
    """§3.3.2 in one line. 'No known vulnerabilities' on its own is the
    sentence the limitation exists to prevent."""
    assert "not the same as safe" in _rendered()


# ---------- grouping, capping, and the promise not to hide ----------
def test_every_severity_has_a_display_position():
    assert set(_ORDER) == set(get_args(Severity))


def test_findings_are_grouped_with_the_worst_first():
    text = _rendered(_vuln("low", id="GHSA-low"),
                     _vuln("critical", id="GHSA-crit"),
                     _vuln("moderate", id="GHSA-mod"))
    assert text.index("GHSA-crit") < text.index("GHSA-mod") < text.index("GHSA-low")


def test_unknown_severity_outranks_moderate_in_the_display():
    """It weighs zero in score.py and must not therefore be buried. An unrated
    finding is unclassified, not mild."""
    text = _rendered(_vuln("moderate", id="GHSA-mod"), _vuln("unknown", id="GHSA-unk"))
    assert text.index("GHSA-unk") < text.index("GHSA-mod")


def test_criticals_and_highs_are_never_capped():
    vulns = [_vuln("critical", id=f"GHSA-c{i}") for i in range(12)]
    text = _rendered(*vulns)
    for v in vulns:
        assert v.id in text
    assert "more" not in text


def test_a_capped_group_says_how_many_it_hid():
    """Silent truncation is §9.1 violated in miniature."""
    text = _rendered(*[_vuln("moderate", id=f"GHSA-m{i}") for i in range(20)])
    assert "... 15 more" in text


def test_the_total_count_always_matches_reality():
    """The reader can reconcile the list against this number, which is the
    only reason capping is acceptable at all."""
    text = _rendered(*[_vuln("moderate", id=f"GHSA-m{i}") for i in range(20)],
                     _vuln("critical", id="GHSA-c"))
    assert "21 findings: 1 critical, 20 moderate" in text


def test_a_finding_with_no_fix_says_so():
    assert "no fix published" in _rendered(_vuln("critical", fixed=()))

# ------------ structural promise -----------------
_ALLOWED_IMPORTS = {"__future__", "models"}


def test_the_renderer_cannot_execute_anything():
    """§4: nothing on the analysis path may execute an install. Checked at the
    import boundary, same technique as score.py's purity test -- a module that
    never imports subprocess or execute cannot reach them."""
    tree = ast.parse(inspect.getsource(openshield.render))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= _ALLOWED_IMPORTS


# --------------- behavior -------------
def test_check_never_runs_npm(monkeypatch, respx_mock):
    def explode(*a, **k):
        raise AssertionError("check invoked npm")

    monkeypatch.setattr("openshield.execute.run_npm", explode)
    respx_mock.get(url__regex=r".*registry\.npmjs\.org/.*").respond(
        json={"name": "axios", "dist-tags": {"latest": "1.7.2"},
              "versions": {"1.7.2": {}}})
    respx_mock.post("https://api.osv.dev/v1/query").respond(200, json={})

    result = CliRunner().invoke(app, ["check", "axios"])
    assert result.exit_code == 0
    assert "npm:axios@1.7.2" in result.stdout


def test_check_reports_unresolvables_without_touching_the_network():
    result = CliRunner().invoke(app, ["check", "axios@^1.0.0"])
    assert result.exit_code == 0
    assert "unresolvable (range)" in result.stdout