import ast
import inspect
from datetime import datetime, timezone
from typing import get_args

import pytest
from typer.testing import CliRunner

import openshield.models
import openshield.render
import openshield.score
from openshield.cli import app
from openshield.collect.npm import _MAX_MESSAGE, _clean_message, parse
from openshield.models import (
    Assessment, Contribution, Evidence, PackageRef, RegistryInfo, RepositoryInfo,
    Severity, SourceRef, Unresolvable, Vulnerability,
)
from openshield.render import (
    _BAND_GLOSS, _MAX_LABEL, _ORDER, band_summary, render_assessment,
    render_declarations, render_score_table, render_unresolvable,
)
from openshield.score import PARTIAL_CEILING, score


# ==============================================================================
# Shared fixtures
# ==============================================================================

TS = datetime(2026, 10, 10, tzinfo=timezone.utc)
SOURCE = SourceRef(name="osv", fetched_at=TS)
REF = PackageRef(name="axios", version="1.7.2")

HEALTHY_REGISTRY = RegistryInfo(maintainer_count=5, license="MIT",
                                weekly_downloads=50_000_000,
                                days_since_last_publish=30,
                                repository_owner="axios", repository_name="axios")
HEALTHY_REPO = RepositoryInfo(archived=False, disabled=False,
                              days_since_last_push=3, contributors=400,
                              stars=100_000)


def ref(name="left-pad", version="1.3.0"):
    return PackageRef(name=name, version=version)


# Vulnerability-only evidence: no registry or repository data.

def _vuln(severity, id="GHSA-x", fixed=("9.9.9",), summary="a summary"):
    return Vulnerability(id=id, severity=severity, summary=summary,
                         fixed_versions=list(fixed), source=SOURCE)


def _rendered(*vulns, partial=False, degraded=(), sources=(SOURCE,)):
    ev_ = Evidence(package=REF, vulnerabilities=list(vulns), sources=list(sources),
                   partial=partial, degraded_sources=list(degraded))
    return render_assessment(score(ev_))


# Full evidence: a healthy baseline with registry and repository data.

def vuln(severity, fixed=("9.9.9",)):
    return Vulnerability(id="GHSA-x", severity=severity,
                         fixed_versions=list(fixed), source=SOURCE)


def ev(*vulnerabilities, registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO,
       partial=False):
    return Evidence(
        package=REF,
        vulnerabilities=list(vulnerabilities),
        registry=registry, repository=repository, sources=[SOURCE],
        partial=partial,
        degraded_sources=["github: 404 -- repository moved"] if partial else [],
    )


def with_notice(message="use something else"):
    return ev(registry=HEALTHY_REGISTRY.model_copy(update={"deprecated": message}))


def with_repo(**fields):
    return ev(repository=HEALTHY_REPO.model_copy(update=fields))


def rows(assessment):
    return {c.label: c.points for c in assessment.contributions}


# ==============================================================================
# 1. Output constraints
# ==============================================================================

def test_output_is_plain_ascii():
    text = _rendered(_vuln("critical"), _vuln("low"))
    assert text.isascii()
    assert "\x1b" not in text


def test_no_line_assumes_a_terminal_width():
    text = _rendered(*[_vuln("moderate", id=f"GHSA-{i}") for i in range(20)])
    assert max(len(line) for line in text.splitlines()) < 100


# ==============================================================================
# 2. Degraded results
# ==============================================================================

def test_the_degraded_warning_precedes_the_score():
    text = _rendered(partial=True, degraded=["osv: 503 from api.osv.dev"])
    lines = text.splitlines()
    warning = next(i for i, l in enumerate(lines) if "DEGRADED" in l)
    identity = next(i for i, l in enumerate(lines) if "npm:axios@1.7.2" in l)
    assert warning < identity


def test_the_failing_source_is_named():
    text = _rendered(partial=True, degraded=["osv: 503 from api.osv.dev"])
    assert "osv: 503 from api.osv.dev" in text


def test_no_evidence_is_not_rendered_as_a_clean_result():
    nothing_known = _rendered(partial=True, degraded=["osv: timeout"], sources=())
    genuinely_clean = _rendered()
    assert "no evidence" in nothing_known
    assert "no known vulnerabilities" not in nothing_known
    assert "no known vulnerabilities" in genuinely_clean


def test_a_clean_result_states_the_limitation():
    assert "not the same as safe" in _rendered()


# ==============================================================================
# 3. Grouping and capping
# ==============================================================================

def test_every_severity_has_a_display_position():
    assert set(_ORDER) == set(get_args(Severity))


def test_findings_are_grouped_with_the_worst_first():
    text = _rendered(_vuln("low", id="GHSA-low"),
                     _vuln("critical", id="GHSA-crit"),
                     _vuln("moderate", id="GHSA-mod"))
    assert text.index("GHSA-crit") < text.index("GHSA-mod") < text.index("GHSA-low")


def test_unknown_severity_outranks_moderate_in_the_display():
    text = _rendered(_vuln("moderate", id="GHSA-mod"), _vuln("unknown", id="GHSA-unk"))
    assert text.index("GHSA-unk") < text.index("GHSA-mod")


def test_criticals_and_highs_are_never_capped():
    vulns = [_vuln("critical", id=f"GHSA-c{i}") for i in range(12)]
    text = _rendered(*vulns)
    for v in vulns:
        assert v.id in text
    assert "more" not in text


def test_a_capped_group_says_how_many_it_hid():
    text = _rendered(*[_vuln("moderate", id=f"GHSA-m{i}") for i in range(20)])
    assert "... 15 more" in text


def test_the_total_count_always_matches_reality():
    """The total lets the reader reconcile a capped list."""
    text = _rendered(*[_vuln("moderate", id=f"GHSA-m{i}") for i in range(20)],
                     _vuln("critical", id="GHSA-c"))
    assert "21 findings: 1 critical, 20 moderate" in text


def test_a_finding_with_no_fix_says_so():
    assert "no fix published" in _rendered(_vuln("critical", fixed=()))


# ==============================================================================
# 4. Sanitising untrusted text
# ==============================================================================

def test_the_escape_character_is_removed_not_merely_the_bracket():
    """Without the ESC byte the remainder is inert text."""
    cleaned = _clean_message("\x1b[2Jcleared")
    assert "\x1b" not in cleaned
    assert cleaned == "[2Jcleared"


def test_a_message_cannot_forge_a_line_of_our_own_output():
    """Newlines collapse to spaces, so one field always occupies one line."""
    forged = "deprecated\n  no known vulnerabilities\n  score 95/100"
    cleaned = _clean_message(forged)
    assert "\n" not in cleaned
    assert cleaned.count("no known vulnerabilities") == 1
    assert len(cleaned.splitlines()) == 1


def test_carriage_return_cannot_overwrite_the_previous_line():
    assert "\r" not in _clean_message("\rSAFE TO INSTALL")


def test_stripped_characters_become_spaces_rather_than_vanishing():
    """Deleting them would join adjacent words."""
    assert _clean_message("foo\x00bar") == "foo bar"


def test_non_ascii_lookalikes_are_removed():
    """Covers bidi overrides, non-breaking spaces and box-drawing characters."""
    assert _clean_message("café \u202eevil") == "caf evil"


def test_a_long_message_is_capped_and_marked_as_truncated():
    cleaned = _clean_message("x" * 5000)
    assert len(cleaned) == _MAX_MESSAGE + 3
    assert cleaned.endswith("...")


def test_bare_true_becomes_a_message_because_the_fact_is_the_signal():
    """npm accepts `deprecated: true` with no text."""
    assert _clean_message(True) == "deprecated by its maintainer (no message given)"


@pytest.mark.parametrize("junk", [False, "", "   ", "\n\n", "\x1b", None, 7, [], {}])
def test_absent_and_meaningless_values_are_none(junk):
    """npm uses `False` to mean not deprecated."""
    assert _clean_message(junk) is None


# ==============================================================================
# 5. parse(): precedence and version resolution
# ==============================================================================

def test_the_per_version_notice_wins_over_the_top_level_one():
    """The notice must describe the version being installed."""
    payload = {"packument": {
        "deprecated": "the whole package is deprecated",
        "versions": {"1.3.0": {"deprecated": "only 1.3.0 is deprecated"}},
    }}
    assert parse(payload, ref()).deprecated == "only 1.3.0 is deprecated"


def test_the_top_level_notice_is_used_when_the_version_has_none():
    payload = {"packument": {"deprecated": "all versions",
                             "versions": {"1.3.0": {}}}}
    assert parse(payload, ref()).deprecated == "all versions"


def test_a_notice_on_another_version_does_not_leak_onto_ours():
    payload = {"packument": {"versions": {"1.2.0": {"deprecated": "old"},
                                          "1.3.0": {}}}}
    assert parse(payload, ref()).deprecated is None


def test_a_hostile_notice_is_sanitised_on_the_way_through_parse():
    """parse is the trust boundary; nothing downstream holds the raw string."""
    payload = {"packument": {
        "versions": {"1.3.0": {"deprecated": "\x1b[2Jgone\nforged"}}}}
    cleaned = parse(payload, ref()).deprecated
    assert "\x1b" not in cleaned and "\n" not in cleaned


def test_the_monorepo_subpath_is_kept_separately_from_the_repository():
    payload = {"packument": {"versions": {"1.3.0": {"repository": {
        "url": "https://github.com/babel/babel",
        "directory": "packages/babel-core"}}}}}
    info = parse(payload, ref())
    assert info.repository_name == "babel"
    assert info.repository_directory == "packages/babel-core"


# ==============================================================================
# 6. Scoring
# ==============================================================================

def test_deprecation_costs_more_than_any_inferred_signal():
    """An explicit maintainer statement outweighs signals inferred from activity."""
    before, after = score(ev()), score(with_notice())
    assert after.score == before.score - 25
    assert rows(after)["deprecated by its maintainer"] == -25


def test_the_row_label_is_short_enough_for_the_table():
    """The message is rendered separately; the label must fit the column."""
    after = score(with_notice("x" * 200))
    assert all(len(c.label) <= 44 for c in after.contributions)


def test_a_disabled_repository_is_scored():
    after = score(with_repo(disabled=True))
    assert rows(after)["repository disabled by GitHub"] == -25


def test_disabled_none_is_not_disabled_false():
    """An unknown value adds no row; the partial ceiling accounts for the gap."""
    unknown = score(with_repo(disabled=None))
    measured = score(with_repo(disabled=False))
    assert "repository disabled by GitHub" not in rows(unknown)
    assert "repository disabled by GitHub" not in rows(measured)
    assert unknown.score == measured.score


def test_declarations_are_listed_before_inferred_signals():
    labels = [c.label for c in score(with_notice("stop")).contributions]
    declaration = labels.index("deprecated by its maintainer")
    # Matched by substring because inferred labels embed their own numbers.
    inferred = [i for i, label in enumerate(labels)
                if "downloads" in label or "maintainers" in label]
    assert inferred, labels
    assert declaration < min(inferred)


def test_the_rows_still_sum_to_the_score():
    after = score(ev(
        registry=HEALTHY_REGISTRY.model_copy(update={"deprecated": "stop"}),
        repository=HEALTHY_REPO.model_copy(update={"archived": True,
                                                   "disabled": True})))
    assert sum(c.points for c in after.contributions) == after.score


# ==============================================================================
# 7. The score line
# ==============================================================================

def test_the_number_is_still_there():
    assert band_summary(score(ev())).startswith("91/100 -- ")


def test_low_does_not_read_as_a_clean_bill_of_health():
    assert band_summary(score(ev())) == "91/100 -- low: nothing known against this"


def test_the_marker_does_not_contradict_the_gloss():
    assert "[ok]" not in render_assessment(score(ev()))


def test_the_capped_gloss_only_appears_when_the_ceiling_actually_bound():
    """A partial result scoring below the ceiling must not be described as capped."""
    bound = score(ev(partial=True))
    did_not_bind = score(ev(vuln("critical"), partial=True))

    assert bound.score == PARTIAL_CEILING
    assert "capped" in band_summary(bound)

    # Checks against the band's own gloss rather than fixed wording, so the
    # test does not depend on the weight table.
    assert did_not_bind.score < PARTIAL_CEILING
    assert "capped" not in band_summary(did_not_bind)
    assert band_summary(did_not_bind).endswith(_BAND_GLOSS[did_not_bind.risk])


def test_incompleteness_is_never_lost_when_the_gloss_drops_it():
    text = render_assessment(score(ev(vuln("critical"), partial=True)))
    assert "DEGRADED" in text
    assert "the result below is incomplete" in text


# ==============================================================================
# 8. The score table
# ==============================================================================

def test_the_rows_shown_sum_to_the_total_shown():
    assessment = score(ev(vuln("high"), partial=True))
    numbers = [int(line.split()[-1])
               for line in render_score_table(assessment)[2:-1]]
    assert sum(numbers) == assessment.score


def test_the_first_row_has_no_sign():
    """The starting point is a baseline, not an adjustment."""
    table = render_score_table(score(ev()))
    assert table[2].strip().endswith(" 60")
    assert "+60" not in table[2]


def test_the_width_comes_from_the_content_not_a_terminal_guess():
    """Column width follows the labels, bounded by _MAX_LABEL.

    Labels are injected directly because real labels are all short.
    """
    base = score(ev())
    narrow = render_score_table(base.model_copy(update={"contributions": [
        Contribution(label="starting point", points=60)]}))
    wide = render_score_table(base.model_copy(update={"contributions": [
        Contribution(label="starting point", points=60),
        Contribution(label="a label of some considerable length", points=-1)]}))
    assert max(map(len, wide)) > max(map(len, narrow))

    capped = render_score_table(base.model_copy(update={"contributions": [
        Contribution(label="z" * 300, points=60)]}))
    assert all(len(line) < _MAX_LABEL + 20 for line in capped)


def test_no_table_when_there_is_nothing_to_explain():
    assert render_score_table(score(ev(registry=None, repository=None))) != []
    empty = score(ev()).model_copy(update={"contributions": []})
    assert render_score_table(empty) == []


# ==============================================================================
# 9. Declarations
# ==============================================================================

def test_the_declaration_comes_after_the_score_and_before_the_findings():
    text = render_assessment(score(with_notice("stop")))
    lines = text.splitlines()
    score_line = next(i for i, l in enumerate(lines) if "/100 --" in l)
    notice = next(i for i, l in enumerate(lines) if "asked you to stop" in l)
    findings = next(i for i, l in enumerate(lines) if "vulnerabilit" in l)
    assert score_line < notice < findings


def test_the_message_is_quoted_and_attributed():
    """Publisher text must be distinguishable from the tool's own output."""
    lines = render_declarations(score(with_notice("use padStart()")))
    assert any('the maintainer says: "use padStart()"' in l for l in lines)


def test_nothing_is_rendered_when_there_is_nothing_to_declare():
    assert render_declarations(score(ev())) == []


def test_a_disabled_repository_does_not_guess_at_the_reason():
    """GitHub does not disclose why a repository was disabled."""
    lines = render_declarations(score(with_repo(disabled=True)))
    text = " ".join(lines).lower()
    assert "dmca" not in text and "malware" not in text
    assert "does not say why" in text


@pytest.mark.parametrize("hostile", [
    "\x1b[2J all checks passed",
    "ok\nno known vulnerabilities\n  score 95/100",
    "\rSAFE TO INSTALL",
])
def test_a_hostile_message_cannot_reshape_the_output(hostile):
    """End to end through parse, score and render.

    Input must enter through parse, where sanitising happens; building
    RegistryInfo directly would bypass it.
    """
    registry = parse({"packument": {"maintainers": [1, 2, 3, 4, 5],
                                    "versions": {"1.7.2": {
                                        "deprecated": hostile,
                                        "license": "MIT"}}}},
                     PackageRef(name="axios", version="1.7.2"))
    text = render_assessment(score(ev(registry=registry)))

    assert "\x1b" not in text
    notice = [l for l in text.splitlines() if "the maintainer " in l]
    assert len(notice) == 2                     # headline and quote
    assert notice[1].rstrip().endswith('"')
    assert "no known vulnerabilities" in text
    assert text.count("/100 --") == 1


# ==============================================================================
# 10. The analysis path cannot execute anything
# ==============================================================================
#
# Imports are checked transitively across first-party modules, so an indirect
# import of an execution module is caught.

# Third-party and stdlib modules permitted anywhere on the analysis path.
_ALLOWED_IMPORTS = {
    "__future__", "typing", "re", "datetime", "pydantic",
}

# First-party modules to walk into; each is checked, not trusted.
_FIRST_PARTY = {
    "render": openshield.render,
    "score": openshield.score,
    "models": openshield.models,
}


def _direct_imports(module) -> set[str]:
    """Top-level names imported by a module, including `from . import x`."""
    tree = ast.parse(inspect.getsource(module))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.add(node.module.split(".")[0])
            else:
                found |= {alias.name for alias in node.names}
    return found


def _closure(start: str) -> tuple[set[str], set[str]]:
    """Return (first-party modules reached, other modules imported)."""
    seen: set[str] = set()
    outside: set[str] = set()
    queue = [start]
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        for imported in _direct_imports(_FIRST_PARTY[name]):
            if imported in _FIRST_PARTY:
                queue.append(imported)
            else:
                outside.add(imported)
    return seen, outside


def test_the_renderer_cannot_execute_anything():
    walked, outside = _closure("render")
    assert outside <= _ALLOWED_IMPORTS, f"unexpected: {outside - _ALLOWED_IMPORTS}"


def test_the_walk_actually_entered_score_and_models():
    """Guards against the import check passing vacuously."""
    walked, _ = _closure("render")
    assert walked == {"render", "score", "models"}


def test_the_closure_would_catch_an_execution_import():
    assert "subprocess" not in _ALLOWED_IMPORTS
    assert "os" not in _ALLOWED_IMPORTS
    assert "execute" not in _FIRST_PARTY


# ==============================================================================
# 11. CLI behaviour
# ==============================================================================

def test_check_never_runs_npm(monkeypatch, respx_mock):
    def explode(*a, **k):
        raise AssertionError("check spawned a subprocess")

    monkeypatch.setattr("subprocess.run", explode)
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