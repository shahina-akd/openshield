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


# --- M0-style: vulnerabilities only, no registry or repository ---

def _vuln(severity, id="GHSA-x", fixed=("9.9.9",), summary="a summary"):
    return Vulnerability(id=id, severity=severity, summary=summary,
                         fixed_versions=list(fixed), source=SOURCE)


def _rendered(*vulns, partial=False, degraded=(), sources=(SOURCE,)):
    ev_ = Evidence(package=REF, vulnerabilities=list(vulns), sources=list(sources),
                   partial=partial, degraded_sources=list(degraded))
    return render_assessment(score(ev_))


# --- M1-style: the all-good baseline with registry and repository ---

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


# ==============================================================================
# 2. Degradation invariants
# ==============================================================================

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


# ==============================================================================
# 3. Grouping, capping, and the promise not to hide
# ==============================================================================

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


# ==============================================================================
# 4. The sanitiser. Untrusted text, on a terminal.
# ==============================================================================

def test_the_escape_character_is_removed_not_merely_the_bracket():
    """The ESC byte is what makes a sequence a sequence.

    `\\x1b[2J` clears the screen. Leave the ESC and strip the rest and you have
    broken the message; strip the ESC and the remainder is inert text that a
    terminal prints literally. This test asserts on the ABSENCE OF \\x1b rather
    than on the exact leftover, because the leftover is cosmetic and the ESC is
    the vulnerability.
    """
    cleaned = _clean_message("\x1b[2Jcleared")
    assert "\x1b" not in cleaned
    assert cleaned == "[2Jcleared"


def test_a_message_cannot_forge_a_line_of_our_own_output():
    """THE ATTACK THIS BLOCKS.

    A publisher who can emit a newline can write a line that looks like the
    tool's own -- "no known vulnerabilities" under our banner, in our voice.
    Collapsing newlines to spaces means one field occupies one line, always.
    """
    forged = "deprecated\n  no known vulnerabilities\n  score 95/100"
    cleaned = _clean_message(forged)
    assert "\n" not in cleaned
    assert cleaned.count("no known vulnerabilities") == 1   # as text, not a line
    assert len(cleaned.splitlines()) == 1


def test_carriage_return_cannot_overwrite_the_previous_line():
    """\\r alone moves the cursor to column 0 without advancing. It would
    overwrite whatever was just printed -- the findings, or the score."""
    assert "\r" not in _clean_message("\rSAFE TO INSTALL")


def test_stripped_characters_become_spaces_rather_than_vanishing():
    """Deleting would join the words either side and misrepresent the text.
    "foo\\x00bar" is two words in the publisher's source, not one."""
    assert _clean_message("foo\x00bar") == "foo bar"


def test_non_ascii_lookalikes_are_removed():
    """A bidi override (U+202E) reverses display order, and non-breaking spaces
    and box-drawing characters can dress text up as framing of our own. The
    ASCII rule removes the whole family without enumerating it."""
    assert _clean_message("café \u202eevil") == "caf evil"


def test_a_long_message_is_capped_and_marked_as_truncated():
    """A megabyte in one field is a denial of service against the reader. The
    ellipsis matters: a silently cut message reads as the whole message."""
    cleaned = _clean_message("x" * 5000)
    assert len(cleaned) == _MAX_MESSAGE + 3
    assert cleaned.endswith("...")


def test_bare_true_becomes_a_message_because_the_fact_is_the_signal():
    """npm accepts `deprecated: true` with no text. None would lose the fact."""
    assert _clean_message(True) == "deprecated by its maintainer (no message given)"


@pytest.mark.parametrize("junk", [False, "", "   ", "\n\n", "\x1b", None, 7, [], {}])
def test_absent_and_meaningless_values_are_none(junk):
    """`False` belongs here and is the interesting case: npm writes it to mean
    NOT deprecated, so it must not become a message. Everything that survives
    sanitising to nothing is also nothing."""
    assert _clean_message(junk) is None


# ==============================================================================
# 5. parse() -- precedence, and the version we actually resolved
# ==============================================================================

def test_the_per_version_notice_wins_over_the_top_level_one():
    """THE WHOLE THREAT MODEL IS A SPECIFIC VERSION (§7).

    npm carries `deprecated` in two places: on the version, and on the package.
    They disagree constantly -- a maintainer deprecates 1.x and leaves 2.x
    current. Reading the top level first would report the wrong statement about
    the version being installed, which is worse than reporting none.
    """
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
    """1.2.0 being deprecated says nothing about 1.3.0."""
    payload = {"packument": {"versions": {"1.2.0": {"deprecated": "old"},
                                          "1.3.0": {}}}}
    assert parse(payload, ref()).deprecated is None


def test_a_hostile_notice_is_sanitised_on_the_way_through_parse():
    """The sanitiser is not optional decoration at the call site: parse is the
    boundary, so nothing downstream ever holds the raw string."""
    payload = {"packument": {
        "versions": {"1.3.0": {"deprecated": "\x1b[2Jgone\nforged"}}}}
    cleaned = parse(payload, ref()).deprecated
    assert "\x1b" not in cleaned and "\n" not in cleaned


def test_the_monorepo_subpath_is_kept_separately_from_the_repository():
    """npm puts the subpath in `repository.directory`, which is why @babel/core
    resolves to a real repository rather than to nothing (§8 live check)."""
    payload = {"packument": {"versions": {"1.3.0": {"repository": {
        "url": "https://github.com/babel/babel",
        "directory": "packages/babel-core"}}}}}
    info = parse(payload, ref())
    assert info.repository_name == "babel"
    assert info.repository_directory == "packages/babel-core"


# ==============================================================================
# 6. Scoring -- a statement outweighs an inference
# ==============================================================================

def test_deprecation_costs_more_than_any_inferred_signal():
    """-25, the heaviest single weight in the table.

    An inference can be wrong about INTENT: a package with no commits for two
    years might be finished, or abandoned, and the tool cannot tell. A
    deprecation notice cannot be wrong about intent -- the maintainer said it.
    """
    before, after = score(ev()), score(with_notice())
    assert after.score == before.score - 25
    assert rows(after)["deprecated by its maintainer"] == -25


def test_the_row_label_is_short_enough_for_the_table():
    """The label explains the NUMBER; the message is rendered separately. A
    200-character label in a 44-character column truncates away the "use X
    instead" that is the only actionable part."""
    after = score(with_notice("x" * 200))
    assert all(len(c.label) <= 44 for c in after.contributions)


def test_a_disabled_repository_is_scored():
    after = score(with_repo(disabled=True))
    assert rows(after)["repository disabled by GitHub"] == -25


def test_disabled_none_is_not_disabled_false():
    """A.2 at this site too. A failed GitHub lookup must not look like a clean
    answer -- the ceiling is what contains the gap, not a silent zero."""
    unknown = score(with_repo(disabled=None))
    measured = score(with_repo(disabled=False))
    assert "repository disabled by GitHub" not in rows(unknown)
    assert "repository disabled by GitHub" not in rows(measured)
    assert unknown.score == measured.score


def test_declarations_are_listed_before_inferred_signals():
    """Row ORDER is part of the output, not an implementation detail: a reader
    scanning top-down should meet "the maintainer told you to stop" before
    "it has a lot of downloads"."""
    labels = [c.label for c in score(with_notice("stop")).contributions]
    declaration = labels.index("deprecated by its maintainer")
    # Matched by substring, not by literal: the inferred labels embed their
    # own numbers ("50,000,000 weekly downloads"), and pinning those here
    # would make this test fail on a change to the wording rather than to
    # the ordering it is actually about.
    inferred = [i for i, label in enumerate(labels)
                if "downloads" in label or "maintainers" in label]
    assert inferred, labels          # the baseline must HAVE inferred rows
    assert declaration < min(inferred)


def test_the_rows_still_sum_to_the_score():
    """The invariant the whole table rests on, re-checked with the new rows."""
    after = score(ev(
        registry=HEALTHY_REGISTRY.model_copy(update={"deprecated": "stop"}),
        repository=HEALTHY_REPO.model_copy(update={"archived": True,
                                                   "disabled": True})))
    assert sum(c.points for c in after.contributions) == after.score


# ==============================================================================
# 7. The score line -- and the bug that had no test
# ==============================================================================

def test_the_number_is_still_there():
    """The band and gloss are added TO the number, not instead of it. A score
    is comparable between runs and across packages; a word is not."""
    assert band_summary(score(ev())).startswith("91/100 -- ")


def test_low_does_not_read_as_a_clean_bill_of_health():
    """§3.3.2. The whole reason the band exists is that it does NOT mean safe,
    and "low risk" on its own reads as a pass."""
    assert band_summary(score(ev())) == "91/100 -- low: nothing known against this"


def test_the_marker_does_not_contradict_the_gloss():
    """[ok] two characters left of "nothing known against this" would reinstate
    exactly the reading the sentence denies."""
    assert "[ok]" not in render_assessment(score(ev()))


def test_the_capped_gloss_only_appears_when_the_ceiling_actually_bound():
    """THE BUG THIS TEST EXISTS FOR.

    `partial` alone is the wrong condition. A degraded package carrying a
    critical finding scores far below the ceiling, so the ceiling never binds --
    and "capped -- evidence incomplete" would then tell the reader the score
    would be higher if we had looked harder, while hiding the real reason.
    Confidently wrong in the reassuring direction.
    """
    bound = score(ev(partial=True))
    did_not_bind = score(ev(vuln("critical"), partial=True))

    assert bound.score == PARTIAL_CEILING
    assert "capped" in band_summary(bound)

    # Assert the PROPERTY, not a particular band's words: whatever band it
    # lands in, the gloss describes the package rather than our evidence.
    # (A fixed critical on an otherwise healthy package is `medium`, not
    # `high` -- pinning "problems found" here would make this test about the
    # weight table instead of about the gloss.)
    assert did_not_bind.score < PARTIAL_CEILING
    assert "capped" not in band_summary(did_not_bind)
    assert band_summary(did_not_bind).endswith(_BAND_GLOSS[did_not_bind.risk])


def test_incompleteness_is_never_lost_when_the_gloss_drops_it():
    """Dropping the gloss is only safe because the DEGRADED block is
    unconditional for a partial result. Assert the pair, not the half."""
    text = render_assessment(score(ev(vuln("critical"), partial=True)))
    assert "DEGRADED" in text
    assert "the result below is incomplete" in text


# ==============================================================================
# 8. The score table
# ==============================================================================

def test_the_rows_shown_sum_to_the_total_shown():
    """The table is the score's justification, so a table that does not add up
    is worse than no table: it invites the reader to trust arithmetic that is
    wrong somewhere they cannot see."""
    assessment = score(ev(vuln("high"), partial=True))
    numbers = [int(line.split()[-1])
               for line in render_score_table(assessment)[2:-1]]
    assert sum(numbers) == assessment.score


def test_the_first_row_has_no_sign():
    """A starting point is not an adjustment, and "+60" reads as a bonus
    somebody earned."""
    table = render_score_table(score(ev()))
    assert table[2].strip().endswith(" 60")
    assert "+60" not in table[2]


def test_the_width_comes_from_the_content_not_a_terminal_guess():
    """§11.3. A long label widens the column rather than pushing the number off
    the edge of an assumed 80 columns -- and _MAX_LABEL bounds how far that can
    go, so the column is content-sized AND finite.

    The labels are injected rather than produced by score(), because every real
    label is deliberately short; this tests the renderer's own arithmetic.
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
# 9. Declarations -- where they sit, and whose voice they are in
# ==============================================================================

def test_the_declaration_comes_after_the_score_and_before_the_findings():
    """PLACEMENT IS THE POINT. A declaration changes how everything below it
    reads: "no known vulnerabilities" is a fact about today, but under a
    deprecation notice it tells you nobody is looking.

    Below the findings it would be a footnote; above the score it would
    displace the number the reader came for.
    """
    text = render_assessment(score(with_notice("stop")))
    lines = text.splitlines()
    score_line = next(i for i, l in enumerate(lines) if "/100 --" in l)
    notice = next(i for i, l in enumerate(lines) if "asked you to stop" in l)
    findings = next(i for i, l in enumerate(lines) if "vulnerabilit" in l)
    assert score_line < notice < findings


def test_the_message_is_quoted_and_attributed():
    """A reader must see where our voice stops and the publisher's starts,
    or a message reading "all checks passed" borrows our authority."""
    lines = render_declarations(score(with_notice("use padStart()")))
    assert any('the maintainer says: "use padStart()"' in l for l in lines)


def test_nothing_is_rendered_when_there_is_nothing_to_declare():
    """No empty heading, no "none" -- a block that always appears is furniture
    and trains the reader straight past it."""
    assert render_declarations(score(ev())) == []


def test_a_disabled_repository_does_not_guess_at_the_reason():
    """DMCA, terms-of-service, or abuse -- GitHub does not say, and naming the
    wrong one defames a maintainer over a trademark dispute."""
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
    """END TO END: through npm.parse, score and render.

    IT MUST ENTER THROUGH parse. Constructing RegistryInfo(deprecated=...)
    directly bypasses the sanitiser, which lives at the collector boundary --
    so a test that builds the model by hand would prove nothing about the
    pipeline and would quietly pass whatever the renderer did. That is a real
    property of the design: the model stores what it is given, and `parse` is
    the single place untrusted text is allowed in.
    """
    registry = parse({"packument": {"maintainers": [1, 2, 3, 4, 5],
                                    "versions": {"1.7.2": {
                                        "deprecated": hostile,
                                        "license": "MIT"}}}},
                     PackageRef(name="axios", version="1.7.2"))
    text = render_assessment(score(ev(registry=registry)))

    assert "\x1b" not in text
    notice = [l for l in text.splitlines() if "the maintainer " in l]
    assert len(notice) == 2                     # the headline and the quote
    assert notice[1].rstrip().endswith('"')     # the quote is closed
    assert "no known vulnerabilities" in text   # our line, still ours
    assert text.count("/100 --") == 1           # no forged score line


# ==============================================================================
# 10. The analysis path cannot execute anything -- checked transitively
# ==============================================================================
#
# The original checked render.py's DIRECT imports against {"__future__",
# "models"}. 1.5c added `from .score import PARTIAL_CEILING`. Widening the list
# would make the test pass while quietly weakening what it proves, so instead it
# walks every first-party import and applies the allowlist to the whole closure.

# Non-first-party modules the analysis path may touch. Deliberately small:
# `re`, `datetime`, `typing` and `pydantic` arrive via models.py, which is a
# data module and cannot execute anything either.
_ALLOWED_IMPORTS = {
    "__future__", "typing", "re", "datetime", "pydantic",
}

# First-party modules on the analysis path. Each is followed, not trusted --
# membership here means "walk into it", not "assume it is clean".
_FIRST_PARTY = {
    "render": openshield.render,
    "score": openshield.score,
    "models": openshield.models,
}


def _direct_imports(module) -> set[str]:
    """Top-level names this module imports, relative and absolute alike.

    `from . import models` has `node.module is None` and the name in
    `node.names`, which the single-module form misses -- so both shapes are
    handled rather than the one that happens to be in use today.
    """
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
    """Every module reachable from `start`, split into first-party and other.

    Breadth-first with a seen-set, so a cycle (render -> score -> render)
    terminates instead of recursing forever.
    """
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
    """§4: nothing on the analysis path may execute an install.

    Checked at the import boundary, transitively. A module that cannot reach
    `subprocess`, `os` or `openshield.execute` through ANY chain of imports
    cannot run an install, whatever its body says.
    """
    walked, outside = _closure("render")
    assert outside <= _ALLOWED_IMPORTS, f"unexpected: {outside - _ALLOWED_IMPORTS}"


def test_the_walk_actually_entered_score_and_models():
    """THE GUARD ON THE GUARD.

    `_closure` returning early -- a typo in a module name, a refactor that
    renames `score` -- would make the test above pass by checking nothing.
    This asserts the walk reached the modules whose purity the claim rests on,
    so a vacuous pass is a failure instead of a green tick.
    """
    walked, _ = _closure("render")
    assert walked == {"render", "score", "models"}


def test_the_closure_would_catch_an_execution_import():
    """And the guard on the allowlist: prove the test can still FAIL.

    A purity test that cannot fail is furniture. `subprocess` is not in the
    allowlist, so if any module in the closure ever imports it -- directly or
    three hops away -- `test_the_renderer_cannot_execute_anything` goes red.
    """
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