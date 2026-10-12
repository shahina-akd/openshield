import ast
import importlib
import inspect

import pytest

import openshield.run
from openshield.exit_codes import OK, POLICY_BLOCKED, PRIOR_REJECTION, REJECTED
from openshield.run import run_intercept

AXIOS = "npm:axios@1.7.2"
LODASH = "npm:lodash@4.17.11"

@pytest.fixture
def npm_spy(monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(openshield.run, "run_npm", lambda argv: calls.append(argv) or 0)
    return calls


@pytest.fixture
def never_npm(monkeypatch):
    def explode(argv):
        raise AssertionError(f"npm was run: {argv}")
    monkeypatch.setattr(openshield.run, "run_npm", explode)


@pytest.fixture
def mocked_registry_and_osv(respx_mock):
    respx_mock.get(url__regex=r".*registry\.npmjs\.org/.*").respond(
        json={"name": "axios", "dist-tags": {"latest": "1.7.2"},
              "versions": {"1.7.2": {}}})
    respx_mock.post("https://api.osv.dev/v1/query").respond(
        200, json={"vulns": [{"id": "GHSA-x",
                              "database_specific": {"severity": "HIGH"}}]})
    respx_mock.get(url__regex=r".*api\.npmjs\.org/.*").respond(
        200, json={"downloads": 51_000_000})


def test_reject_never_calls_execute(never_npm, monkeypatch, mocked_registry_and_osv):
    monkeypatch.setattr("openshield.run.is_interactive", lambda: True)
    monkeypatch.setattr("openshield.run.prompt", lambda *a, **k: "reject")
    assert run_intercept(["npm", "install", "axios"]) == REJECTED


def test_no_tty_exits_12_without_ever_calling_input(never_npm, monkeypatch,
                                                    mocked_registry_and_osv):
    def explode(*a, **k):
        raise AssertionError("input() called with no TTY -- this would hang")
    monkeypatch.setattr("builtins.input", explode)
    monkeypatch.setattr("openshield.run.is_interactive", lambda: False)
    assert run_intercept(["npm", "install", "axios"]) == POLICY_BLOCKED

def test_ci_env_counts_as_no_tty(monkeypatch):
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    from openshield.decide import is_interactive
    assert is_interactive() is False


def test_all_sources_failed_refuses(never_npm, monkeypatch, respx_mock):
    respx_mock.get(url__regex=r".*registry\.npmjs\.org/.*").respond(503)
    respx_mock.get(url__regex=r".*api\.npmjs\.org/.*").respond(503)
    respx_mock.post("https://api.osv.dev/v1/query").respond(503)
    monkeypatch.setattr("openshield.run.is_interactive", lambda: True)
    assert run_intercept(["npm", "install", "axios"]) == POLICY_BLOCKED

def test_an_all_unresolvable_command_still_reaches_the_prompt(monkeypatch, npm_spy):
    monkeypatch.setattr("openshield.run.is_interactive", lambda: True)
    monkeypatch.setattr("openshield.run.prompt", lambda *a, **k: "approve")
    assert run_intercept(["npm", "install", "./local"]) == 0
    assert npm_spy == [["install", "./local"]]

def test_approve_runs_the_original_argv(monkeypatch, npm_spy, mocked_registry_and_osv):
    monkeypatch.setattr("openshield.run.is_interactive", lambda: True)
    monkeypatch.setattr("openshield.run.prompt", lambda *a, **k: "approve")
    run_intercept(["npm", "install", "-D", "axios", "--save-exact"])
    assert npm_spy == [["install", "-D", "axios", "--save-exact"]]


def test_npms_exit_code_is_propagated(monkeypatch, mocked_registry_and_osv):
    monkeypatch.setattr(openshield.run, "run_npm", lambda argv: 7)
    monkeypatch.setattr("openshield.run.is_interactive", lambda: True)
    monkeypatch.setattr("openshield.run.prompt", lambda *a, **k: "approve")
    assert run_intercept(["npm", "install", "axios"]) == 7


@pytest.mark.parametrize("argv,forwarded", [
    (["npm", "--version"], ["--version"]),
    (["npm", "run", "dev"], ["run", "dev"]),
    (["npm", "ls"], ["ls"]),
    (["npm", "ci"], ["ci"]),
    (["npm", "install"], ["install"]),
])
def test_pass_through_forwards_without_analysis(argv, forwarded, npm_spy):
    assert run_intercept(argv) == 0
    assert npm_spy == [forwarded]


def test_bypass_runs_npm_immediately(monkeypatch, npm_spy):
    monkeypatch.setenv("OPENSHIELD_BYPASS", "1")
    assert run_intercept(["npm", "install", "axios"]) == 0
    assert npm_spy == [["install", "axios"]]


def test_an_internal_error_never_installs(monkeypatch, never_npm):
    monkeypatch.setattr("openshield.run.classify_invocation",
                        lambda argv: (_ for _ in ()).throw(RuntimeError("boom")))
    assert run_intercept(["npm", "install", "axios"]) == 20


ANALYSIS_MODULES = ["parse", "resolve", "score", "render", "decide",
                    "collect", "collect.base", "collect.osv",
                    "collect.npm", "collect.github", "collect.cvss"]


@pytest.mark.parametrize("name", ANALYSIS_MODULES)
def test_no_analysis_module_can_run_a_subprocess(name):
    module = importlib.import_module(f"openshield.{name}")
    tree = ast.parse(inspect.getsource(module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {"subprocess", "execute"} & imported
    assert not forbidden, f"{name} can reach {forbidden}"


# ------------------------------- sticky rejection -----------------------------

def test_a_sticky_rejection_exits_11_and_never_collects(
        decisions, route_counts, npm_calls, never_prompted):
    """Fails if stored decisions are checked after collection."""
    decisions.reject(LODASH)

    assert run_intercept(["npm", "install", "lodash@4.17.11"]) == PRIOR_REJECTION
    assert route_counts.collectors() == 0
    assert npm_calls == []


def test_a_blocked_package_is_named_in_the_output(
        decisions, route_counts, capsys, never_prompted):
    decisions.reject(LODASH)
    run_intercept(["npm", "install", "lodash@4.17.11"])

    out = capsys.readouterr().out
    assert "lodash" in out and "--revoke" in out


def test_a_rejection_does_not_expire(decisions, route_counts, npm_calls,
                                     never_prompted):
    decisions.reject(LODASH, days_ago=4000)

    assert run_intercept(["npm", "install", "lodash@4.17.11"]) == PRIOR_REJECTION
    assert route_counts.collectors() == 0


# ------------------------------ remembered approval ---------------------------

def test_an_approval_within_ttl_skips_collection_but_still_runs_npm(
        decisions, route_counts, npm_calls, never_prompted):
    decisions.approve(AXIOS)

    assert run_intercept(["npm", "install", "axios@1.7.2"]) == OK
    assert route_counts.collectors() == 0
    assert npm_calls


def test_a_remembered_approval_says_it_did_not_recheck(
        decisions, route_counts, capsys, npm_calls, never_prompted):
    decisions.approve(AXIOS)
    run_intercept(["npm", "install", "axios@1.7.2"])

    assert "not re-checked" in capsys.readouterr().out


def test_an_expired_approval_collects_again(decisions, route_counts, answer_yes,
                                            npm_calls):
    decisions.approve(AXIOS, days_ago=91)
    run_intercept(["npm", "install", "axios@1.7.2"])

    assert route_counts["osv"] > 0


def test_a_partial_approval_still_collects_everything(
        decisions, route_counts, answer_yes, npm_calls):
    """The shortcut applies only when every package is approved."""
    decisions.approve(AXIOS)
    run_intercept(["npm", "install", "axios@1.7.2", "lodash@4.17.11"])

    assert route_counts["osv"] > 0


def test_another_project_does_not_inherit_an_approval(
        decisions, two_projects, route_counts, answer_yes, npm_calls):
    decisions.approve(AXIOS, project=two_projects.a)
    two_projects.use(two_projects.b)
    run_intercept(["npm", "install", "axios@1.7.2"])

    assert route_counts["osv"] > 0


# ---------------------------------- recording ---------------------------------

def test_approving_records_the_score_and_the_scoring_version(
        decisions, route_counts, answer_yes, npm_calls):
    run_intercept(["npm", "install", "axios@1.7.2"])

    row = decisions.fetch(AXIOS)
    assert row is not None, "nothing was recorded"
    assert row["action"] == "approve"
    assert row["trust_score"] is not None
    assert row["scoring_version"]


def test_a_single_package_rejection_is_persisted(decisions, route_counts,
                                                 answer_no):
    assert run_intercept(["npm", "install", "lodash@4.17.11"]) == REJECTED

    row = decisions.fetch(LODASH)
    assert row is not None, "the rejection was not recorded"
    assert row["action"] == "reject"


def test_a_multi_package_rejection_is_not_persisted(decisions, route_counts,
                                                    answer_no, capsys):
    """Rejections are permanent, so rejecting a multi-package command must not
    block packages the user did not object to."""
    code = run_intercept(["npm", "install", "axios@1.7.2", "lodash@4.17.11"])

    assert code == REJECTED
    assert decisions.fetch(AXIOS) is None
    assert decisions.fetch(LODASH) is None
    assert "not remembered" in capsys.readouterr().out


def test_two_specifiers_resolve_to_two_different_packages(
        decisions, route_counts, answer_yes, npm_calls):
    """Guards the registry mock: it must return the requested package name."""
    run_intercept(["npm", "install", "axios@1.7.2"])
    run_intercept(["npm", "install", "lodash@4.17.11"])

    assert decisions.fetch(AXIOS) is not None
    assert decisions.fetch(LODASH) is not None


def test_a_bypass_records_an_audit_row_and_runs_npm(decisions, monkeypatch,
                                                    npm_calls):
    monkeypatch.setenv("OPENSHIELD_BYPASS", "1")
    run_intercept(["npm", "install", "axios@1.7.2"])

    assert npm_calls
    assert "bypass" in decisions.events()