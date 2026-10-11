import ast
import importlib
import inspect

import pytest

import openshield.run
from openshield.exit_codes import OK, POLICY_BLOCKED, REJECTED
from openshield.run import run_intercept

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
    assert not forbidden, f"{name} can reach {forbidden} -- §4 forbids it"