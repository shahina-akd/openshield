"""Shared test fixtures."""
import socket

import httpx
import pytest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import unquote

import openshield.run
from openshield.db import session
from openshield.decisions import save_decision
from openshield.models import PackageRef
from openshield.project import project_id


class RealNetworkAttempted(BaseException):
    """Raised when a test tries to reach the real network.

    Derives from BaseException so collectors, which catch Exception, cannot
    swallow it and report a degraded source instead of failing the test.
    """


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Block real connections at the socket layer.

    Patching sockets rather than httpx leaves respx mocks working. DNS
    resolution is blocked too, since it happens before connect().
    """
    def deny(*args, **kwargs):
        raise RealNetworkAttempted(
            "test attempted a real network connection -- add @respx.mock, "
            "or stub the collector"
        )

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)


def _spy_on(monkeypatch, cls) -> list[dict]:
    """Record each construction of `cls` (instance and kwargs), then construct
    normally. Does not block traffic."""
    calls: list[dict] = []
    original = cls.__init__

    def spy(self, *args, **kwargs):
        calls.append({"self": self, "kwargs": kwargs})
        original(self, *args, **kwargs)

    monkeypatch.setattr(cls, "__init__", spy)
    return calls


@pytest.fixture
def client_spy(monkeypatch):
    return _spy_on(monkeypatch, httpx.Client)


@pytest.fixture
def async_client_spy(monkeypatch):
    return _spy_on(monkeypatch, httpx.AsyncClient)


@pytest.fixture(autouse=True)
def isolated_cache(monkeypatch, tmp_path):
    """Give each test an empty cache so results never depend on ~/.openshield."""
    monkeypatch.setenv("OPENSHIELD_CACHE_DB", str(tmp_path / "cache.db"))


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch, tmp_path):
    """Give each test an empty config path in a not-yet-created directory."""
    monkeypatch.setenv("OPENSHIELD_CONFIG",
                       str(tmp_path / "openshield" / "config.toml"))


@pytest.fixture(autouse=True)
def isolated_db(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENSHIELD_DB", str(tmp_path / "openshield.db"))


@pytest.fixture
def tmp_project(monkeypatch, tmp_path):
    """A directory with a package.json, used as the current project."""
    root = tmp_path / "app"
    root.mkdir()
    (root / "package.json").write_text("{}")
    monkeypatch.setenv("OPENSHIELD_PROJECT", str(root))
    return root


@pytest.fixture
def two_projects(monkeypatch, tmp_path):
    """Two separate projects, and a way to switch between them."""
    def make(name):
        root = tmp_path / name
        root.mkdir()
        (root / "package.json").write_text("{}")
        return root

    a, b = make("a"), make("b")
    monkeypatch.setenv("OPENSHIELD_PROJECT", str(a))

    def use(root):
        monkeypatch.setenv("OPENSHIELD_PROJECT", str(root))

    return SimpleNamespace(a=a, b=b, use=use)


@pytest.fixture
def decisions(tmp_project):
    """Read and write decisions for the current project.

    `days_ago` backdates a row for TTL tests.
    """
    def ref_of(canonical: str) -> PackageRef:
        name, _, version = canonical.removeprefix("npm:").rpartition("@")
        return PackageRef(name=name, version=version)

    def write(canonical, action, *, days_ago=0, project=None, **kwargs):
        ref = ref_of(canonical)
        pid = project_id(project or tmp_project)
        save_decision(ref, pid, action, **kwargs)
        if days_ago:
            when = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
            with session() as conn:
                conn.execute(
                    "UPDATE decisions SET decided_at=? "
                    "WHERE project_id=? AND name=? AND version=?",
                    (when, pid, ref.name, ref.version),
                )

    def fetch(canonical, project=None):
        ref = ref_of(canonical)
        with session() as conn:
            return conn.execute(
                "SELECT * FROM decisions WHERE project_id=? AND name=? "
                "AND version=?",
                (project_id(project or tmp_project), ref.name, ref.version),
            ).fetchone()

    def events():
        with session() as conn:
            return [r["event"] for r in conn.execute("SELECT event FROM audit")]

    return SimpleNamespace(
        approve=lambda c, **kw: write(c, "approve", **kw),
        reject=lambda c, **kw: write(c, "reject", **kw),
        fetch=fetch,
        events=events,
    )


def _packument(request: httpx.Request) -> httpx.Response:
    """A registry response named after the requested package.

    resolve() takes the name from the response, so a fixed name would make
    every package resolve to the same one.
    """
    name = unquote(request.url.path.lstrip("/"))
    return httpx.Response(200, json={
        "name": name,
        "dist-tags": {"latest": "1.7.2"},
        "versions": {
            version: {"license": "MIT"}
            for version in ("1.7.2", "4.17.11", "18.2.0", "3.4.0")
        },
        "time": {"1.7.2": "2026-01-01T00:00:00.000Z"},
        "maintainers": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
    })


@pytest.fixture
def route_counts(respx_mock):
    """Mock every source and count calls per source.

    Needed by any test that reaches run_intercept, since resolve() always
    queries the registry.
    """
    routes = {
        "npm-registry": respx_mock.get(url__regex=r".*registry\.npmjs\.org/.*")
            .mock(side_effect=_packument),
        "downloads": respx_mock.get(url__regex=r".*api\.npmjs\.org/.*")
            .respond(200, json={"downloads": 51_000_000}),
        "osv": respx_mock.post("https://api.osv.dev/v1/query")
            .respond(200, json={"vulns": []}),
        "github": respx_mock.get(url__regex=r".*api\.github\.com/.*")
            .respond(200, json={"archived": False, "stargazers_count": 1}),
    }

    class Counts:
        def __getitem__(self, name):
            return routes[name].call_count

        def values(self):
            return [route.call_count for route in routes.values()]

        def total(self):
            return sum(self.values())

        def collectors(self):
            """Calls to OSV and GitHub. Excludes the registry, which resolve()
            calls before decisions are checked."""
            return routes["osv"].call_count + routes["github"].call_count

    return Counts()


@pytest.fixture
def npm_calls(monkeypatch):
    """Record run_npm calls instead of running npm."""
    calls: list[list[str]] = []
    monkeypatch.setattr(openshield.run, "run_npm",
                        lambda argv: calls.append(argv) or 0)
    return calls


@pytest.fixture
def answer_yes(monkeypatch):
    monkeypatch.setattr("openshield.run.is_interactive", lambda: True)
    monkeypatch.setattr("openshield.run.prompt", lambda *a, **k: "approve")


@pytest.fixture
def answer_no(monkeypatch):
    monkeypatch.setattr("openshield.run.is_interactive", lambda: True)
    monkeypatch.setattr("openshield.run.prompt", lambda *a, **k: "reject")


@pytest.fixture
def never_prompted(monkeypatch):
    """Fails the test if the prompt is reached."""
    def explode(*a, **k):
        raise AssertionError("prompted, but a stored decision should have applied")
    monkeypatch.setattr("openshield.run.is_interactive", lambda: True)
    monkeypatch.setattr("openshield.run.prompt", explode)