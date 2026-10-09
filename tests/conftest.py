"""Shared test fixtures.

Three things live here, each wanted by more than one test file:

- the network guard (SPEC §15), which must be UNSWALLOWABLE -- see below;
- client_spy, counting sync httpx.Client constructions;
- async_client_spy, counting async httpx.AsyncClient constructions.

The spies COUNT POOLS. They do not block traffic -- both call through to the
real __init__. For "zero network calls" (M1 Step 1.4's cache hit, M2 Step 2.2's
approved-cache-hit path) rely on the guard, and assert on the evidence too.
"""
import socket

import httpx
import pytest


class RealNetworkAttempted(BaseException):
    """Raised when a test tries to reach the real network.

    BaseException, NOT Exception, and that is the whole point of this class.

    Collectors catch Exception by design (the never-raises rule), and
    asyncio.gather(return_exceptions=True) returns whatever they miss. A guard
    deriving from Exception is therefore invisible inside collect(): a
    collector that accidentally reaches the network produces a degraded source
    line rather than a failing test. NOTES-M1-inheritance.md D.1.

    collect/base.py's _survive and collect/__init__.py's _failed_evidence both
    re-raise any BaseException that is not an Exception, so this propagates all
    the way out of collect(). test_collect.py pins that permanently.
    """


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """SPEC §15: 'No test touches the network.' Enforced, not conventioned.

    Guards at the socket layer rather than httpx's transport: respx intercepts
    BELOW httpx.HTTPTransport, so patching there would block respx's own mocked
    responses. A mocked request never reaches a socket, so this is invisible to
    it; only a genuine connection attempt trips it.

    getaddrinfo is guarded too, because DNS happens BEFORE connect. Without it,
    an offline machine fails the lookup first with an ordinary ConnectError --
    which the collectors catch -- and the guard never fires.
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
    """Record each construction of `cls`, then construct normally.

    Records `self` so tests can assert IDENTITY (every collector received the
    pool that was built) and LIFECYCLE (the pool was closed), neither of which
    a count can prove. NOTES-M1-inheritance.md B.13.

    Not positional args: httpx.Client and AsyncClient take keyword-only
    arguments, so there are none to record.
    """
    calls: list[dict] = []
    original = cls.__init__

    def spy(self, *args, **kwargs):
        calls.append({"self": self, "kwargs": kwargs})
        original(self, *args, **kwargs)

    monkeypatch.setattr(cls, "__init__", spy)
    return calls


@pytest.fixture
def client_spy(monkeypatch):
    """Sync httpx.Client constructions -- resolve_all's pool.

    Separate from async_client_spy because a command line legitimately builds
    one of each; a spy conflating them could not say which layer regressed.
    """
    return _spy_on(monkeypatch, httpx.Client)


@pytest.fixture
def async_client_spy(monkeypatch):
    """Async httpx.AsyncClient constructions -- collect()'s pool."""
    return _spy_on(monkeypatch, httpx.AsyncClient)


@pytest.fixture(autouse=True)
def isolated_cache(monkeypatch, tmp_path):
    """Every test gets an empty cache in its own temp directory.

    Without this, tests read and write ~/.openshield/cache.db -- so a test
    passes or fails depending on whether you ran the tool that morning, which
    is the definition of a test you cannot trust. It also means the FIRST run
    of a suite behaves differently from the second.

    Same rule M2 applies to the shim directory: a test never touches the real
    HOME. The override is read inside cache_path() on every call, so pointing
    the env var at tmp_path is enough -- no module state to reset.
    """
    monkeypatch.setenv("OPENSHIELD_CACHE_DB", str(tmp_path / "cache.db"))


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch, tmp_path):
    """Every test sees a fresh, EMPTY config directory.

    Without this, tests read your real ~/.openshield/config.toml -- so a test
    passes or fails depending on what you configured that morning. Same rule
    as isolated_cache above, and the same rule M2 applies to the shim
    directory: a test never touches the real HOME.

    The path is deliberately inside a subdirectory that does not exist yet, so
    ensure_file() has to create it -- which is the behaviour a new user gets.
    """
    monkeypatch.setenv("OPENSHIELD_CONFIG",
                       str(tmp_path / "openshield" / "config.toml"))