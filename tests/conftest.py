"""Shared test fixtures."""
import socket

import httpx
import pytest


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