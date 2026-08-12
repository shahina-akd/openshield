"""Shared test fixtures."""
import socket

import httpx
import pytest


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """SPEC §15: 'No test touches the network.' Enforced, not conventioned.

    Guards at the socket layer rather than at httpx's transport, because respx
    intercepts *below* httpx.HTTPTransport -- patching there would block respx's
    own mocked responses and fail every test in the suite. A mocked request
    never reaches a socket at all, so this fixture is invisible to it; only a
    genuine connection attempt trips it.

    Layer-agnostic on purpose: it keeps working if respx changes where it
    patches, and it catches a real request made through requests, urllib, or
    anything else that ends up at a socket.
    """
    def deny(self, *args, **kwargs):
        raise AssertionError(
            "test attempted a real network connection -- add @respx.mock, "
            "or mock the transport for this test"
        )

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)


@pytest.fixture
def client_spy(monkeypatch):
    """Records every httpx.Client construction, then constructs normally.

    Asserts a property no request count can: how many connection pools were
    opened. `resolve_all` and `collect` both exist to open exactly one per
    command line, and a refactor back to one-per-specifier is invisible to a
    call-count assertion.

    Yields the list of kwargs each client was built with, so a test can also
    assert the explicit timeout §17 requires.

    Wanted by: test_resolve.py (resolve_all), test_osv.py (collect), and from
    M1 Step 1.4 / M2 Step 2.2 the cache-hit and prior-decision paths.
    """
    calls: list[dict] = []
    original = httpx.Client.__init__

    def spy(self, *args, **kwargs):
        calls.append(kwargs)
        original(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", spy)
    return calls