"""Tests for the container healthcheck helper.

The check exists to answer one question -- is Arkana serving? -- without
being fooled by auth. ``/mcp`` sits behind bearer auth and HTTP transport
always has a key (auto-generated when ``--api-key`` is omitted), so an
unauthenticated probe receives 401; in stdio mode the dashboard owns the
port and has no ``/mcp`` route, so it receives 404. The previous inline
``urlopen()`` treated both as failures, leaving every container permanently
"unhealthy".
"""
import importlib.util
import urllib.error
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "docker_healthcheck",
    Path(__file__).resolve().parent.parent / "scripts" / "docker_healthcheck.py",
)
hc = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(hc)


def _http_error(code):
    return urllib.error.HTTPError("http://x/mcp", code, "err", {}, None)


@pytest.fixture
def no_pid1(monkeypatch):
    """Default: unreadable /proc/1/cmdline, so argv-derived hints are absent."""
    monkeypatch.setattr(hc, "_pid1_argv", lambda: [])
    monkeypatch.delenv("ARKANA_NO_DASHBOARD", raising=False)
    monkeypatch.delenv("ARKANA_DASHBOARD_PORT", raising=False)


class TestFlagParsing:
    @pytest.mark.parametrize("argv,expected", [
        (["a", "--mcp-port", "9000"], "9000"),
        (["a", "--mcp-port=9000"], "9000"),
        (["a", "--mcp-port"], None),
        (["a"], None),
    ])
    def test_flag_value(self, argv, expected):
        assert hc._flag_value(argv, "--mcp-port") == expected

    @pytest.mark.parametrize("argv,expected", [
        ([], 8082),
        (["--mcp-port", "9000"], 9000),
        (["--mcp-port", "notanumber"], 8082),
        (["--mcp-port", "0"], 8082),
        (["--mcp-port", "70000"], 8082),
        (["--mcp-port", "-1"], 8082),
    ])
    def test_target_port(self, argv, expected, no_pid1):
        assert hc._target_port(argv) == expected

    def test_port_falls_back_to_dashboard_env(self, monkeypatch):
        monkeypatch.setenv("ARKANA_DASHBOARD_PORT", "9100")
        assert hc._target_port([]) == 9100


class TestHttpSurfaceExpected:
    def test_streamable_http_always_expects_a_listener(self, no_pid1):
        assert hc._http_surface_expected(
            ["--mcp-transport", "streamable-http", "--no-dashboard"]) is True

    def test_sse_always_expects_a_listener(self, no_pid1):
        assert hc._http_surface_expected(["--mcp-transport", "sse"]) is True

    def test_stdio_with_dashboard_expects_a_listener(self, no_pid1):
        assert hc._http_surface_expected(["--mcp-transport", "stdio"]) is True

    def test_stdio_without_dashboard_expects_nothing(self, no_pid1):
        assert hc._http_surface_expected(
            ["--mcp-transport", "stdio", "--no-dashboard"]) is False

    def test_dashboard_disabled_by_env(self, monkeypatch, no_pid1):
        monkeypatch.setenv("ARKANA_NO_DASHBOARD", "1")
        assert hc._http_surface_expected(["--mcp-transport", "stdio"]) is False

    def test_dashboard_port_zero_expects_nothing(self, monkeypatch, no_pid1):
        monkeypatch.setenv("ARKANA_DASHBOARD_PORT", "0")
        assert hc._http_surface_expected([]) is False


class TestExitStatus:
    def test_200_is_healthy(self, monkeypatch, no_pid1):
        monkeypatch.setattr(hc.urllib.request, "urlopen",
                            lambda *a, **k: __import__("io").BytesIO(b""))
        assert hc.main() == 0

    @pytest.mark.parametrize("code", [401, 403, 404, 405, 406, 500])
    def test_any_http_status_is_healthy(self, monkeypatch, no_pid1, code):
        """A status line proves the ASGI stack answered -- 401 especially."""
        def boom(*a, **k):
            raise _http_error(code)
        monkeypatch.setattr(hc.urllib.request, "urlopen", boom)
        assert hc.main() == 0

    def test_connection_refused_is_unhealthy_when_serving(self, monkeypatch):
        monkeypatch.setattr(hc, "_pid1_argv",
                            lambda: ["python", "arkana.py",
                                     "--mcp-transport", "streamable-http"])
        def boom(*a, **k):
            raise ConnectionRefusedError("refused")
        monkeypatch.setattr(hc.urllib.request, "urlopen", boom)
        assert hc.main() == 1

    def test_timeout_is_unhealthy_when_serving(self, monkeypatch):
        monkeypatch.setattr(hc, "_pid1_argv",
                            lambda: ["python", "arkana.py",
                                     "--mcp-transport", "streamable-http"])
        def boom(*a, **k):
            raise TimeoutError("timed out")
        monkeypatch.setattr(hc.urllib.request, "urlopen", boom)
        assert hc.main() == 1

    def test_connection_refused_is_healthy_when_nothing_serves(self, monkeypatch):
        """stdio + --no-dashboard opens no socket; red forever would be noise."""
        monkeypatch.delenv("ARKANA_NO_DASHBOARD", raising=False)
        monkeypatch.delenv("ARKANA_DASHBOARD_PORT", raising=False)
        monkeypatch.setattr(hc, "_pid1_argv",
                            lambda: ["python", "arkana.py", "--mcp-server",
                                     "--mcp-transport", "stdio", "--no-dashboard"])
        def boom(*a, **k):
            raise ConnectionRefusedError("refused")
        monkeypatch.setattr(hc.urllib.request, "urlopen", boom)
        assert hc.main() == 0

    def test_unreadable_pid1_defaults_to_expecting_a_listener(self, monkeypatch, no_pid1):
        """Without argv hints, assume the dashboard is up and report honestly."""
        def boom(*a, **k):
            raise ConnectionRefusedError("refused")
        monkeypatch.setattr(hc.urllib.request, "urlopen", boom)
        assert hc.main() == 1
