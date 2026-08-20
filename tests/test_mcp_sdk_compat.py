"""MCP SDK version-compatibility tests.

The SDK renamed and relocated its high-level server class in v2.0
(``mcp.server.fastmcp.FastMCP`` -> ``mcp.server.mcpserver.MCPServer``) with no
deprecation shim, which silently broke Arkana builds when an unpinned
``mcp[cli]`` resolved to 2.0.  These tests lock in the pieces that make the
codebase work on both generations.
"""
import asyncio
import contextlib
import logging
import types

from arkana import imports as arkana_imports
from arkana import main as arkana_main


# ---------------------------------------------------------------------------
#  SDK detection shim
# ---------------------------------------------------------------------------

class TestSdkDetection:
    def test_sdk_is_available(self):
        """The installed SDK must resolve to a real server class, not the mock."""
        assert arkana_imports.MCP_SDK_AVAILABLE is True
        assert arkana_imports.MCP_SDK_IMPORT_ERROR is None

    def test_major_version_is_supported(self):
        assert arkana_imports.MCP_SDK_MAJOR in (1, 2)

    def test_version_string_recorded(self):
        """Version is captured for diagnostics regardless of which path matched."""
        assert arkana_imports.MCP_SDK_VERSION
        assert arkana_imports.MCP_SDK_VERSION.split(".")[0] == str(
            arkana_imports.MCP_SDK_MAJOR
        )

    def test_alias_points_at_the_generation_specific_class(self):
        """``FastMCP`` is the internal alias for whichever class the SDK ships."""
        expected = {
            1: ("FastMCP", "mcp.server.fastmcp"),
            2: ("MCPServer", "mcp.server.mcpserver"),
        }[arkana_imports.MCP_SDK_MAJOR]
        assert arkana_imports.FastMCP.__name__ == expected[0]
        assert arkana_imports.FastMCP.__module__.startswith(expected[1])

    def test_new_flags_are_exported(self):
        """config.py re-exports via ``import *``, so the flags need to be in __all__."""
        for name in (
            "MCP_SDK_AVAILABLE",
            "MCP_SDK_MAJOR",
            "MCP_SDK_VERSION",
            "MCP_SDK_IMPORT_ERROR",
        ):
            assert name in arkana_imports.__all__, f"{name} missing from __all__"

    def test_flags_reachable_through_config_hub(self):
        from arkana import config

        assert config.MCP_SDK_MAJOR == arkana_imports.MCP_SDK_MAJOR
        assert config.MCP_SDK_AVAILABLE is True

    def test_server_exposes_the_api_arkana_uses(self):
        """Both generations must provide the surface main.py/server.py call."""
        for attr in ("tool", "run", "sse_app", "streamable_http_app", "settings"):
            assert hasattr(arkana_imports.FastMCP, attr) or hasattr(
                arkana_imports.FastMCP("probe"), attr
            ), f"SDK server class is missing {attr!r}"


# ---------------------------------------------------------------------------
#  _apply_mcp_settings — v1 had host/port on settings, v2 does not
# ---------------------------------------------------------------------------

class _FakeServer:
    def __init__(self, settings):
        self.settings = settings



class TestApplyMcpSettings:
    def test_v1_style_settings_receive_host_and_port(self):
        cls = type("Settings", (object,), {"model_fields": {
            "host": None, "port": None, "log_level": None}})
        settings = cls()
        arkana_main._apply_mcp_settings(
            _FakeServer(settings), "0.0.0.0", 9001, logging.INFO
        )
        assert settings.host == "0.0.0.0"
        assert settings.port == 9001
        assert settings.log_level == "info"

    def test_v2_style_settings_skip_absent_host_port(self):
        """v2 dropped host/port; assigning them would raise ValueError."""
        cls = type("Settings", (object,), {"model_fields": {"log_level": None}})
        settings = cls()
        arkana_main._apply_mcp_settings(
            _FakeServer(settings), "0.0.0.0", 9001, logging.WARNING
        )
        assert settings.log_level == "warning"
        assert not hasattr(settings, "host")
        assert not hasattr(settings, "port")

    def test_assignment_error_is_swallowed(self):
        """A field that is declared but rejects assignment must not crash startup."""
        class Strict:
            model_fields = {"host": None}

            def __setattr__(self, name, value):
                raise ValueError("frozen")

        arkana_main._apply_mcp_settings(
            _FakeServer(Strict()), "127.0.0.1", 1234, logging.INFO
        )  # must not raise

    def test_missing_settings_object_is_tolerated(self):
        arkana_main._apply_mcp_settings(_FakeServer(None), "h", 1, logging.INFO)

        class NoSettings:
            pass

        arkana_main._apply_mcp_settings(NoSettings(), "h", 1, logging.INFO)

    def test_non_pydantic_settings_fall_back_to_hasattr(self):
        """The mock SDK's plain-class settings has no model_fields."""
        class Plain:
            host = "127.0.0.1"
            port = 8081
            log_level = "INFO"

        settings = Plain()
        arkana_main._apply_mcp_settings(
            _FakeServer(settings), "10.0.0.1", 4321, logging.DEBUG
        )
        assert settings.host == "10.0.0.1"
        assert settings.port == 4321
        assert settings.log_level == "debug"


# ---------------------------------------------------------------------------
#  _mcp_run_kwargs — v2 forwards **kwargs from run(); v1 does not accept them
# ---------------------------------------------------------------------------

class TestMcpRunKwargs:
    def test_matches_installed_generation(self, monkeypatch):
        if arkana_main.MCP_SDK_MAJOR >= 2:
            assert arkana_main._mcp_run_kwargs("h", 1) == {"host": "h", "port": 1}
        else:
            assert arkana_main._mcp_run_kwargs("h", 1) == {}

    def test_v1_gets_no_kwargs(self, monkeypatch):
        """v1's run() signature is (transport, mount_path) — kwargs would TypeError."""
        monkeypatch.setattr(arkana_main, "MCP_SDK_MAJOR", 1)
        assert arkana_main._mcp_run_kwargs("0.0.0.0", 9999) == {}

    def test_v2_gets_host_and_port(self, monkeypatch):
        monkeypatch.setattr(arkana_main, "MCP_SDK_MAJOR", 2)
        assert arkana_main._mcp_run_kwargs("0.0.0.0", 9999) == {
            "host": "0.0.0.0", "port": 9999,
        }


# ---------------------------------------------------------------------------
#  _mounted_lifespan — Starlette does not forward lifespan to mounted apps
# ---------------------------------------------------------------------------

def _app_with_lifespan(log, name):
    """Minimal stand-in for a Starlette app exposing router.lifespan_context."""
    @contextlib.asynccontextmanager
    async def ctx(app):
        log.append(f"{name}:startup")
        try:
            yield
        finally:
            log.append(f"{name}:shutdown")

    return types.SimpleNamespace(router=types.SimpleNamespace(lifespan_context=ctx))


class TestMountedLifespan:
    def test_runs_each_mounted_lifespan(self):
        log = []
        lifespan = arkana_main._mounted_lifespan(
            _app_with_lifespan(log, "mcp"), _app_with_lifespan(log, "dash")
        )

        async def _run():
            async with lifespan(object()):
                assert log == ["mcp:startup", "dash:startup"]

        asyncio.run(_run())
        assert log == [
            "mcp:startup", "dash:startup", "dash:shutdown", "mcp:shutdown",
        ]

    def test_skips_apps_without_a_lifespan(self):
        """The dashboard app declares no lifespan today — that must not crash."""
        log = []
        plain = types.SimpleNamespace(router=types.SimpleNamespace())
        lifespan = arkana_main._mounted_lifespan(
            _app_with_lifespan(log, "mcp"), plain, None, object()
        )

        async def _run():
            async with lifespan(object()):
                pass

        asyncio.run(_run())
        assert log == ["mcp:startup", "mcp:shutdown"]

    def test_no_apps_is_a_noop(self):
        lifespan = arkana_main._mounted_lifespan()

        async def _run():
            async with lifespan(object()):
                pass

        asyncio.run(_run())

    def test_real_sdk_app_lifespan_is_discoverable(self):
        """Guard the actual attribute path used against the installed SDK.

        This is the regression that broke HTTP mode: mounting the SDK app
        under a wrapper Starlette left its session-manager task group
        unstarted, so every MCP request 500'd with
        "Task group is not initialized".
        """
        server = arkana_imports.FastMCP("Probe")
        app = server.streamable_http_app()
        ctx = getattr(getattr(app, "router", None), "lifespan_context", None)
        assert ctx is not None and callable(ctx)
