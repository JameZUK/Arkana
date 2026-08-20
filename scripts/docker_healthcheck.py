#!/usr/bin/env python3
"""Container healthcheck for Arkana. Exit 0 = healthy, 1 = unhealthy.

Two things make a naive ``urlopen(...)`` check wrong here:

1. **Any HTTP response means the server is alive.** ``/mcp`` sits behind
   bearer auth and HTTP transport *always* has a key -- one is
   auto-generated when ``--api-key`` is omitted -- so an unauthenticated
   probe gets 401 forever. In stdio mode the dashboard owns the port and
   has no ``/mcp`` route at all, so the probe gets 404. Both prove the ASGI
   stack is up and answering; treating them as failures marked every
   container unhealthy for its entire life.

2. **Some configurations serve no HTTP at all.** stdio transport with
   ``--no-dashboard`` opens no socket, so there is nothing to probe and a
   red healthcheck would be permanent and meaningless. That case reports
   healthy; liveness is the supervisor's job there, not ours.

Only a genuine connection-level failure -- refused, reset, or timed out --
when an HTTP surface *is* expected counts as unhealthy.
"""
import os
import sys
import urllib.error
import urllib.request

TIMEOUT_SECONDS = 4
DEFAULT_PORT = 8082


def _pid1_argv():
    """Argv of the container's main process, or [] if unreadable."""
    try:
        with open("/proc/1/cmdline", "rb") as fh:
            return [a.decode("utf-8", "replace") for a in fh.read().split(b"\0") if a]
    except OSError:
        return []


def _flag_value(argv, flag):
    """Value of ``--flag X`` or ``--flag=X`` in *argv*, else None."""
    for i, arg in enumerate(argv):
        if arg == flag and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(flag + "="):
            return arg.split("=", 1)[1]
    return None


def _target_port(argv):
    raw = _flag_value(argv, "--mcp-port") or os.environ.get("ARKANA_DASHBOARD_PORT")
    try:
        port = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_PORT
    return port if 1 <= port <= 65535 else DEFAULT_PORT


def _http_surface_expected(argv):
    """Whether this configuration is supposed to be listening at all."""
    transport = _flag_value(argv, "--mcp-transport") or "stdio"
    if transport in ("streamable-http", "sse"):
        return True  # the MCP endpoint itself is served over HTTP
    # stdio: only the dashboard thread listens, and it can be turned off.
    if "--no-dashboard" in argv:
        return False
    if os.environ.get("ARKANA_NO_DASHBOARD", "") == "1":
        return False
    try:
        return int(os.environ.get("ARKANA_DASHBOARD_PORT", DEFAULT_PORT)) > 0
    except ValueError:
        return True


def main():
    argv = _pid1_argv()
    url = f"http://127.0.0.1:{_target_port(argv)}/mcp"
    try:
        urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS).close()
    except urllib.error.HTTPError:
        pass  # 401/404/405/... -- the server answered, so it is alive
    except Exception:
        if _http_surface_expected(argv):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
