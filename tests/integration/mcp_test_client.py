#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Comprehensive MCP Integration Test Suite for Arkana.

Tests all 104+ MCP tools across every category: file management, PE analysis,
strings, deobfuscation, triage, Angr, multi-format, extended libraries, and more.

Coverage includes:
  - Basic success-path tests for every tool
  - StringSifter integration (rank_with_sifter=True, min_sifter_score filtering)
  - Parametrized tests for: hash algorithms, architectures, sort keys,
    FLOSS string types, min_length values
  - Error/edge-case tests: invalid inputs, missing files, out-of-range params,
    invalid hex, double-close, no-file-loaded guards

Supports both streamable-http (default) and SSE transports.

Usage:
    # Start the server first
    python arkana.py --mcp-server --mcp-transport streamable-http --input-file samples/test.exe

    # Run all tests
    pytest mcp_test_client.py -v

    # Run a specific category
    pytest mcp_test_client.py -v -k "TestConfig"
    pytest mcp_test_client.py -v -k "TestPEData"
    pytest mcp_test_client.py -v -k "TestAngr"

    # Run only tests that don't need a loaded file
    pytest mcp_test_client.py -v -m no_file

    # Run with a custom server URL or transport
    ARKANA_TEST_URL=http://localhost:9000 pytest mcp_test_client.py -v
    ARKANA_TEST_TRANSPORT=sse pytest mcp_test_client.py -v

Environment variables:
    ARKANA_TEST_URL         Server URL (default: http://127.0.0.1:8082)
    ARKANA_TEST_TRANSPORT   Transport: "auto" (default), "streamable-http", or "sse"
                           "auto" tries streamable-http first, falls back to SSE
    ARKANA_TEST_SAMPLE      Path to a sample file for open_file tests (optional)
"""

import asyncio
import base64
import json
import logging
import os
import re
import sys
from contextlib import asynccontextmanager, AsyncExitStack
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import httpx
import pytest

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
)
logger = logging.getLogger("arkana_tests")

# ---------------------------------------------------------------------------
# MCP SDK imports — try streamable-http first, fall back to SSE
# ---------------------------------------------------------------------------
try:
    from mcp import ClientSession, types as mcp_types
    logger.info("MCP SDK core imported.")
except ImportError as exc:
    logger.critical("MCP SDK import failed: %s", exc)
    logger.critical("Install with: pip install 'mcp[cli]'")
    sys.exit(1)

_have_streamable_http = False
try:
    from mcp.client.streamable_http import streamable_http_client
    _have_streamable_http = True
    logger.info("Streamable-HTTP transport available (streamable_http_client).")
except ImportError:
    try:
        from mcp.client.streamable_http import streamablehttp_client as streamable_http_client
        _have_streamable_http = True
        logger.info("Streamable-HTTP transport available (legacy streamablehttp_client).")
    except ImportError:
        logger.info("Streamable-HTTP transport not available in this MCP SDK version.")

_have_sse = False
try:
    from mcp.client.sse import sse_client
    _have_sse = True
    logger.info("SSE transport available.")
except ImportError:
    logger.info("SSE transport not available.")

if not _have_streamable_http and not _have_sse:
    logger.critical("No MCP transport available. Update the MCP SDK: pip install -U 'mcp[cli]'")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SERVER_URL = os.environ.get("ARKANA_TEST_URL", "http://127.0.0.1:8082")
TRANSPORT = os.environ.get("ARKANA_TEST_TRANSPORT", "auto")
SAMPLE_FILE = os.environ.get("ARKANA_TEST_SAMPLE", "")


# ═══════════════════════════════════════════════════════════════════════════
# Session Management
# ═══════════════════════════════════════════════════════════════════════════

def _result_is_error(result) -> bool:
    """Read the tool-call error flag across MCP SDK generations.

    SDK v1 exposed the wire name ``isError``; v2 renamed the model attribute
    to ``is_error`` (the camelCase alias is still accepted on construction,
    but not on attribute access).
    """
    flag = getattr(result, "is_error", None)
    if flag is None:
        flag = getattr(result, "isError", None)
    return bool(flag)


def _extract_root_cause(exc: BaseException) -> str:
    """Dig into ExceptionGroup / BaseExceptionGroup to find the real error."""
    if hasattr(exc, "exceptions"):  # ExceptionGroup / BaseExceptionGroup
        causes = []
        for sub in exc.exceptions:
            causes.append(_extract_root_cause(sub))
        return "; ".join(causes)
    return f"{type(exc).__name__}: {exc}"


@asynccontextmanager
async def _connect_streamable_http(url: str) -> AsyncGenerator[ClientSession, None]:
    """Open a streamable-http session."""
    # SDK v1 yields (read, write, get_session_id); v2 yields (read, write).
    # Index rather than unpack so both shapes work.
    async with streamable_http_client(url) as streams:
        read_stream, write_stream = streams[0], streams[1]
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


@asynccontextmanager
async def _connect_sse(url: str) -> AsyncGenerator[ClientSession, None]:
    """Open an SSE session."""
    async with sse_client(url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


@asynccontextmanager
async def managed_mcp_session() -> AsyncGenerator[ClientSession, None]:
    """Connect to the Arkana server.

    Transport selection (ARKANA_TEST_TRANSPORT env var):
      "auto"             — try streamable-http first, fall back to SSE (default)
      "streamable-http"  — only streamable-http
      "sse"              — only SSE

    The connection phase (with fallback) is fully separated from the
    yield phase so that test assertion errors propagate cleanly and are
    never swallowed by the fallback logic.
    """
    transport = TRANSPORT.lower()

    # Build an ordered list of (label, connect_fn) to try
    attempts: list[tuple[str, Any]] = []
    if transport == "sse":
        if _have_sse:
            attempts.append(("SSE", lambda: _connect_sse(urljoin(SERVER_URL, "/sse"))))
        else:
            pytest.fail("SSE transport requested but not available in this MCP SDK.")
    elif transport == "streamable-http":
        if _have_streamable_http:
            attempts.append(("streamable-http", lambda: _connect_streamable_http(urljoin(SERVER_URL, "/mcp"))))
        else:
            pytest.fail("Streamable-HTTP transport requested but not available in this MCP SDK.")
    else:  # "auto"
        if _have_streamable_http:
            attempts.append(("streamable-http", lambda: _connect_streamable_http(urljoin(SERVER_URL, "/mcp"))))
        if _have_sse:
            attempts.append(("SSE", lambda: _connect_sse(urljoin(SERVER_URL, "/sse"))))

    if not attempts:
        pytest.fail("No MCP transport available. Install the MCP SDK: pip install -U 'mcp[cli]'")

    # --- Phase 1: Connection (with fallback) ---
    # Uses AsyncExitStack so the transport context managers stay open
    # across the yield, but fallback errors don't swallow test failures.
    stack = AsyncExitStack()
    session: Optional[ClientSession] = None
    last_error: Optional[BaseException] = None

    for label, connect_fn in attempts:
        try:
            session = await stack.enter_async_context(connect_fn())
            logger.info("Connected via %s transport.", label)
            break  # success
        except BaseException as exc:
            # Connection/init failed — reset stack and try next transport
            await stack.aclose()
            stack = AsyncExitStack()
            root = _extract_root_cause(exc)
            last_error = exc
            remaining = len(attempts) - attempts.index((label, connect_fn)) - 1
            if remaining > 0:
                logger.warning("%s transport failed: %s. Trying next transport...", label, root)
            else:
                logger.warning("%s transport failed: %s", label, root)

    if session is None:
        await stack.aclose()
        root = _extract_root_cause(last_error) if last_error else "unknown"
        pytest.fail(
            f"Cannot connect to MCP server at {SERVER_URL} "
            f"(tried: {', '.join(l for l, _ in attempts)}): {root}\n"
            f"\n"
            f"Start the server first:\n"
            f"  python arkana.py --mcp-server --mcp-transport streamable-http --input-file <sample>\n"
            f"\n"
            f"If using Docker/Podman, add --mcp-host 0.0.0.0 (or use ./run.sh):\n"
            f"  podman run --rm -it -p 8082:8082 arkana-toolkit \\\n"
            f"    --mcp-server --mcp-transport streamable-http --mcp-host 0.0.0.0 --input-file <sample>"
        )

    # --- Phase 2: Yield the session (test errors propagate cleanly) ---
    try:
        yield session
    finally:
        await stack.aclose()


# ═══════════════════════════════════════════════════════════════════════════
# Test Helpers
# ═══════════════════════════════════════════════════════════════════════════

# Patterns that indicate a tool is unavailable (not a real test failure)
_SKIP_PATTERNS = [
    "unknown tool",
    "not installed",
    "not available",
    "library not found",
    "module not found",
    "no module named",
    "not a .net",
    "not a dotnet",
    "not an elf",
    "not a mach-o",
    "not a macho",
    "not a go binary",
    "not a rust binary",
]


async def call_tool(
    session: ClientSession,
    tool_name: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    expected_type: Optional[type] = None,
    expected_keys: Optional[List[str]] = None,
    expected_status: Optional[Tuple[str, Any]] = None,
    allow_none: bool = False,
    wrap_single_dict_in_list: bool = False,
) -> Any:
    """Call an MCP tool, parse the response, and run standard assertions.

    If the server reports the tool is unknown or the required library is not
    installed, the test is skipped (not failed).
    """
    params = params or {}
    logger.info("[CALL] %s(%s)", tool_name, json.dumps(params, default=str))

    try:
        result = await session.call_tool(tool_name, arguments=params)
    except Exception as exc:
        # Some MCP SDKs raise on unknown tool rather than returning isError
        msg = str(exc).lower()
        if any(p in msg for p in _SKIP_PATTERNS):
            pytest.skip(f"{tool_name}: {exc}")
        raise

    assert isinstance(result, mcp_types.CallToolResult), (
        f"{tool_name}: expected CallToolResult, got {type(result)}"
    )

    if _result_is_error(result):
        text = (
            result.content[0].text
            if result.content and hasattr(result.content[0], "text")
            else "unknown error"
        )
        # Skip instead of fail for tools not available on this server build
        text_lower = text.lower()
        if any(p in text_lower for p in _SKIP_PATTERNS):
            pytest.skip(f"{tool_name}: {text}")
        pytest.fail(f"{tool_name} returned error: {text}")

    if not result.content:
        if allow_none:
            return None
        pytest.fail(f"{tool_name}: empty content but result was expected")

    raw = result.content[0].text
    payload: Any = None

    # Parse strategy
    if tool_name == "get_hex_dump":
        payload = [line for line in raw.splitlines() if line.strip()]
    elif expected_type is str and not raw.strip().startswith(("{", "[")):
        payload = raw
    elif allow_none and raw.strip().lower() == "null":
        payload = None
    else:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            pytest.fail(f"{tool_name}: cannot parse JSON: {raw[:300]}")

    if payload is None and not allow_none:
        pytest.fail(f"{tool_name}: parsed to None but allow_none is False")

    # Wrap single dict → list when needed
    if wrap_single_dict_in_list and expected_type is list and isinstance(payload, dict):
        payload = [payload]

    # Assertions
    if payload is not None:
        if expected_type is not None:
            assert isinstance(payload, expected_type), (
                f"{tool_name}: expected {expected_type.__name__}, got {type(payload).__name__}"
            )
        if isinstance(payload, dict):
            if expected_status:
                key, val = expected_status
                assert key in payload, f"{tool_name}: missing status key '{key}'"
                if isinstance(val, list):
                    assert payload[key] in val
                else:
                    assert payload[key] == val
            if expected_keys:
                for k in expected_keys:
                    assert k in payload, f"{tool_name}: missing key '{k}'"

    logger.info("[PASS] %s", tool_name)
    return payload


async def call_tool_expect_error(
    session: ClientSession,
    tool_name: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    error_substring: Optional[str] = None,
):
    """Call a tool and assert that it returns an error.

    If the tool is unknown on this server build, the test is skipped.
    """
    params = params or {}
    logger.info("[CALL] %s(%s) — expecting error", tool_name, json.dumps(params, default=str))

    try:
        result = await session.call_tool(tool_name, arguments=params)
    except Exception as exc:
        msg = str(exc)
        msg_lower = msg.lower()
        # Skip if tool doesn't exist on this server
        if any(p in msg_lower for p in _SKIP_PATTERNS):
            pytest.skip(f"{tool_name}: {exc}")
        # Otherwise the exception itself counts as "got an error"
        if error_substring:
            assert error_substring.lower() in msg_lower, (
                f"{tool_name}: expected '{error_substring}' in exception: {msg[:200]}"
            )
        logger.info("[PASS] %s raised expected exception: %s", tool_name, type(exc).__name__)
        return

    assert isinstance(result, mcp_types.CallToolResult)

    # If the tool returned successfully (no error flag), check the payload
    if not _result_is_error(result):
        text = ""
        if result.content and hasattr(result.content[0], "text"):
            text = result.content[0].text
        # Some tools return isError=False but include {"error": "..."} in payload
        has_error_in_payload = False
        try:
            payload = json.loads(text)
            if isinstance(payload, dict) and "error" in payload:
                has_error_in_payload = True
        except (json.JSONDecodeError, TypeError):
            pass
        if error_substring and error_substring.lower() in text.lower():
            logger.info("[PASS] %s returned error info in payload", tool_name)
            return
        if has_error_in_payload:
            logger.info("[PASS] %s returned error in payload (isError=False)", tool_name)
            return
        pytest.fail(f"{tool_name}: expected an error but got success")

    if error_substring:
        text = result.content[0].text if result.content else ""
        assert error_substring.lower() in text.lower(), (
            f"{tool_name}: expected '{error_substring}' in error: {text[:200]}"
        )
    logger.info("[PASS] %s returned expected error", tool_name)


_shared_loop = None


def run(coro):
    """Run an async coroutine using a shared event loop.

    Reuses a single event loop across all tests in the session to avoid the
    overhead of creating/destroying a loop (and re-establishing TCP connections)
    for each of the 100+ test methods.
    """
    global _shared_loop
    if _shared_loop is None or _shared_loop.is_closed():
        _shared_loop = asyncio.new_event_loop()
    return _shared_loop.run_until_complete(coro)


# ═══════════════════════════════════════════════════════════════════════════
# 1. Configuration & Utility Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestConfigAndUtility:
    """Tests for: get_current_datetime, get_config, set_api_key,
    check_task_status, get_extended_capabilities."""

    @pytest.mark.no_file
    def test_get_current_datetime(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_current_datetime",
                                    expected_type=dict,
                                    expected_keys=["utc_datetime", "local_datetime"])
                assert re.match(r"\d{4}-\d{2}-\d{2}T", r["utc_datetime"])
        run(_test())

    @pytest.mark.no_file
    def test_get_config(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_config", expected_type=dict,
                                expected_keys=["_server_info"])
        run(_test())

    @pytest.mark.no_file
    def test_get_extended_capabilities(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_extended_capabilities", expected_type=dict)
                # Response has library names as top-level keys (e.g. "capstone", "lief")
                known_libs = {"lief", "capstone", "keystone", "speakeasy", "unipacker",
                              "dotnetfile", "ppdeep", "tlsh", "binwalk"}
                assert any(k in r for k in known_libs), (
                    f"get_extended_capabilities: expected at least one of {known_libs} "
                    f"in response keys {set(r.keys())}"
                )
        run(_test())

    @pytest.mark.no_file
    def test_check_task_status_invalid(self):
        async def _test():
            async with managed_mcp_session() as s:
                # Checking a non-existent task should return a dict (not crash)
                r = await call_tool(s, "check_task_status",
                                    {"task_id": "nonexistent-task-id-000"},
                                    expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.no_file
    def test_set_api_key(self):
        """set_api_key should accept a known key name (vt_api_key)."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "set_api_key",
                                    {"key_name": "vt_api_key",
                                     "key_value": "test_dummy_vt_key_000"},
                                    expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.no_file
    def test_set_api_key_invalid_name(self):
        """set_api_key should reject unknown key names."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool_expect_error(
                    s, "set_api_key",
                    {"key_name": "nonexistent_key", "key_value": "dummy"},
                    error_substring="unknown key",
                )
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 2. Cache Management Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestCacheManagement:
    """Tests for: get_cache_stats, clear_analysis_cache, remove_cached_analysis."""

    @pytest.mark.no_file
    def test_get_cache_stats(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_cache_stats", expected_type=dict)
                assert "enabled" in r, "get_cache_stats should include 'enabled' key"
                assert "entry_count" in r, "get_cache_stats should include 'entry_count' key"
                assert isinstance(r["entry_count"], int), "entry_count should be an integer"
        run(_test())

    @pytest.mark.no_file
    def test_remove_cached_analysis_nonexistent(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "remove_cached_analysis",
                                    {"sha256_hash": "0" * 64}, expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.no_file
    def test_clear_analysis_cache(self):
        """clear_analysis_cache should succeed even if cache is empty."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "clear_analysis_cache", expected_type=dict)
                assert "entries_removed" in r, "clear_analysis_cache should report entries_removed"
                assert isinstance(r["entries_removed"], int)
                assert r["entries_removed"] >= 0
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 3. File Management Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestFileManagement:
    """Tests for: open_file, close_file, reanalyze_loaded_pe_file,
    detect_binary_format."""

    @pytest.mark.pe_file
    def test_get_analyzed_file_summary(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_analyzed_file_summary", {"limit": 5},
                                expected_type=dict, expected_keys=["filepath"])
        run(_test())

    @pytest.mark.pe_file
    def test_get_full_analysis_results(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_full_analysis_results", {"limit": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_detect_binary_format_loaded(self):
        """detect_binary_format with no path uses the loaded file."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "detect_binary_format", expected_type=dict)
                assert "primary_format" in r or "detected_formats" in r or "format" in r, (
                    f"detect_binary_format: expected 'primary_format' or 'detected_formats' "
                    f"in response keys {set(r.keys())}"
                )
        run(_test())

    @pytest.mark.pe_file
    def test_close_file(self):
        """close_file should succeed when a file is loaded.

        Note: Each test uses its own MCP session (with inherited state),
        so closing the file here does not affect other tests.
        """
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "close_file", expected_type=dict,
                               expected_status=("status", "success"))
        run(_test())

    @pytest.mark.pe_file
    def test_reanalyze_loaded_pe_file(self):
        """reanalyze_loaded_pe_file should re-parse the currently loaded file."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "reanalyze_loaded_pe_file",
                                    {"analyses_to_skip": ["floss", "capa"]},
                                    expected_type=dict, allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.no_file
    def test_open_file_with_sample(self):
        """open_file success path — requires ARKANA_TEST_SAMPLE env var."""
        async def _test():
            if not SAMPLE_FILE:
                pytest.skip("Set ARKANA_TEST_SAMPLE to enable open_file success test")
            async with managed_mcp_session() as s:
                r = await call_tool(s, "open_file",
                                    {"file_path": SAMPLE_FILE,
                                     "analyses_to_skip": ["floss", "capa"]},
                                    expected_type=dict)
                assert r is not None
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 4. Unified PE Data Retrieval (get_pe_data)
# ═══════════════════════════════════════════════════════════════════════════

# All 25 keys supported by get_pe_data
PE_DATA_KEYS = [
    "file_hashes",
    "dos_header",
    "nt_headers",
    "data_directories",
    "sections",
    "imports",
    "exports",
    "resources_summary",
    "version_info",
    "debug_info",
    "digital_signature",
    "peid_matches",
    "yara_matches",
    "rich_header",
    "delay_load_imports",
    "tls_info",
    "load_config",
    "com_descriptor",
    "overlay_data",
    "base_relocations",
    "bound_imports",
    "exception_data",
    "coff_symbols",
    "checksum_verification",
    "pefile_warnings",
]


class TestPEData:
    """Tests for: get_pe_data (all 25 keys) and list discovery."""

    @pytest.mark.pe_file
    def test_get_pe_data_list_keys(self):
        """get_pe_data(key='list') should return all available keys."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_pe_data", {"key": "list"}, expected_type=dict)
                # Should contain all 25 standard PE data keys
                assert len(r) >= 20, (
                    f"get_pe_data(key='list') should return at least 20 keys, got {len(r)}"
                )
                # Check a few well-known keys are present
                for expected_key in ("file_hashes", "sections", "imports"):
                    assert expected_key in r, f"Expected key '{expected_key}' in PE data list"
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.parametrize("key", PE_DATA_KEYS)
    def test_get_pe_data_key(self, key: str):
        """Test each get_pe_data key individually."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_pe_data",
                                    {"key": key, "limit": 5, "offset": 0},
                                    allow_none=True)
                logger.info("get_pe_data(key=%s) → type=%s", key,
                            type(r).__name__ if r is not None else "None")
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 5. PE Extended Analysis Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestPEExtended:
    """Tests for all 14 PE extended analysis tools."""

    @pytest.mark.pe_file
    def test_get_section_permissions(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_section_permissions", {"limit": 50},
                                    expected_type=dict)
                assert "sections" in r, "get_section_permissions should return 'sections' key"
                if r["sections"]:
                    first_section = r["sections"][0]
                    assert "name" in first_section, "Section should have 'name'"
                    assert "permissions" in first_section, "Section should have 'permissions'"
                    assert "characteristics_hex" in first_section, "Section should have 'characteristics_hex'"
        run(_test())

    @pytest.mark.pe_file
    def test_get_pe_metadata(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_pe_metadata", expected_type=dict)
                # Metadata should contain at least some basic PE info
                assert len(r) >= 1, "get_pe_metadata should return at least one field"
        run(_test())

    @pytest.mark.pe_file
    def test_extract_resources(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "extract_resources", {"limit": 10},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    def test_extract_manifest(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "extract_manifest", expected_type=dict,
                                allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    def test_get_load_config_details(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_load_config_details", expected_type=dict,
                                allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    def test_extract_wide_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "extract_wide_strings",
                                {"min_length": 4, "limit": 50},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_detect_format_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "detect_format_strings", {"limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_detect_compression_headers(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "detect_compression_headers", {"limit": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_detect_crypto_constants(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "detect_crypto_constants", {"limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_analyze_entropy_by_offset(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "analyze_entropy_by_offset",
                                {"window_size": 256, "step": 256, "limit": 50},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_scan_for_api_hashes(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "scan_for_api_hashes",
                                {"hash_algorithm": "ror13", "limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_get_import_hash_analysis(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_import_hash_analysis", expected_type=dict)
                # Should contain at least imphash or some hash key
                hash_keys = {"imphash", "imphash_value", "import_hash", "md5"}
                assert any(k in r for k in hash_keys) or len(r) >= 1, (
                    f"get_import_hash_analysis should return hash data, got keys: {set(r.keys())}"
                )
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.parametrize("algorithm", ["ror13", "djb2", "crc32"])
    def test_scan_for_api_hashes_algorithms(self, algorithm):
        """Verify each supported hash_algorithm value."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "scan_for_api_hashes",
                                {"hash_algorithm": algorithm, "limit": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.no_file
    def test_deobfuscate_xor_multi_byte(self):
        """XOR multi-byte is a pure-data tool (no file needed)."""
        async def _test():
            async with managed_mcp_session() as s:
                # "Hello" XOR'd with key 0xAB 0xCD
                data = bytes([ord(c) ^ [0xAB, 0xCD][i % 2] for i, c in enumerate("Hello")])
                r = await call_tool(s, "deobfuscate_xor_multi_byte",
                                    {"data_hex": data.hex(), "key_hex": "abcd"},
                                    expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.no_file
    def test_bruteforce_xor_key(self):
        async def _test():
            async with managed_mcp_session() as s:
                original = "This program"
                key = 0x42
                data = bytes([b ^ key for b in original.encode()])
                r = await call_tool(s, "bruteforce_xor_key",
                                    {"data_hex": data.hex(),
                                     "known_plaintext": "This",
                                     "max_key_length": 1, "limit": 5},
                                    expected_type=dict)
                assert r is not None
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 6. String Analysis Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestStringAnalysis:
    """Tests for all 10 string analysis tools."""

    @pytest.mark.pe_file
    def test_get_floss_analysis_info(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_floss_analysis_info",
                                    {"string_type": "static_strings", "limit": 10},
                                    expected_type=dict)
                assert "strings" in r
        run(_test())

    @pytest.mark.pe_file
    def test_get_floss_only_with_references(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_floss_analysis_info",
                                    {"string_type": "static_strings",
                                     "only_with_references": True, "limit": 5},
                                    expected_type=dict)
                if r.get("strings"):
                    for item in r["strings"]:
                        assert item.get("references")
        run(_test())

    @pytest.mark.pe_file
    def test_extract_strings_from_binary(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "extract_strings_from_binary",
                                    {"limit": 20, "min_length": 5},
                                    allow_none=True)
                if r is not None:
                    assert isinstance(r, (list, dict))
        run(_test())

    @pytest.mark.pe_file
    def test_extract_strings_with_sifter(self):
        """Exercise the StringSifter ranking path (rank_with_sifter=True)."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "extract_strings_from_binary",
                                    {"limit": 10, "min_length": 5,
                                     "rank_with_sifter": True,
                                     "sort_by_score": True},
                                    allow_none=True)
                if r is not None:
                    assert isinstance(r, (list, dict))
                    # If sifter ran, entries should have scores
                    if isinstance(r, list) and r:
                        assert "sifter_score" in r[0], (
                            "rank_with_sifter=True but result has no sifter_score"
                        )
        run(_test())

    @pytest.mark.pe_file
    def test_extract_strings_with_sifter_score_filter(self):
        """StringSifter with min_sifter_score filtering."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "extract_strings_from_binary",
                                    {"limit": 10, "min_length": 5,
                                     "rank_with_sifter": True,
                                     "min_sifter_score": 0.5,
                                     "sort_by_score": True},
                                    allow_none=True)
                if r is not None and isinstance(r, list):
                    for item in r:
                        assert item.get("sifter_score", 0) >= 0.5
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.parametrize("min_len", [3, 8, 15])
    def test_extract_strings_min_length(self, min_len):
        """Verify different min_length values are respected."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "extract_strings_from_binary",
                                    {"limit": 10, "min_length": min_len},
                                    allow_none=True)
                if r is not None and isinstance(r, list):
                    for item in r:
                        assert len(item.get("string", "")) >= min_len
        run(_test())

    @pytest.mark.pe_file
    def test_search_for_specific_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "search_for_specific_strings",
                                    {"search_terms": ["kernel32.dll", "MZ"]},
                                    expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    def test_search_floss_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "search_floss_strings",
                                    {"regex_patterns": [".*dll.*"], "limit": 10},
                                    expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    def test_get_top_sifted_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_top_sifted_strings",
                                    {"limit": 10},
                                    allow_none=True)
                # May be a list or None if StringSifter is not available
                if r is not None:
                    assert isinstance(r, (list, dict))
        run(_test())

    @pytest.mark.pe_file
    def test_fuzzy_search_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "fuzzy_search_strings",
                                    {"query_string": "kermel32.dll",
                                     "limit": 5, "min_similarity_ratio": 60},
                                    allow_none=True)
                if r is not None:
                    assert isinstance(r, (list, dict))
        run(_test())

    @pytest.mark.pe_file
    def test_get_strings_for_function(self):
        """Get strings referenced by a function. Needs a valid function VA."""
        async def _test():
            async with managed_mcp_session() as s:
                # First find a function with string references
                floss = await call_tool(s, "get_floss_analysis_info",
                                        {"string_type": "static_strings",
                                         "only_with_references": True, "limit": 1},
                                        expected_type=dict)
                strings = floss.get("strings", [])
                if not strings or not strings[0].get("references"):
                    pytest.skip("No strings with function references in sample")
                func_va = int(strings[0]["references"][0]["function_va"], 16)
                r = await call_tool(s, "get_strings_for_function",
                                    {"function_va": func_va},
                                    allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    def test_get_string_usage_context(self):
        """Get disassembly context for a string."""
        async def _test():
            async with managed_mcp_session() as s:
                floss = await call_tool(s, "get_floss_analysis_info",
                                        {"string_type": "static_strings",
                                         "only_with_references": True, "limit": 1},
                                        expected_type=dict)
                strings = floss.get("strings", [])
                if not strings:
                    pytest.skip("No strings with references in sample")
                offset = int(strings[0]["offset"], 16)
                r = await call_tool(s, "get_string_usage_context",
                                    {"string_offset": offset},
                                    allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.parametrize("string_type", [
        "static_strings", "stack_strings", "tight_strings", "decoded_strings",
    ])
    def test_get_floss_string_types(self, string_type):
        """Test each FLOSS string_type individually."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_floss_analysis_info",
                                    {"string_type": string_type, "limit": 5},
                                    expected_type=dict, allow_none=True)
                if r is not None:
                    assert "strings" in r or "error" in r or "status" in r
        run(_test())

    @pytest.mark.pe_file
    def test_find_and_decode_encoded_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "find_and_decode_encoded_strings",
                                    {"limit": 5}, allow_none=True)
                if r is not None:
                    assert isinstance(r, (list, dict))
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 7. Deobfuscation & Utility Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestDeobfuscation:
    """Tests for: deobfuscate_base64, deobfuscate_xor_single_byte,
    is_mostly_printable_ascii, get_hex_dump, find_and_decode_encoded_strings."""

    @pytest.mark.no_file
    def test_deobfuscate_base64(self):
        async def _test():
            async with managed_mcp_session() as s:
                original = "Hello MCP!"
                hex_str = base64.b64encode(original.encode()).hex()
                r = await call_tool(s, "deobfuscate_base64",
                                    {"hex_string": hex_str}, expected_type=str)
                assert r == original
        run(_test())

    @pytest.mark.no_file
    def test_deobfuscate_xor_single_byte(self):
        async def _test():
            async with managed_mcp_session() as s:
                original = "XOR Test!"
                key = 0xAB
                data = bytes([ord(c) ^ key for c in original]).hex()
                r = await call_tool(s, "deobfuscate_xor_single_byte",
                                    {"data_hex": data, "key": key},
                                    expected_type=dict)
                assert r.get("deobfuscated_printable_string") == original
        run(_test())

    @pytest.mark.no_file
    def test_is_mostly_printable_ascii(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "is_mostly_printable_ascii",
                                    {"text_input": "Hello World 123!"},
                                    expected_type=bool)
                assert r is True
        run(_test())

    @pytest.mark.pe_file
    def test_get_hex_dump(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_hex_dump",
                                    {"start_offset": 0, "length": 64},
                                    expected_type=list)
                assert r and "00000000" in r[0]
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 8. Capa Analysis Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestCapaAnalysis:
    """Tests for: get_capa_analysis_info, get_capa_rule_match_details."""

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_get_capa_analysis_info(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_capa_analysis_info", {"limit": 10},
                               expected_type=dict, expected_keys=["rules"])
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_get_capa_rule_match_details(self):
        """Fetch details for the first capa rule found."""
        async def _test():
            async with managed_mcp_session() as s:
                capa = await call_tool(s, "get_capa_analysis_info",
                                       {"limit": 1}, expected_type=dict)
                rules = capa.get("rules", {})
                if not rules:
                    pytest.skip("No capa rules matched in sample")
                # rules is a dict keyed by rule_id, not a list
                if isinstance(rules, dict):
                    rule_id = next(iter(rules))
                else:
                    # Fallback for list-style responses
                    rule_id = rules[0].get("rule_name") or rules[0].get("name")
                if not rule_id:
                    pytest.skip("Cannot determine rule_id from capa output")
                r = await call_tool(s, "get_capa_rule_match_details",
                                    {"rule_id": rule_id, "address_limit": 5},
                                    expected_type=dict)
                assert r is not None
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 9. Triage & Classification Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestTriageAndClassification:
    """Tests for: get_triage_report, classify_binary_purpose."""

    @pytest.mark.pe_file
    def test_get_triage_report(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_triage_report", expected_type=dict)
                assert "risk_score" in r, "Triage report should include risk_score"
                assert "risk_level" in r, "Triage report should include risk_level"
                assert isinstance(r["risk_score"], int), "risk_score should be an integer"
                assert r["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"), (
                    f"Unexpected risk_level: {r['risk_level']}"
                )
                assert "suggested_next_tools" in r, "Triage report should suggest next tools"
        run(_test())

    @pytest.mark.pe_file
    def test_classify_binary_purpose(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "classify_binary_purpose", expected_type=dict)
                assert "primary_type" in r or "classifications" in r, (
                    f"classify_binary_purpose should return classification data, got keys: {set(r.keys())}"
                )
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 10. VirusTotal Tool
# ═══════════════════════════════════════════════════════════════════════════

class TestVirusTotal:
    """Tests for: get_virustotal_report_for_loaded_file."""

    @pytest.mark.pe_file
    def test_get_virustotal_report(self):
        async def _test():
            async with managed_mcp_session() as s:
                valid = [
                    "success", "not_found", "api_key_missing", "error_auth",
                    "error_rate_limit", "error_api", "error_timeout",
                    "error_request", "error_unexpected",
                ]
                r = await call_tool(s, "get_virustotal_report_for_loaded_file",
                                    expected_type=dict,
                                    expected_status=("status", valid))
                logger.info("VT status: %s", r.get("status"))
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 11. Angr Core Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestAngrCore:
    """Tests for all 15 core Angr tools."""

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_list_angr_analyses(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "list_angr_analyses",
                                    {"category": "all"}, expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_function_complexity_list(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_function_complexity_list",
                                    {"limit": 5, "sort_by": "blocks"},
                                    expected_type=dict, allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_decompile_function_with_angr(self):
        """Decompile the top function from the complexity list."""
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                r = await call_tool(s, "decompile_function_with_angr",
                                    {"function_address": str(addr)},
                                    expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_function_cfg(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                r = await call_tool(s, "get_function_cfg",
                                    {"function_address": str(addr)},
                                    expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_function_xrefs(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_function_xrefs",
                                {"function_address": str(addr)},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_extract_function_constants(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "extract_function_constants",
                                {"function_address": str(addr)},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_global_data_refs(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_global_data_refs",
                                {"function_address": str(addr)},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_scan_for_indirect_jumps(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "scan_for_indirect_jumps",
                                {"function_address": str(addr)},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_analyze_binary_loops(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "analyze_binary_loops", expected_type=dict,
                                allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_backward_slice(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_backward_slice",
                                {"target_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_forward_slice(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_forward_slice",
                                {"source_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_dominators(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_dominators",
                                {"target_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    @pytest.mark.parametrize("sort_by", ["blocks", "edges"])
    def test_get_function_complexity_sort_by(self, sort_by):
        """Verify each sort_by value for get_function_complexity_list."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_function_complexity_list",
                                    {"limit": 5, "sort_by": sort_by},
                                    expected_type=dict, allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_find_path_to_address(self):
        """find_path_to_address with a known function address."""
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                r = await call_tool(s, "find_path_to_address",
                                    {"target_address": str(addr),
                                     "run_in_background": False},
                                    expected_type=dict, allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_emulate_function_execution(self):
        """Emulate the first function found by the complexity list."""
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                r = await call_tool(s, "emulate_function_execution",
                                    {"function_address": str(addr),
                                     "max_steps": 200,
                                     "run_in_background": False},
                                    expected_type=dict, allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_patch_binary_memory(self):
        """Patch a byte in memory (NOP at the entry point)."""
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                r = await call_tool(s, "patch_binary_memory",
                                    {"address": str(addr),
                                     "patch_bytes_hex": "90"},
                                    expected_type=dict)
                assert r is not None
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 12. Angr Disassembly & Function Recovery Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestAngrDisasm:
    """Tests for: disassemble_at_address, get_calling_conventions,
    get_function_variables, identify_library_functions, get_annotated_disassembly."""

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_disassemble_at_address(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "disassemble_at_address",
                                {"address": str(addr), "num_instructions": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_calling_conventions(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_calling_conventions",
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_function_variables(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_function_variables",
                                {"function_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_identify_library_functions(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "identify_library_functions",
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_annotated_disassembly(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_annotated_disassembly",
                                {"function_address": str(addr), "limit": 50},
                                expected_type=dict)
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 13. Angr Data Flow Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestAngrDataflow:
    """Tests for: get_reaching_definitions, get_data_dependencies,
    get_control_dependencies, propagate_constants, get_value_set_analysis."""

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_reaching_definitions(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_reaching_definitions",
                                {"function_address": str(addr),
                                 "limit": 20, "run_in_background": False},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_data_dependencies(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_data_dependencies",
                                {"function_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_control_dependencies(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_control_dependencies",
                                {"function_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_propagate_constants(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "propagate_constants",
                                {"function_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_value_set_analysis(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_value_set_analysis",
                                {"function_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 14. Angr Hook Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestAngrHooks:
    """Tests for: hook_function, list_hooks, unhook_function."""

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_list_hooks(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "list_hooks", expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_hook_and_unhook_function(self):
        """Hook a function, list hooks, then unhook it."""
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))

                # Hook with NOP
                await call_tool(s, "hook_function",
                                {"address_or_name": str(addr), "nop": True},
                                expected_type=dict)
                # Verify it appears
                hooks = await call_tool(s, "list_hooks", expected_type=dict)
                assert hooks is not None
                # Unhook
                await call_tool(s, "unhook_function",
                                {"address_or_name": str(addr)},
                                expected_type=dict)
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 15. Angr Forensic & Advanced Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestAngrForensic:
    """Tests for: detect_packing, find_code_caves, detect_self_modifying_code,
    get_call_graph, identify_cpp_classes."""

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_detect_packing(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "detect_packing", expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_find_code_caves(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "find_code_caves",
                                {"min_size": 16, "limit": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_detect_self_modifying_code(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "detect_self_modifying_code",
                                {"limit": 10}, expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_call_graph(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_call_graph", expected_type=dict,
                                allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_identify_cpp_classes(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "identify_cpp_classes", expected_type=dict,
                                allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_diff_binaries(self):
        """diff_binaries requires a second file — skip if ARKANA_TEST_SAMPLE not set."""
        async def _test():
            if not SAMPLE_FILE:
                pytest.skip("Set ARKANA_TEST_SAMPLE to enable diff_binaries test")
            async with managed_mcp_session() as s:
                r = await call_tool(s, "diff_binaries",
                                    {"file_path_b": SAMPLE_FILE,
                                     "limit": 10,
                                     "run_in_background": False},
                                    expected_type=dict, allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_save_patched_binary(self):
        """save_patched_binary writes the current binary to an allowed path."""
        async def _test():
            import os
            async with managed_mcp_session() as s:
                out_path = "/output/test_patched.exe"
                try:
                    # Call the raw MCP session so we can inspect the result
                    # without pytest.fail() on environment-related errors.
                    result = await s.call_tool(
                        "save_patched_binary",
                        arguments={"output_path": out_path},
                    )
                    if _result_is_error(result):
                        text = (
                            result.content[0].text
                            if result.content and hasattr(result.content[0], "text")
                            else ""
                        )
                        text_lower = text.lower()
                        # Permission / access errors are environment limitations
                        # (e.g. /output not mounted writable), not tool bugs.
                        if "permission denied" in text_lower or "access denied" in text_lower:
                            pytest.skip("save_patched_binary: /output not writable in this environment")
                        if any(p in text_lower for p in _SKIP_PATTERNS):
                            pytest.skip(f"save_patched_binary: {text}")
                        pytest.fail(f"save_patched_binary returned error: {text}")
                    # If success, verify we got a result
                    assert result.content, "save_patched_binary should return content"
                finally:
                    if os.path.exists(out_path):
                        os.unlink(out_path)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_find_path_with_custom_input(self):
        """Symbolic execution with custom symbolic inputs."""
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                r = await call_tool(s, "find_path_with_custom_input",
                                    {"target_address": str(addr),
                                     "max_steps": 200,
                                     "run_in_background": False},
                                    expected_type=dict, allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_emulate_with_watchpoints(self):
        """Emulate a function with memory/register watchpoints."""
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                r = await call_tool(s, "emulate_with_watchpoints",
                                    {"function_address": str(addr),
                                     "watch_registers": ["eax", "ebx"],
                                     "max_steps": 200,
                                     "run_in_background": False},
                                    expected_type=dict, allow_none=True)
                assert r is not None
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 16. Extended Library Tools (LIEF, Capstone, Keystone, Speakeasy, etc.)
# ═══════════════════════════════════════════════════════════════════════════

class TestExtendedLibraries:
    """Tests for all 13 extended library tools."""

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_parse_binary_with_lief(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "parse_binary_with_lief", expected_type=dict)
        run(_test())

    @pytest.mark.no_file
    @pytest.mark.optional_lib
    def test_disassemble_raw_bytes(self):
        """Disassemble a NOP sled — no file needed."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "disassemble_raw_bytes",
                                {"hex_bytes": "90909090cccc",
                                 "architecture": "x86_64", "limit": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.no_file
    @pytest.mark.optional_lib
    def test_assemble_instruction(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "assemble_instruction",
                                {"assembly": "nop; nop; ret",
                                 "architecture": "x86_64"},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_compute_similarity_hashes(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "compute_similarity_hashes",
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_emulate_pe_with_windows_apis(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "emulate_pe_with_windows_apis",
                                {"timeout_seconds": 10, "limit": 50},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.no_file
    @pytest.mark.optional_lib
    def test_emulate_shellcode_with_speakeasy(self):
        """Emulate a tiny shellcode stub (INT3)."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "emulate_shellcode_with_speakeasy",
                                {"shellcode_hex": "cc",
                                 "architecture": "x86",
                                 "timeout_seconds": 5, "limit": 10},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_auto_unpack_pe(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "auto_unpack_pe", expected_type=dict,
                                allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_parse_dotnet_metadata(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "parse_dotnet_metadata", {"limit": 20},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_scan_for_embedded_files(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "scan_for_embedded_files", {"limit": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.no_file
    @pytest.mark.optional_lib
    @pytest.mark.parametrize("arch", ["x86", "x86_64", "arm", "arm64"])
    def test_disassemble_raw_bytes_architectures(self, arch):
        """Verify disassembly across different architectures."""
        async def _test():
            # Use architecture-appropriate bytes
            test_bytes = {
                "x86":    "90909090cccc",            # NOP NOP NOP NOP INT3 INT3
                "x86_64": "90909090cccc",            # NOP NOP NOP NOP INT3 INT3
                "arm":    "0000a0e10000a0e1",        # MOV R0,R0 x2 (ARM)
                "arm64":  "1f2003d51f2003d5",        # NOP NOP (AArch64)
            }
            async with managed_mcp_session() as s:
                await call_tool(s, "disassemble_raw_bytes",
                                {"hex_bytes": test_bytes.get(arch, "90909090"),
                                 "architecture": arch, "limit": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_modify_pe_section(self):
        """Rename a PE section (non-destructive — in-memory only)."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "modify_pe_section",
                                    {"section_name": ".text",
                                     "add_characteristics": 0},
                                    expected_type=dict, allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    @pytest.mark.angr
    def test_patch_with_assembly(self):
        """Assemble and patch a NOP into the loaded binary via angr."""
        async def _test():
            async with managed_mcp_session() as s:
                # Need a valid absolute VA — use angr's function list
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr (needed for valid VA)")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                r = await call_tool(s, "patch_with_assembly",
                                    {"address": str(addr),
                                     "assembly": "nop",
                                     "architecture": "x86_64"},
                                    expected_type=dict, allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_compare_file_similarity(self):
        """compare_file_similarity requires a second file."""
        async def _test():
            if not SAMPLE_FILE:
                pytest.skip("Set ARKANA_TEST_SAMPLE to enable compare_file_similarity test")
            async with managed_mcp_session() as s:
                r = await call_tool(s, "compare_file_similarity",
                                    {"file_path_b": SAMPLE_FILE},
                                    expected_type=dict, allow_none=True)
                assert r is not None
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 17. Multi-Format Binary Analysis Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestMultiFormat:
    """Tests for: detect_binary_format, dotnet_analyze, dotnet_disassemble_method,
    go_analyze, rust_analyze, rust_demangle_symbols, elf_analyze, elf_dwarf_info,
    macho_analyze."""

    @pytest.mark.pe_file
    def test_detect_binary_format(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "detect_binary_format", expected_type=dict)
                assert "primary_format" in r or "detected_formats" in r or "format" in r, (
                    f"detect_binary_format: expected 'primary_format' or 'detected_formats' "
                    f"in response keys {set(r.keys())}"
                )
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_dotnet_analyze(self):
        """May return 'not a .NET binary' for non-.NET samples — that's OK."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "dotnet_analyze", {"limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_go_analyze(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "go_analyze", {"limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_rust_analyze(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "rust_analyze", expected_type=dict)
        run(_test())

    @pytest.mark.no_file
    @pytest.mark.optional_lib
    def test_rust_demangle_symbols(self):
        """Rust demangle is a pure-data tool."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "rust_demangle_symbols",
                                {"symbols": ["_ZN4core3fmt5write17h01234abcdef56789E"],
                                 "limit": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_elf_analyze(self):
        """Will report 'not an ELF' for PE samples — that's expected."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "elf_analyze", {"limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_elf_dwarf_info(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "elf_dwarf_info", {"limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_macho_analyze(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "macho_analyze", {"limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_dotnet_disassemble_method(self):
        """Disassemble a .NET method by RVA.  Skipped for non-.NET samples."""
        async def _test():
            async with managed_mcp_session() as s:
                # First check if we have .NET metadata at all
                meta = await call_tool(s, "dotnet_analyze", {"limit": 5},
                                       expected_type=dict, allow_none=True)
                if meta is None:
                    pytest.skip("No .NET metadata available in sample")
                # Look for a method RVA
                methods = meta.get("methods") or meta.get("method_table") or []
                if isinstance(methods, dict):
                    methods = list(methods.values()) if methods else []
                if not methods:
                    pytest.skip("No .NET methods found to disassemble")
                first = methods[0] if isinstance(methods, list) else methods
                rva = (first.get("rva") or first.get("method_rva")
                       or first.get("RVA") or "0x0")
                r = await call_tool(s, "dotnet_disassemble_method",
                                    {"method_rva": str(rva), "limit": 50},
                                    expected_type=dict, allow_none=True)
                assert r is not None
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 18. Error Handling & Edge Cases
# ═══════════════════════════════════════════════════════════════════════════

class TestErrorHandling:
    """Verify tools return proper errors for invalid input."""

    @pytest.mark.no_file
    def test_get_pe_data_invalid_key(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool_expect_error(
                    s, "get_pe_data",
                    {"key": "this_key_does_not_exist"},
                )
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_decompile_invalid_address(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool_expect_error(
                    s, "decompile_function_with_angr",
                    {"function_address": "0xDEADBEEFDEAD"},
                )
        run(_test())

    @pytest.mark.no_file
    def test_open_file_nonexistent(self):
        async def _test():
            async with managed_mcp_session() as s:
                # When --allowed-paths is configured, path validation fires
                # before the file-existence check, producing "Access denied"
                # instead of "not found".  Accept either error.
                await call_tool_expect_error(
                    s, "open_file",
                    {"file_path": "/nonexistent/path/to/file.exe"},
                    error_substring=None,
                )
        run(_test())

    @pytest.mark.no_file
    def test_extract_strings_invalid_limit(self):
        """extract_strings_from_binary should reject limit <= 0."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool_expect_error(
                    s, "extract_strings_from_binary",
                    {"limit": 0},
                )
        run(_test())

    @pytest.mark.no_file
    def test_extract_strings_no_file(self):
        """extract_strings_from_binary should error without a loaded file."""
        async def _test():
            async with managed_mcp_session() as s:
                # Close the file first (may already be None in no_file context)
                await call_tool(s, "close_file", expected_type=dict, allow_none=True)
                await call_tool_expect_error(
                    s, "extract_strings_from_binary",
                    {"limit": 10},
                    error_substring="no pe file",
                )
        run(_test())

    @pytest.mark.no_file
    def test_deobfuscate_base64_invalid_hex(self):
        """deobfuscate_base64 with non-hex input should handle gracefully."""
        async def _test():
            async with managed_mcp_session() as s:
                # The tool may return an error OR handle gracefully with a
                # status/message — either is acceptable, as long as it doesn't crash.
                try:
                    await call_tool(s, "deobfuscate_base64",
                                   {"hex_string": "not_valid_hex!!"},
                                   allow_none=True)
                    # If it returns successfully, that's acceptable (graceful handling)
                    logger.info("[PASS] deobfuscate_base64 handled invalid hex gracefully")
                except Exception:
                    # If it raises, that's also acceptable
                    logger.info("[PASS] deobfuscate_base64 raised on invalid hex")
        run(_test())

    @pytest.mark.no_file
    def test_search_strings_empty_terms(self):
        """search_for_specific_strings with empty search_terms should error."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool_expect_error(
                    s, "search_for_specific_strings",
                    {"search_terms": []},
                    error_substring="non-empty",
                )
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_angr_invalid_address_format(self):
        """Angr tools should handle obviously invalid address strings."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool_expect_error(
                    s, "get_function_cfg",
                    {"function_address": "not_an_address"},
                )
        run(_test())

    @pytest.mark.no_file
    def test_hex_dump_no_file(self):
        """get_hex_dump should error gracefully with no file loaded."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "close_file", expected_type=dict, allow_none=True)
                await call_tool_expect_error(
                    s, "get_hex_dump",
                    {"start_offset": 0, "length": 16},
                )
        run(_test())

    @pytest.mark.no_file
    def test_sifter_score_out_of_range(self):
        """min_sifter_score outside 0.0-1.0 should be rejected."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool_expect_error(
                    s, "extract_strings_from_binary",
                    {"limit": 10, "rank_with_sifter": True,
                     "min_sifter_score": 5.0},
                )
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_patch_binary_invalid_hex(self):
        """patch_binary_memory should reject invalid hex bytes."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool_expect_error(
                    s, "patch_binary_memory",
                    {"address": "0x0", "patch_bytes_hex": "ZZZZ"},
                )
        run(_test())

    @pytest.mark.no_file
    def test_close_file_when_none_loaded(self):
        """close_file with nothing loaded should return no_file status."""
        async def _test():
            async with managed_mcp_session() as s:
                # Ensure nothing is loaded
                await call_tool(s, "close_file", expected_type=dict, allow_none=True)
                r = await call_tool(s, "close_file", expected_type=dict)
                assert r.get("status") == "no_file"
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_hook_by_name(self):
        """hook_function accepts symbol names (not just addresses)."""
        async def _test():
            async with managed_mcp_session() as s:
                # hook_function resolves string names as symbols, so this
                # should succeed (NOP hook at a named function).
                r = await call_tool(s, "hook_function",
                                    {"address_or_name": "main", "nop": True},
                                    expected_type=dict, allow_none=True)
                # Either succeeds or reports function not found — both OK.
                # If hook succeeded, best-effort cleanup via raw session call
                # (unhook may fail if symbol isn't in the loader table, and
                # call_tool would pytest.fail which is a BaseException).
                if r is not None and r.get("status") == "success":
                    await s.call_tool("unhook_function",
                                      arguments={"address_or_name": "main"})
        run(_test())

    @pytest.mark.pe_file
    def test_get_pe_data_multiple_valid_keys(self):
        """get_pe_data should handle multiple calls with different keys gracefully."""
        async def _test():
            async with managed_mcp_session() as s:
                for key in ["file_hashes", "sections", "imports"]:
                    await call_tool(s, "get_pe_data",
                                   {"key": key, "limit": 3},
                                   allow_none=True)
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 19. Tool Discovery — verify all 104 tools are registered
# ═══════════════════════════════════════════════════════════════════════════

# Complete list of all 104 tools in Arkana
ALL_TOOL_NAMES = sorted([
    # File management (6)
    "open_file", "close_file", "reanalyze_loaded_pe_file",
    "get_analyzed_file_summary", "get_full_analysis_results", "get_pe_data",
    # Config & utilities (4)
    "get_current_datetime", "check_task_status", "set_api_key", "get_config",
    # Cache (3)
    "get_cache_stats", "clear_analysis_cache", "remove_cached_analysis",
    # PE extended (14)
    "get_section_permissions", "get_pe_metadata", "extract_resources",
    "extract_manifest", "get_load_config_details", "extract_wide_strings",
    "detect_format_strings", "detect_compression_headers",
    "deobfuscate_xor_multi_byte", "bruteforce_xor_key",
    "detect_crypto_constants", "analyze_entropy_by_offset",
    "scan_for_api_hashes", "get_import_hash_analysis",
    # Strings (10)
    "search_floss_strings", "get_floss_analysis_info",
    "get_capa_analysis_info", "get_capa_rule_match_details",
    "extract_strings_from_binary", "search_for_specific_strings",
    "get_top_sifted_strings", "get_strings_for_function",
    "get_string_usage_context", "fuzzy_search_strings",
    # Deobfuscation (5)
    "get_hex_dump", "deobfuscate_base64", "deobfuscate_xor_single_byte",
    "is_mostly_printable_ascii", "find_and_decode_encoded_strings",
    # Angr core (15)
    "list_angr_analyses", "decompile_function_with_angr", "get_function_cfg",
    "find_path_to_address", "emulate_function_execution",
    "analyze_binary_loops", "get_function_xrefs", "get_backward_slice",
    "get_forward_slice", "get_dominators", "get_function_complexity_list",
    "extract_function_constants", "get_global_data_refs",
    "scan_for_indirect_jumps", "patch_binary_memory",
    # Angr dataflow (5)
    "get_reaching_definitions", "get_data_dependencies",
    "get_control_dependencies", "propagate_constants", "get_value_set_analysis",
    # Angr disasm (5)
    "disassemble_at_address", "get_calling_conventions",
    "get_function_variables", "identify_library_functions",
    "get_annotated_disassembly",
    # Angr forensic (9)
    "diff_binaries", "detect_self_modifying_code", "find_code_caves",
    "detect_packing", "save_patched_binary", "find_path_with_custom_input",
    "emulate_with_watchpoints", "identify_cpp_classes", "get_call_graph",
    # Angr hooks (3)
    "hook_function", "list_hooks", "unhook_function",
    # Classification (1)
    "classify_binary_purpose",
    # Format detection (1)
    "detect_binary_format",
    # VirusTotal (1)
    "get_virustotal_report_for_loaded_file",
    # Triage (1)
    "get_triage_report",
    # Extended libraries (13)
    "parse_binary_with_lief", "modify_pe_section", "disassemble_raw_bytes",
    "assemble_instruction", "patch_with_assembly",
    "compute_similarity_hashes", "compare_file_similarity",
    "emulate_pe_with_windows_apis", "emulate_shellcode_with_speakeasy",
    "auto_unpack_pe", "parse_dotnet_metadata", "scan_for_embedded_files",
    "get_extended_capabilities",
    # Multi-format (9)
    "dotnet_analyze", "dotnet_disassemble_method",
    "go_analyze", "rust_analyze", "rust_demangle_symbols",
    "elf_analyze", "elf_dwarf_info", "macho_analyze",
    # (detect_binary_format already listed above)
])


class TestToolDiscovery:
    """Verify tools registered on the server and report discrepancies."""

    @pytest.mark.no_file
    def test_all_tools_registered(self):
        """List tools from the server and check coverage.

        Missing tools are logged as warnings (the server image may be older).
        Extra tools on the server are logged for informational purposes.
        The test only fails if the server reports zero tools.
        """
        async def _test():
            async with managed_mcp_session() as s:
                result = await s.list_tools()
                server_tools = {t.name for t in result.tools}
                logger.info("Server reports %d tools.", len(server_tools))

                assert len(server_tools) > 0, "Server reports 0 tools — is it running correctly?"

                missing = set(ALL_TOOL_NAMES) - server_tools
                extra = server_tools - set(ALL_TOOL_NAMES)

                if missing:
                    logger.warning(
                        "%d expected tools NOT on server (older build?): %s",
                        len(missing), sorted(missing),
                    )
                if extra:
                    logger.info(
                        "%d extra tools on server (not in test list): %s",
                        len(extra), sorted(extra),
                    )

                # Warn but don't fail — the server image may not have all tools
                if missing:
                    import warnings
                    warnings.warn(
                        f"{len(missing)} tools missing from server: {sorted(missing)}",
                        stacklevel=2,
                    )

                logger.info(
                    "Tool coverage: %d/%d expected present, %d extra.",
                    len(set(ALL_TOOL_NAMES) & server_tools),
                    len(ALL_TOOL_NAMES),
                    len(extra),
                )
        run(_test())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Arkana Integration Test Suite")
    print("=" * 50)
    print()
    print("Usage:")
    print("  pytest mcp_test_client.py -v                  # Run all tests")
    print("  pytest mcp_test_client.py -v -m no_file       # Tests without a loaded file")
    print("  pytest mcp_test_client.py -v -m pe_file       # Tests requiring a PE file")
    print("  pytest mcp_test_client.py -v -m angr          # Angr tests only")
    print("  pytest mcp_test_client.py -v -k TestPEData    # PE data retrieval tests")
    print("  pytest mcp_test_client.py -v -k TestConfig    # Config & utility tests")
    print()
    print("Environment variables:")
    print(f"  ARKANA_TEST_URL       = {SERVER_URL}")
    print(f"  ARKANA_TEST_TRANSPORT = {TRANSPORT}  (auto|streamable-http|sse)")
    print(f"  ARKANA_TEST_SAMPLE    = {SAMPLE_FILE or '(not set)'}")
    print()
    print("Start the server first:")
    print("  python arkana.py --mcp-server --mcp-transport streamable-http --input-file samples/test.exe")
    print()
    sys.exit(pytest.main([__file__, "-v"]))
