"""MCP server setup, tool decorator, and validation helpers."""
import asyncio
import functools
import json
import logging
import time

from typing import Dict, Any, Optional

from arkana.config import (
    state, logger, FastMCP, Context,
    ANGR_AVAILABLE, MAX_MCP_RESPONSE_SIZE_BYTES, MAX_MCP_RESPONSE_SIZE_KB,
    MCP_SOFT_RESPONSE_LIMIT_CHARS,
)
from arkana.state import get_session_key_from_context, activate_session_state, get_current_state, TASK_RUNNING, TASK_OVERTIME
from arkana.utils import _safe_env_int
from arkana.warning_handler import _current_tool_var
from arkana.mcp._input_helpers import _ToolResultCache
from mcp.server.transport_security import TransportSecuritySettings

# Soft character limit — primary truncation threshold.
# Claude Code CLI truncates MCP responses at character thresholds far below 64KB,
# so we default to 8K chars.  Non-Claude-Code clients can set the env var to
# a higher value (e.g. 65536) to restore the old 64KB-only behaviour.
_SOFT_LIMIT = _safe_env_int("ARKANA_MCP_RESPONSE_LIMIT_CHARS", MCP_SOFT_RESPONSE_LIMIT_CHARS, min_val=1000)

# --- MCP Server Setup ---
mcp_server = FastMCP(
    name="Arkana",
    # whatever other arguments Arkana already has...
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)
_raw_tool_decorator = mcp_server.tool()

# --- Brief descriptions mode ---
# When enabled, tool docstrings are trimmed to the first paragraph only
# (everything before the first blank line).  This dramatically reduces the
# size of the tool listing sent to AI clients that don't support tool search.
# Set via --brief-descriptions CLI flag or ARKANA_BRIEF_DESCRIPTIONS=1 env var.
#
# IMPORTANT: Every tool decorated with @tool_decorator MUST include a
# ---compact: line in its docstring for --brief-descriptions mode.
# Place it after the first paragraph, before the blank line that precedes
# "When to use:".  Run tests/test_compact_descriptions.py to verify.
# Grammar:  ---compact: <action> [| <details>] [| needs: <prereqs>]
_brief_descriptions: bool = False


def set_brief_descriptions(enabled: bool) -> None:
    """Enable or disable brief tool descriptions. Must be called before tool registration."""
    global _brief_descriptions
    _brief_descriptions = enabled


def _extract_brief_description(docstring: str) -> str:
    """Extract the compact shorthand from a ``---compact:`` line in the docstring.

    Every tool docstring should contain a line like::

        ---compact: decompile function to pseudocode | search, digest modes | needs: angr

    This is used by ``--brief-descriptions`` to replace the full docstring
    in the MCP tool listing, reducing context window usage by ~90%.

    Falls back to the first paragraph if no ``---compact:`` line is found
    (backward compatibility during migration).
    """
    stripped = docstring.strip()
    if not stripped:
        return stripped
    # Look for ---compact: line
    for line in stripped.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("---compact:"):
            return trimmed[len("---compact:"):].strip()
    # Fallback: first paragraph (pre-compact docstrings)
    idx = stripped.find("\n\n")
    if idx == -1:
        return stripped
    return stripped[:idx].strip()


# Tools excluded from automatic history recording to avoid noise / recursion.
_SKIP_HISTORY_TOOLS = frozenset({
    "get_tool_history", "clear_tool_history", "get_session_summary",
    "get_notes", "add_note", "delete_note", "update_note",
    "get_progress_overview",
    # Rename/type listing tools — meta, not analysis steps
    "list_renames", "list_custom_types",
    # Learning tools — meta/progress, not analysis steps
    "get_learner_profile", "update_concept_mastery",
    "get_learning_suggestions", "reset_learner_profile",
    # Warning tools — diagnostic, not analysis steps
    "get_analysis_warnings", "clear_analysis_warnings",
    # Resource monitoring — diagnostic
    "get_resource_usage",
})

# --- Heartbeat configuration ---
# Delay before the first heartbeat fires (avoids noise for fast tools).
_HEARTBEAT_START_DELAY_SECONDS = _safe_env_int("ARKANA_HEARTBEAT_START_DELAY", 10, min_val=1, max_val=300)
# Interval between subsequent heartbeat pings.
_HEARTBEAT_INTERVAL_SECONDS = _safe_env_int("ARKANA_HEARTBEAT_INTERVAL", 15, min_val=1, max_val=300)

# Tools that manage their own MCP progress reporting.  The generic heartbeat
# is skipped for these to avoid conflicting or redundant messages.
_SELF_REPORTING_TOOLS = frozenset({
    # Core file operations
    "open_file",
    "reanalyze_loaded_pe_file",
    # angr tools (Group A background bridge + Group B foreground)
    "decompile_function_with_angr",
    "get_function_cfg",
    "find_path_to_address",
    "emulate_function_execution",
    "analyze_binary_loops",
    "find_path_with_custom_input",
    "emulate_with_watchpoints",
    # angr forensic tools (Group A background bridge + Group B foreground)
    "detect_self_modifying_code",
    "find_code_caves",
    "detect_packing",
    "get_call_graph",
    "find_anti_debug_comprehensive",
    "diff_binaries",
    "save_patched_binary",
    # angr dataflow tools (Group A background bridge + Group B foreground)
    "get_reaching_definitions",
    "get_data_dependencies",
    "get_value_set_analysis",
    "get_control_dependencies",
    "propagate_constants",
    # Qiling tools (Group D subprocess progress)
    "emulate_binary_with_qiling",
    "emulate_shellcode_with_qiling",
    "qiling_trace_execution",
    "qiling_hook_api_calls",
    "qiling_dump_unpacked_binary",
    "qiling_resolve_api_hashes",
    "qiling_memory_search",
    # Debug tools (persistent subprocess progress)
    "debug_start",
    "debug_continue",
    "debug_run_until",
    "debug_step",
    "debug_step_over",
    "debug_search_memory",
    # Speakeasy / unipacker tools (Group D subprocess progress)
    "emulate_pe_with_windows_apis",
    "emulate_shellcode_with_speakeasy",
    "auto_unpack_pe",
    # Unpack orchestration tools (Group E)
    "try_all_unpackers",
    "reconstruct_pe_from_dump",
    "find_oep_heuristic",
    # Triage (Group C)
    "get_triage_report",
    # Crypto tools (Group C)
    "identify_crypto_algorithm",
    "auto_extract_crypto_keys",
    "brute_force_simple_crypto",
    # Deobfuscation (Group C)
    "find_and_decode_encoded_strings",
    # String tools (Group C)
    "extract_strings_from_binary",
    "get_top_sifted_strings",
    "fuzzy_search_strings",
    "search_yara_custom",
    # Payload extraction (Group C)
    "extract_config_automated",
    # PE extended (Group C)
    "detect_crypto_constants",
    "analyze_entropy_by_offset",
    "scan_for_api_hashes",
    # BSim function similarity (background tasks)
    "build_function_signature_db",
    "find_similar_functions",
    # Batch decompilation (self-reporting progress)
    "batch_decompile",
    # Symbolic execution extensions (background tasks)
    "solve_constraints_for_path",
    "explore_symbolic_states",
    # Vulnerability analysis (long-running RDA)
    "find_dangerous_data_flows",
    # Obfuscation detection (long-running analysis)
    "detect_control_flow_flattening",
    "detect_opaque_predicates",
})


def _extract_key_params(kwargs: dict) -> Dict[str, Any]:
    """Build a compact parameter snapshot for history recording."""
    params: Dict[str, Any] = {}
    for k, v in kwargs.items():
        if k == "ctx":
            continue
        if isinstance(v, str) and len(v) > 200:
            params[k] = v[:200] + "..."
        elif isinstance(v, (list, dict)):
            params[k] = f"<{type(v).__name__}({len(v)})>"
        else:
            params[k] = v
    return params


def _build_result_summary(result: Any) -> str:
    """Extract a short summary string from a tool result."""
    if not isinstance(result, dict):
        return ""
    parts = []
    if "status" in result:
        parts.append(f"status={result['status']}")
    if "risk_level" in result:
        parts.append(f"risk_level={result['risk_level']}")
    if "count" in result:
        parts.append(f"count={result['count']}")
    if "error" in result:
        parts.append(f"error={str(result['error'])[:80]}")
    if not parts:
        keys = list(result.keys())[:3]
        parts.append(f"keys: {', '.join(keys)}")
    return "; ".join(parts)[:200]


_ALERT_MIN_AGE_SECONDS = 5  # Don't alert for transient tasks

# Periodic cache sweep to proactively evict TTL-expired entries
_cache_sweep_state = {"count": 0, "last": 0.0}
_CACHE_SWEEP_INTERVAL = 60  # seconds between sweeps
_CACHE_SWEEP_CALLS = 50     # tool calls between sweeps


def _collect_background_alerts(current_state) -> list:
    """Collect alerts for running and overtime background tasks."""
    alerts = []
    now = time.time()
    try:
        for tid in current_state.get_all_task_ids():
            task = current_state.get_task(tid)
            if not task:
                continue
            status = task["status"]
            if status == TASK_OVERTIME:
                overtime_since = task.get("overtime_since_epoch", 0)
                alerts.append({
                    "task_id": tid,
                    "status": "overtime",
                    "overtime_seconds": round(now - overtime_since) if overtime_since else 0,
                    "progress_percent": task.get("progress_percent", 0),
                    "progress_message": task.get("progress_message", ""),
                    "hint": f"Use check_task_status('{tid}') for details or abort_background_task('{tid}') to stop.",
                })
            elif status == TASK_RUNNING:
                created = task.get("created_at_epoch", 0)
                elapsed = now - created if created else 0
                if elapsed < _ALERT_MIN_AGE_SECONDS:
                    continue  # Skip transient tasks
                alerts.append({
                    "task_id": tid,
                    "status": "running",
                    "elapsed_seconds": round(elapsed),
                    "progress_percent": task.get("progress_percent", 0),
                    "progress_message": task.get("progress_message", ""),
                    "hint": f"Use check_task_status('{tid}') for details.",
                })
    except Exception:
        logger.debug("Alert collection error", exc_info=True)

    # Resource pressure alert (memory / CPU)
    try:
        from arkana.resource_monitor import get_resource_alert
        resource_alert = get_resource_alert()
        if resource_alert:
            alerts.append(resource_alert)
    except Exception:
        logger.debug("Resource alert collection error", exc_info=True)

    # Decompile lock force-reset alert (transient, 30s window)
    try:
        lock = current_state._decompile_lock
        if lock._last_force_reset:
            age = now - lock._last_force_reset
            if age < 30:
                alerts.append({
                    "type": "decompile_lock_reset",
                    "message": "Decompile lock was force-released during file switch. "
                               "A stale background thread from the previous file may still be running.",
                    "seconds_ago": round(age),
                })
    except Exception:
        logger.debug("Lock alert collection error", exc_info=True)

    # Partial CFG alert (persistent until next file switch)
    try:
        cfg_quality = current_state._cfg_quality
        if cfg_quality and cfg_quality.get("status") == "partial":
            alerts.append({
                "type": "cfg_partial",
                "message": (
                    f"CFG is partial: {cfg_quality.get('functions_discovered', '?')} functions "
                    f"({cfg_quality.get('reason', 'unknown reason')}). "
                    "Function map and decompilation available for discovered functions."
                ),
                "functions_discovered": cfg_quality.get("functions_discovered", 0),
                "errors_during_build": cfg_quality.get("errors_during_build", 0),
                "reason": cfg_quality.get("reason", ""),
            })
    except Exception:
        logger.debug("CFG quality alert collection error", exc_info=True)

    return alerts


def tool_decorator(func):
    """MCP tool decorator that activates per-session state before each call.

    Wraps the underlying FastMCP ``tool()`` decorator so that every tool
    invocation first resolves the correct ``AnalyzerState`` for the current
    MCP session (relevant in HTTP mode with concurrent clients).

    Automatically records tool invocations in the session's tool history
    (except for meta-tools listed in ``_SKIP_HISTORY_TOOLS``).

    For long-running tools, an automatic heartbeat sends periodic
    ``ctx.info()`` messages so the MCP client knows the server is alive.
    Tools that manage their own progress (listed in ``_SELF_REPORTING_TOOLS``)
    and lightweight meta-tools are excluded from the heartbeat.
    """
    @functools.wraps(func)
    async def _with_session(*args, **kwargs):
        # Find the Context argument and activate the matching session state
        ctx = None
        for arg in list(args) + list(kwargs.values()):
            if isinstance(arg, Context):
                ctx = arg
                key = get_session_key_from_context(arg)
                activate_session_state(key)
                break
        # Update last-active timestamp for session TTL tracking
        current_state = get_current_state()
        current_state.touch()

        tool_name = func.__name__

        # Track active tool on state for dashboard visibility
        if tool_name not in _SKIP_HISTORY_TOOLS:
            current_state.push_active_tool(tool_name)
            with current_state._active_tool_lock:
                current_state.active_tool_progress = 0
                current_state.active_tool_total = 100

            # Wrap ctx.report_progress to also update state for dashboard.
            # Guard against double-wrapping if the same ctx is reused.
            if ctx is not None and not getattr(ctx, '_arkana_progress_wrapped', False):
                _orig_report_progress = ctx.report_progress
                async def _wrapped_report_progress(progress, total=100):
                    if getattr(current_state, '_closing', False):
                        return
                    with current_state._active_tool_lock:
                        current_state.active_tool_progress = progress
                        current_state.active_tool_total = total
                    return await _orig_report_progress(progress, total)
                object.__setattr__(ctx, "report_progress", _wrapped_report_progress)
                object.__setattr__(ctx, "_arkana_progress_wrapped", True)

        # Set up automatic heartbeat for tools that don't self-report progress.
        # Lightweight meta-tools and self-reporting tools are excluded.
        heartbeat_task = None
        if (
            ctx is not None
            and tool_name not in _SELF_REPORTING_TOOLS
            and tool_name not in _SKIP_HISTORY_TOOLS
        ):
            async def _heartbeat():
                await asyncio.sleep(_HEARTBEAT_START_DELAY_SECONDS)
                elapsed = _HEARTBEAT_START_DELAY_SECONDS
                while True:
                    try:
                        await ctx.info(
                            f"[heartbeat] {tool_name} still running "
                            f"({elapsed}s elapsed)"
                        )
                    except Exception:
                        break  # Context may have been closed
                    await asyncio.sleep(_HEARTBEAT_INTERVAL_SECONDS)
                    elapsed += _HEARTBEAT_INTERVAL_SECONDS

            heartbeat_task = asyncio.create_task(_heartbeat())

        start_time = time.time()
        _tool_token = _current_tool_var.set(tool_name)
        try:
            result = await func(*args, **kwargs)
        except (RuntimeError, ValueError) as exc:
            # Enrich error messages with actionable hints
            msg = str(exc)
            if not msg:
                msg = f"{tool_name} failed: {type(exc).__name__} (no details available)"
            enriched = _enrich_error_message(msg)
            if enriched != str(exc):
                raise type(exc)(enriched) from exc
            raise
        except (AssertionError, AttributeError, TypeError, KeyError) as exc:
            # Catch common internal errors that surface with empty messages
            # KeyError wraps its arg in quotes via str(), so use args[0] to
            # avoid double-quoting when re-raising.
            if isinstance(exc, KeyError) and exc.args:
                msg = str(exc.args[0])
            else:
                msg = str(exc)
            if not msg:
                msg = f"{tool_name} failed: {type(exc).__name__} (internal error — the binary may be incompatible with this analysis)"
                raise RuntimeError(msg) from exc
            # Preserve original exception type and message when message is non-empty
            raise type(exc)(msg) from exc
        finally:
            _current_tool_var.reset(_tool_token)
            # Always cancel the heartbeat when the tool finishes
            if heartbeat_task is not None:
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass
            # Clear active tool on state for dashboard
            if tool_name not in _SKIP_HISTORY_TOOLS:
                current_state.pop_active_tool(tool_name)
                with current_state._active_tool_lock:
                    current_state.active_tool_progress = 0
            # Periodic cache sweep to evict TTL-expired entries
            _cache_sweep_state["count"] += 1
            _now = time.time()
            if (_cache_sweep_state["count"] >= _CACHE_SWEEP_CALLS
                    or (_now - _cache_sweep_state["last"]) >= _CACHE_SWEEP_INTERVAL):
                _cache_sweep_state["count"] = 0
                _cache_sweep_state["last"] = _now
                try:
                    _ToolResultCache.sweep_all_expired()
                except Exception:
                    pass

        # Safety net: enforce soft char limit for tools that don't call
        # _check_mcp_response_size explicitly.  Fast no-op when the response
        # is already under the limit (single json.dumps + len check).
        if ctx is not None and isinstance(result, (dict, list, str)):
            try:
                _result_json = json.dumps(result, ensure_ascii=False)
                if len(_result_json) > _SOFT_LIMIT:
                    result = await _check_mcp_response_size(ctx, result, tool_name, _preserialized=_result_json)
            except (TypeError, ValueError):
                logger.debug("Auto-truncation skipped for %s (serialization error)", tool_name, exc_info=True)

        duration_ms = int((time.time() - start_time) * 1000)

        # Record tool invocation in history (skip meta-tools)
        if tool_name not in _SKIP_HISTORY_TOOLS:
            try:
                current_state.record_tool_call(
                    tool_name=tool_name,
                    parameters=_extract_key_params(kwargs),
                    result_summary=_build_result_summary(result),
                    duration_ms=duration_ms,
                )
            except Exception:
                logger.debug("History recording failed for %s", tool_name, exc_info=True)

        # Passive background alerts: inject overtime/recently-failed task alerts
        if isinstance(result, dict):
            alerts = _collect_background_alerts(current_state)
            if alerts:
                result["_background_alerts"] = alerts

        return result
    # In brief mode, trim the docstring to the first paragraph before
    # FastMCP reads it for the tool listing.  This is a registration-time
    # transformation — the full docstring is still available on the original
    # function object via func.__doc__.
    if _brief_descriptions and _with_session.__doc__:
        _with_session.__doc__ = _extract_brief_description(_with_session.__doc__)

    return _raw_tool_decorator(_with_session)

# --- MCP Feedback Helpers ---

def _check_pe_loaded(tool_name: str) -> None:
    """Raise a descriptive RuntimeError if no file has been loaded.

    Snapshots both ``pe_data`` and ``filepath`` in a single read to avoid
    a potential (though unlikely) race where one is reset between two
    separate attribute accesses through the StateProxy.
    """
    pe_data, filepath = state.get_file_snapshot()
    if pe_data is None or filepath is None:
        raise RuntimeError(
            f"[{tool_name}] No file is currently loaded. "
            "Use the 'open_file' tool to load a file for analysis (supports PE, ELF, Mach-O, shellcode), "
            "or start the server with --input-file to pre-load one. "
            "If a file was provided at startup, it may have failed — check the server logs."
        )

def _check_pe_object(tool_name: str, *, require_headers: bool = False) -> None:
    """Raise a descriptive RuntimeError if pe_object is unavailable.

    Call *after* ``_check_pe_loaded()``.  Many PE-specific tools access
    ``state.pe_object`` attributes (sections, OPTIONAL_HEADER, __data__).
    This guard prevents ``AttributeError`` crashes when pe_object is None
    (e.g. cache-restored sessions, closed files, or parse failures).

    When *require_headers* is True, also validates that OPTIONAL_HEADER and
    FILE_HEADER are present (i.e. this is a real PE, not an ELF/Mach-O/shellcode
    loaded via MockPE with stub headers).

    Cache-hit fast-load promotion: when ``state._pe_object_needs_full_load``
    is True, ``open_file`` constructed pe_object with ``fast_load=True``
    (headers + sections only — directories not yet parsed). The full-load
    is deferred to the first tool call that actually needs directory
    structures, so cached opens stay fast (~1s) while tools that walk
    imports/exports/resources still get the data they need on first use.

    Concurrency: the lazy ``full_load()`` runs OUTSIDE ``_pe_lock`` because
    it can take seconds for a packed binary. We snapshot ``(pe_object,
    needs_full_load)`` under the lock first, then run ``full_load()`` on
    the captured reference, then re-acquire the lock and only clear the
    flag if ``state.pe_object is still the same object`` we loaded. If a
    concurrent ``close_pe()`` + ``open_file()`` swapped in a new pe_object
    while we were loading, that new object's needs-full-load flag is
    preserved untouched.
    """
    # Snapshot under the lock — pe_object and needs_full_load must agree.
    with state._pe_lock:
        pe = state.pe_object
        needs_full_load = bool(getattr(state, "_pe_object_needs_full_load", False))
    if pe is None:
        raise RuntimeError(
            f"[{tool_name}] PE object is not available. The file may have been "
            "loaded from cache without the original binary, or failed to parse. "
            "Use open_file() to reload the PE binary."
        )
    if require_headers:
        if getattr(pe, 'OPTIONAL_HEADER', None) is None:
            raise RuntimeError(
                f"[{tool_name}] This tool requires a PE binary with valid headers. "
                "The loaded file (ELF, Mach-O, or shellcode) does not have PE structures. "
                "Use format-specific tools (elf_analyze, macho_analyze) instead."
            )
        # Lazy full_load() — first tool that needs directories pays the
        # parse cost; subsequent tools see the already-fully-parsed object.
        if needs_full_load:
            try:
                pe.full_load()
            except Exception as exc:
                logger.warning(
                    "[%s] pefile full_load() failed; some PE directories may "
                    "be unavailable: %s", tool_name, exc,
                )
            # Re-acquire lock and clear the flag ONLY if state.pe_object
            # still points at the object we loaded. If a concurrent
            # close_pe + open_file swapped in a new pe_object during our
            # full_load(), its needs_full_load flag must be left alone so
            # the next tool call promotes the NEW object.
            with state._pe_lock:
                if state.pe_object is pe:
                    state._pe_object_needs_full_load = False


def _check_angr_ready(tool_name: str, *, require_cfg: bool = True) -> None:
    """
    Raise a descriptive RuntimeError if angr is unavailable or still initializing.
    Provides actionable guidance to the MCP client.

    Args:
        tool_name: Name of the calling tool (used in error messages).
        require_cfg: If True (default), block while background CFG build is
                     in progress.  Set to False for tools that only need the
                     angr Project (e.g. save_patched_binary) and can work
                     before the CFG is ready.
    """
    if not ANGR_AVAILABLE:
        raise RuntimeError(
            f"[{tool_name}] The angr library is not installed on this server. "
            "Binary analysis tools (decompilation, CFG, symbolic execution, emulation) "
            "require angr. Install it with: pip install 'angr[unicorn]'"
        )
    if state.filepath is None:
        raise RuntimeError(
            f"[{tool_name}] No file is loaded. Cannot perform binary analysis."
        )
    # Check if background angr startup is still running
    if require_cfg:
        startup_task = state.get_task("startup-angr")
        if startup_task and startup_task["status"] in (TASK_RUNNING, TASK_OVERTIME):
            status = startup_task["status"]
            progress = startup_task.get("progress_percent", 0)
            msg = startup_task.get("progress_message", "Initializing...")
            status_label = "overtime (still running)" if status == TASK_OVERTIME else "in progress"
            raise RuntimeError(
                f"[{tool_name}] Angr background analysis is {status_label} ({progress}%: {msg}). "
                "Please wait and retry shortly. Use check_task_status('startup-angr') to monitor progress."
            )

_PREREQUISITE_HINTS = {
    "floss_analysis": (
        "FLOSS analysis data is not available. Possible causes:\n"
        "  1. FLOSS was skipped at startup (--skip-floss flag)\n"
        "  2. FLOSS is not installed on this server\n"
        "  3. FLOSS analysis failed during file loading\n"
        "Fix: Run reanalyze_loaded_pe_file() to re-run all analyses, "
        "or check server logs for FLOSS errors."
    ),
    "capa_analysis": (
        "CAPA analysis data is not available. Possible causes:\n"
        "  1. CAPA was skipped at startup (--skip-capa flag)\n"
        "  2. CAPA is not installed on this server\n"
        "  3. CAPA analysis failed during file loading\n"
        "Fix: Run reanalyze_loaded_pe_file() to re-run all analyses."
    ),
    "yara_matches": (
        "YARA match data is not available. Possible causes:\n"
        "  1. YARA was skipped at startup (--skip-yara flag)\n"
        "  2. YARA rules were not found or failed to compile\n"
        "Fix: Run reanalyze_loaded_pe_file() or check YARA rule paths."
    ),
    "peid_matches": (
        "PEiD signature data is not available. Possible causes:\n"
        "  1. PEiD was skipped at startup (--skip-peid flag)\n"
        "  2. PEiD signature database (userdb.txt) was not found\n"
        "Fix: Run reanalyze_loaded_pe_file() to re-run all analyses."
    ),
}

# Map error message patterns to suggested next actions.
_ERROR_HINTS = {
    "angr background analysis is still in progress": (
        "Suggested: Call check_task_status('startup-angr') to monitor progress, "
        "or use non-angr tools while waiting (get_hex_dump, detect_crypto_constants, "
        "extract_resources, etc.)."
    ),
    "no file is currently loaded": (
        "Suggested: Call open_file(filepath) to load a binary, "
        "or restart the server with --input-file to pre-load one."
    ),
    "not installed": (
        "Suggested: Check the server's installed packages. The Docker image "
        "includes all dependencies. If running locally, check requirements.txt."
    ),
    "failed to initialize qiling": (
        "Suggested: Run qiling_setup_check() to verify rootfs and DLL setup. "
        "Windows PE emulation requires real DLL files (ntdll.dll, kernel32.dll, etc.) "
        "in the rootfs. See docs/QILING_ROOTFS.md for setup instructions. "
        "For quick analysis, try emulate_shellcode_with_qiling or Speakeasy tools instead."
    ),
    "windows api implementation": (
        "Suggested: This usually means Qiling's Windows API layer couldn't initialize. "
        "Run qiling_setup_check() to verify DLL setup. Ensure ntdll.dll and kernel32.dll "
        "are present in the rootfs Windows/System32/ directory."
    ),
    "qiling framework is not available": (
        "Suggested: The Qiling venv may not be set up. If using Docker, rebuild the image. "
        "Run qiling_setup_check() for detailed diagnostics."
    ),
    "qiling rootfs directory not found": (
        "Suggested: Create the rootfs directory or set QILING_ROOTFS env var. "
        "Run qiling_setup_check() for step-by-step setup guidance."
    ),
}

def _check_data_key_available(key_name: str, tool_name: str) -> None:
    """
    Check that a specific analysis data key is available in pe_data.
    Provides context-aware feedback about why data might be missing,
    including specific prerequisites and fix instructions.
    """
    _check_pe_loaded(tool_name)
    if key_name not in state.pe_data:
        hint = _PREREQUISITE_HINTS.get(key_name, "")
        if not hint:
            # Fallback to the old skip_map logic for unknown keys
            skip_map = {
                "floss_analysis": "floss", "capa_analysis": "capa",
                "yara_matches": "yara", "peid_matches": "peid"
            }
            if key_name in skip_map:
                hint = (
                    f" This analysis may have been skipped via --skip-{skip_map[key_name]} at startup. "
                    "Use reanalyze_loaded_pe_file() to re-run the analysis."
                )
        raise RuntimeError(
            f"[{tool_name}] Analysis data for '{key_name}' is not available. {hint}"
        )


def _enrich_error_message(error_msg: str) -> str:
    """Append actionable hints to known error patterns."""
    msg_lower = error_msg.lower()
    for pattern, hint in _ERROR_HINTS.items():
        if pattern in msg_lower:
            return f"{error_msg}\n\n{hint}"
    return error_msg

async def _check_mcp_response_size(
    ctx: Context,
    data_to_return: Any,
    tool_name: str,
    limit_param_info: Optional[str] = None,
    _preserialized: Optional[str] = None,
) -> Any:
    """
    Smart Size Guard with dual-limit system.

    Primary: Soft character limit (_SOFT_LIMIT, default 8K chars) — prevents
    Claude Code CLI from truncating or persisting responses to disk files.

    Secondary: Hard byte limit (MAX_MCP_RESPONSE_SIZE_BYTES, 64KB) — backstop
    for correctness.

    Set ARKANA_MCP_RESPONSE_LIMIT_CHARS=65536 to restore old 64KB-only behavior.
    """
    data_size_bytes = 0  # Safe default for error fallback
    try:
        # 1. Check initial size — measure both char count and byte length
        serialized_data = _preserialized or json.dumps(data_to_return, ensure_ascii=False)
        data_size_chars = len(serialized_data)
        data_size_bytes = len(serialized_data.encode('utf-8'))

        # Fast path: under both limits
        if data_size_chars <= _SOFT_LIMIT and data_size_bytes <= MAX_MCP_RESPONSE_SIZE_BYTES:
            return data_to_return

        # 2. It's too big. Enter Truncation Mode.
        # Target 90% of the soft char limit to leave room for warning metadata.
        TARGET_CHARS = int(_SOFT_LIMIT * 0.9)
        TARGET_BYTES = MAX_MCP_RESPONSE_SIZE_BYTES - 4096

        exceeded = []
        if data_size_chars > _SOFT_LIMIT:
            exceeded.append(f"{data_size_chars} chars (limit: {_SOFT_LIMIT})")
        if data_size_bytes > MAX_MCP_RESPONSE_SIZE_BYTES:
            exceeded.append(f"{data_size_bytes / 1024:.1f}KB (limit: {MAX_MCP_RESPONSE_SIZE_KB}KB)")

        await ctx.warning(
            f"Response for '{tool_name}' exceeded limits: {', '.join(exceeded)}. "
            f"Auto-truncating."
        )

        # Shallow copy suffices — truncation only replaces top-level keys
        # with new sliced objects, never mutates nested structures in-place.
        if isinstance(data_to_return, dict):
            modified_data = dict(data_to_return)
        elif isinstance(data_to_return, list):
            modified_data = list(data_to_return)
        else:
            modified_data = data_to_return

        # Track current char count from the initial measurement to avoid
        # re-serialising on every loop iteration (expensive for large dicts).
        current_chars = data_size_chars

        # 3. Heuristic: Find the largest element and chop it
        # We iterate up to 5 times to try and make it fit.
        for _attempt in range(5):
            if current_chars <= TARGET_CHARS:
                break  # It fits now!

            reduction_ratio = TARGET_CHARS / current_chars
            # Be aggressive: cut slightly more than the ratio suggests
            reduction_ratio *= 0.9

            if isinstance(modified_data, dict):
                # Find the key holding the largest amount of data
                largest_key = None
                largest_len = 0

                for k, v in modified_data.items():
                    # Skip pagination metadata and truncation warnings —
                    # these are small control fields, not data to truncate.
                    if k.endswith("_pagination") or k == "_pagination":
                        continue
                    if k == "_truncation_warning":
                        continue
                    try:
                        v_len = len(json.dumps(v, ensure_ascii=False))
                        if v_len > largest_len:
                            largest_len = v_len
                            largest_key = k
                    except Exception:
                        logger.debug("Failed to serialize key %r during truncation", k)
                        continue

                if largest_key:
                    val = modified_data[largest_key]
                    # Measure old field size via repr (cheap proxy) before replacement
                    old_field_repr_len = largest_len
                    if isinstance(val, list):
                        orig_len = len(val)
                        new_len = int(orig_len * reduction_ratio)
                        new_len = max(1, new_len)  # Keep at least 1
                        modified_data[largest_key] = val[:new_len]
                        # Update sibling pagination metadata if present
                        for pag_key in (f"{largest_key}_pagination", "_pagination"):
                            if pag_key in modified_data and isinstance(modified_data[pag_key], dict):
                                modified_data[pag_key]["returned"] = new_len
                                modified_data[pag_key]["has_more"] = True
                                break
                        modified_data["_truncation_warning"] = (
                            f"Data in '{largest_key}' truncated from {orig_len} to {new_len} items "
                            f"(response exceeded {_SOFT_LIMIT}-char limit). "
                            f"Use {limit_param_info} to paginate, or request specific items."
                            if limit_param_info else
                            f"Data in '{largest_key}' truncated from {orig_len} to {new_len} items "
                            f"to fit {_SOFT_LIMIT}-char response limit."
                        )
                    elif isinstance(val, str):
                        new_len = int(len(val) * reduction_ratio)
                        modified_data[largest_key] = val[:new_len] + "...[TRUNCATED]"
                        modified_data["_truncation_warning"] = f"String in '{largest_key}' truncated to fit limit."
                    elif isinstance(val, dict):
                        # If a dictionary is the biggest thing, simply removing items is risky structure-wise,
                        # but we can try to remove half the keys.
                        keys = list(val.keys())
                        cut_point = int(len(keys) * reduction_ratio)
                        new_dict = {k: val[k] for k in keys[:cut_point]}
                        modified_data[largest_key] = new_dict
                        modified_data["_truncation_warning"] = f"Dictionary '{largest_key}' truncated keys to fit limit."
                    else:
                        # Fallback: if we can't shrink the biggest value, we fail gracefully to avoid infinite loop
                        break
                    # Estimate new size by subtracting old field size and adding new.
                    # This avoids a full json.dumps on every iteration.
                    try:
                        new_field_repr_len = len(json.dumps(modified_data[largest_key], ensure_ascii=False))
                    except Exception:
                        new_field_repr_len = old_field_repr_len
                    current_chars -= (old_field_repr_len - new_field_repr_len)

            elif isinstance(modified_data, list):
                # If the root object is a list, slice the list itself
                old_len = len(modified_data)
                new_len = max(1, int(old_len * reduction_ratio))
                modified_data = modified_data[:new_len]
                # We can't add a key to a list, so we append a warning item if possible, or rely on ctx.warning
                if len(modified_data) > 0 and isinstance(modified_data[0], dict):
                    modified_data.append({"_warning": f"List truncated from {old_len} to {new_len} items."})
                # Estimate: size scales roughly linearly with item count
                current_chars = int(current_chars * (new_len / old_len)) if old_len > 0 else current_chars

            elif isinstance(modified_data, str):
                old_str_len = len(modified_data)
                new_len = int(old_str_len * reduction_ratio)
                modified_data = modified_data[:new_len] + "...[TRUNCATED]"
                current_chars -= (old_str_len - len(modified_data))

        # Single final serialization for both char and byte checks.
        final_json = json.dumps(modified_data, ensure_ascii=False)
        final_bytes = final_json.encode('utf-8')
        final_size = len(final_bytes)
        if final_size > MAX_MCP_RESPONSE_SIZE_BYTES:
            # Reserve space for the wrapper dict overhead (~200 bytes)
            max_preview = TARGET_BYTES - 300
            truncated_str = final_json[:max_preview]
            modified_data = {
                "data_preview": truncated_str,
                "_truncation_warning": f"Response could not be structurally reduced. Converted to truncated string preview ({final_size} bytes -> {len(truncated_str)} bytes)."
            }
            # Final safety check — measure wrapper without re-serializing the preview
            wrapper_overhead = len(json.dumps({"data_preview": "", "_truncation_warning": modified_data["_truncation_warning"]}, ensure_ascii=False).encode('utf-8'))
            if wrapper_overhead + len(truncated_str.encode('utf-8')) > MAX_MCP_RESPONSE_SIZE_BYTES:
                safe_len = max(100, max_preview - (wrapper_overhead + len(truncated_str.encode('utf-8')) - MAX_MCP_RESPONSE_SIZE_BYTES))
                modified_data["data_preview"] = truncated_str[:safe_len]

        return modified_data

    except Exception as e:
        # If auto-truncation fails, fallback to the hard error so we don't crash the server
        await ctx.error(f"Auto-truncation failed: {e}")
        logger.error("MCP: Truncation logic failed: %s", e, exc_info=True)
        # Fallback to a safe, tiny error message
        return {
            "error": "Response too large",
            "message": f"The data generated was {data_size_bytes} bytes (Limit: {MAX_MCP_RESPONSE_SIZE_BYTES}). Auto-truncation failed.",
            "suggestion": limit_param_info or "Reduce limit parameter significantly."
        }
