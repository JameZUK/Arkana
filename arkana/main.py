"""Main entry point: argument parsing, CLI mode, and MCP server startup."""
import faulthandler
import os
import sys
import signal
import logging
import threading
import time
import argparse

# Enable faulthandler early so that segfaults, stuck threads, and deadlocks
# are diagnosable.  ``faulthandler.enable()`` dumps tracebacks to stderr on
# SIGSEGV/SIGABRT/etc.  On non-Windows, SIGUSR1 dumps *all* thread stacks —
# send ``kill -USR1 <pid>`` (or ``docker kill -s USR1 <container>``) to
# diagnose a hung process without needing py-spy or gdb.
faulthandler.enable()
if hasattr(signal, "SIGUSR1"):
    faulthandler.register(signal.SIGUSR1, all_threads=True, chain=False)

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from arkana.config import (
    state, logger, pefile,
    PEFILE_AVAILABLE,
    ANGR_AVAILABLE, MCP_SDK_AVAILABLE, FLOSS_AVAILABLE, REFINERY_AVAILABLE,
    FLOSS_MIN_LENGTH_DEFAULT,
    Actual_DebugLevel_Floss, Actual_StringType_Floss,
    DEFAULT_PEID_DB_PATH, DATA_DIR, CAPA_RULES_DEFAULT_DIR_NAME,
    CAPA_RULES_SUBDIR_NAME, YARA_AVAILABLE,
    log_library_availability,
)
from arkana.mock import MockPE
from arkana.utils import validate_regex_pattern, _safe_env_int
from arkana.background import _console_heartbeat_loop, _update_progress, start_angr_background
from arkana.parsers.pe import _parse_pe_to_dict, _parse_file_hashes
from arkana.parsers.strings import _extract_strings_from_data, _format_hex_dump_lines, _perform_unified_string_sifting
from arkana.parsers.floss import _parse_floss_analysis
from arkana.cli.printers import _cli_analyze_and_print_pe
from arkana.mcp.server import mcp_server
from arkana.mcp._format_helpers import detect_format_from_magic

# Tool registration is managed by the tool_registry module.
from arkana.tool_registry import register_all_tools as _register_all_tools


# ---------------------------------------------------------------------------
#  Resolved configuration dataclass — replaces many loose local variables
# ---------------------------------------------------------------------------

@dataclass
class _ResolvedConfig:
    """Holds all resolved paths and FLOSS configuration for a run."""
    abs_input_file: Optional[str] = None
    abs_peid_db_path: str = ""
    abs_yara_rules_path: Optional[str] = None
    abs_capa_rules_dir: Optional[str] = None
    abs_capa_sigs_dir: Optional[str] = None
    analyses_to_skip: List[str] = field(default_factory=list)
    # FLOSS config
    floss_min_len: int = 4
    floss_fmt: str = "auto"
    floss_debug_level: object = None  # Actual_DebugLevel_Floss enum
    floss_disabled_types: List = field(default_factory=list)
    floss_only_types: List = field(default_factory=list)
    floss_functions: List[int] = field(default_factory=list)
    floss_quiet: bool = True


# ---------------------------------------------------------------------------
#  Phase 1: Argument parsing
# ---------------------------------------------------------------------------

def _parse_arguments() -> argparse.Namespace:
    """Build the CLI parser and return parsed arguments."""
    parser = argparse.ArgumentParser(description="AI-Powered Binary Analysis.", formatter_class=argparse.RawTextHelpFormatter)

    # --- Input & Mode ---
    parser.add_argument("--input-file", type=str, default=None, help="Path to the file to be analyzed. Required for CLI mode. Optional for MCP server mode (use open_file tool instead).")
    parser.add_argument("--mode", choices=["auto", "pe", "elf", "macho", "shellcode"], default="auto", help="Analysis mode: 'auto' (default, detects from magic bytes), 'pe', 'elf', 'macho', or 'shellcode'.")

    # --- External Resources ---
    parser.add_argument("-d", "--db", dest="peid_db", default=None, help=f"Path to PEiD userdb.txt. If not specified, defaults to '{DEFAULT_PEID_DB_PATH}'. Downloads if not found.")
    parser.add_argument("-y", "--yara-rules", dest="yara_rules", default=None, help="Path to YARA rule file or directory. If not provided, uses bundled rules from ReversingLabs (MIT) and Yara-Rules Community (GPL-2.0), downloading them on first run if needed.")
    parser.add_argument("--capa-rules-dir", default=None, help=f"Directory containing capa rule files. If not provided or empty/invalid, attempts download to '{DATA_DIR / CAPA_RULES_DEFAULT_DIR_NAME / CAPA_RULES_SUBDIR_NAME}'.")
    parser.add_argument("--capa-sigs-dir", default=None, help="Directory containing capa library identification signature files (e.g., sigs/*.sig). Optional. If not provided, attempts to find a script-relative 'capa_sigs' or uses Capa's internal default.")

    # --- Skips ---
    parser.add_argument("--skip-capa", action="store_true", help="Skip capa capability analysis entirely.")
    parser.add_argument("--skip-floss", action="store_true", help="Skip FLOSS advanced string analysis entirely.")
    parser.add_argument("--skip-peid", action="store_true", help="Skip PEiD signature scanning entirely.")
    parser.add_argument("--skip-yara", action="store_true", help="Skip YARA scanning entirely.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for CLI mode and more detailed MCP logging.")

    # --- PEiD Options ---
    peid_group = parser.add_argument_group('PEiD Specific Options (if PEiD scan is not skipped)')
    peid_group.add_argument("--skip-full-peid-scan", action="store_true", help="Skip full PEiD scan (only scan entry point).")
    peid_group.add_argument("--psah", "--peid-scan-all-sigs-heuristically", action="store_true", dest="peid_scan_all_sigs_heuristically", help="During full heuristic PEiD scan, use ALL signatures (not just non-EP_only).")

    # --- FLOSS Options ---
    floss_group = parser.add_argument_group('FLOSS Specific Options (if FLOSS scan is not skipped)')
    floss_group.add_argument("--floss-min-length", "-n", type=int, default=None, help=f"Minimum string length for FLOSS (default: {FLOSS_MIN_LENGTH_DEFAULT}).")
    floss_group.add_argument("--floss-format", "-f", default="auto", choices=["auto", "pe", "sc32", "sc64"], help="File format hint for FLOSS/Vivisect (auto, pe, sc32, sc64). Important for shellcode mode.")
    floss_group.add_argument("--floss-no-static", action="store_true", help="FLOSS: Do not extract static strings.")
    floss_group.add_argument("--floss-no-stack", action="store_true", help="FLOSS: Do not extract stack strings.")
    floss_group.add_argument("--floss-no-tight", action="store_true", help="FLOSS: Do not extract tight strings.")
    floss_group.add_argument("--floss-no-decoded", action="store_true", help="FLOSS: Do not extract decoded strings.")
    floss_group.add_argument("--floss-only-static", action="store_true", help="FLOSS: Only extract static strings.")
    floss_group.add_argument("--floss-only-stack", action="store_true", help="FLOSS: Only extract stack strings.")
    floss_group.add_argument("--floss-only-tight", action="store_true", help="FLOSS: Only extract tight strings.")
    floss_group.add_argument("--floss-only-decoded", action="store_true", help="FLOSS: Only extract decoded strings.")
    floss_group.add_argument("--floss-functions", type=str, nargs="+", default=[], help="FLOSS: Hex addresses (e.g., 0x401000) of functions to analyze for stack/decoded strings.")
    floss_group.add_argument("--floss-verbose-level", "--fv", type=int, default=0, choices=[0,1,2], help="FLOSS internal verbosity for string output (0=default, 1=verbose, 2=more verbose). Default: 0.")
    floss_group.add_argument("--floss-quiet", "--fq", action="store_true", help="FLOSS: Suppress FLOSS's own progress indicators. Overrides script verbosity for FLOSS progress bars.")
    floss_group.add_argument("--floss-script-debug-level", default="NONE", choices=["NONE", "DEFAULT", "DEBUG", "TRACE", "SUPERTRACE"], help="Set logging level for FLOSS internal loggers (NONE, DEFAULT, TRACE, SUPERTRACE). Default: NONE.")
    floss_group.add_argument("-r", "--regex", dest="regex_pattern", type=str, default=None, help="A regex pattern to search for within all extracted FLOSS strings (case-insensitive).")

    # --- CLI Options ---
    cli_group = parser.add_argument_group('CLI Mode Specific Options (ignored if --mcp-server is used)')
    cli_group.add_argument("--extract-strings", action="store_true", help="Extract and print strings from the PE file (basic method, use FLOSS for advanced).")
    cli_group.add_argument("--min-str-len", type=int, default=5, help="Minimum length for basic extracted strings (default: 5).")
    cli_group.add_argument("--search-string", action="append", help="String to search for within the PE file (multiple allowed, basic method).")
    cli_group.add_argument("--strings-limit", type=int, default=100, help="Limit for basic string extraction and search results display (default: 100).")
    cli_group.add_argument("--hexdump-offset", type=lambda x:int(x,0), help="Hex dump start offset (e.g., 0x1000 or 4096).")
    cli_group.add_argument("--hexdump-length", type=int, help="Hex dump length in bytes.")
    cli_group.add_argument("--hexdump-lines", type=int, default=16, help="Maximum number of lines to display for hex dump (default: 16).")

    # --- MCP Options ---
    mcp_group = parser.add_argument_group('MCP Server Mode Specific Options')
    mcp_group.add_argument("--mcp-server", action="store_true", help="Run in MCP server mode. The --input-file is pre-analyzed, and tools operate on this file.")
    mcp_group.add_argument("--mcp-host", type=str, default="127.0.0.1", help="MCP server host (default: 127.0.0.1).")
    mcp_group.add_argument("--mcp-port", type=int, default=8082, help="MCP server port (default: 8082).")
    mcp_group.add_argument("--mcp-transport", type=str, default="stdio", choices=["stdio", "sse", "streamable-http"], help="MCP transport protocol: 'stdio' (default), 'streamable-http' (recommended for network), or 'sse' (deprecated).")
    mcp_group.add_argument("--allowed-paths", nargs="+", default=None, help="Restrict open_file to these directories (security sandbox for HTTP mode). Required for HTTP/SSE transports. Accepts multiple paths.")
    mcp_group.add_argument("--api-key", type=str, default=None, help="Bearer token for HTTP mode authentication. Clients must send 'Authorization: Bearer <key>' header. Can also be set via ARKANA_API_KEY env var.")
    mcp_group.add_argument("--samples-path", type=str, default=None, help="Path to the directory containing sample files for analysis. Exposed via the list_samples tool. Falls back to ARKANA_SAMPLES env var if not set.")
    mcp_group.add_argument("--no-dashboard", action="store_true", help="Disable the web dashboard entirely. Can also be set via ARKANA_NO_DASHBOARD=1 env var.")
    mcp_group.add_argument("--brief-descriptions", action="store_true", default=None,
                           help="Use brief tool descriptions (first paragraph only) to reduce "
                                "context window usage. Full descriptions include 'When to use', "
                                "'Next steps', Args, and Returns sections; brief mode keeps only "
                                "the phase label and summary sentence. "
                                "Falls back to ARKANA_BRIEF_DESCRIPTIONS=1 env var.")

    args = None
    try:
        args = parser.parse_args()
    except SystemExit as e:
        sys.exit(e.code)
    except Exception as e_parse:
        print(f"[!] Exception during argument parsing: {type(e_parse).__name__} - {e_parse}", file=sys.stderr)
        sys.exit(1)

    if args is None:
        print("[!] Args is None after parsing attempt, exiting.", file=sys.stderr)
        sys.exit(1)

    return args


# ---------------------------------------------------------------------------
#  Phase 2: Logging configuration
# ---------------------------------------------------------------------------

def _configure_logging(args: argparse.Namespace) -> int:
    """Set up logging based on parsed arguments. Returns the log level."""
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    logger.setLevel(log_level)
    log_library_availability()
    logging.getLogger('mcp').setLevel(log_level)
    if args.mcp_transport in ('sse', 'streamable-http'):
        logging.getLogger('uvicorn').setLevel(log_level)
        logging.getLogger('uvicorn.error').setLevel(log_level)
        logging.getLogger('uvicorn.access').setLevel(logging.WARNING if not args.verbose else logging.DEBUG)

    if args.mcp_transport == 'sse':
        logger.warning("SSE transport is deprecated. Please use 'streamable-http' or 'stdio' instead.")

    # Capture WARNING+ from library loggers (angr, cle, capa, etc.)
    from arkana.warning_handler import install_warning_handler
    install_warning_handler()

    return log_level


# ---------------------------------------------------------------------------
#  Phase 3: Path and skip-list resolution
# ---------------------------------------------------------------------------

def _resolve_paths(args: argparse.Namespace) -> _ResolvedConfig:
    """Resolve input file, resource paths, skip list, and FLOSS config."""
    cfg = _ResolvedConfig()

    # CLI mode requires --input-file
    if not args.mcp_server and not args.input_file:
        print("[!] Error: --input-file is required for CLI mode.", file=sys.stderr)
        sys.exit(1)

    if args.input_file:
        cfg.abs_input_file = str(Path(args.input_file).resolve())
        if not os.path.exists(cfg.abs_input_file):
            logger.critical("Input file not found: %s", cfg.abs_input_file)
            print(f"[!] Error: Input file not found: {cfg.abs_input_file}", file=sys.stderr)
            sys.exit(1)

    cfg.abs_peid_db_path = str(Path(args.peid_db).resolve()) if args.peid_db else str(DEFAULT_PEID_DB_PATH)
    cfg.abs_yara_rules_path = str(Path(args.yara_rules).resolve()) if args.yara_rules else None

    # Skip list — must be populated BEFORE YARA auto-resolution which checks it
    if args.skip_capa: cfg.analyses_to_skip.append("capa")
    if args.skip_floss: cfg.analyses_to_skip.append("floss")
    if args.skip_peid: cfg.analyses_to_skip.append("peid")
    if args.skip_yara: cfg.analyses_to_skip.append("yara")
    if cfg.analyses_to_skip:
        logger.info("Skipping analyses: %s", ", ".join(cfg.analyses_to_skip))

    # Auto-resolve to default YARA rules store when not explicitly specified
    if cfg.abs_yara_rules_path is None and YARA_AVAILABLE and "yara" not in cfg.analyses_to_skip:
        from arkana.resources import get_default_yara_rules_path, ensure_yara_rules_exist
        cfg.abs_yara_rules_path = get_default_yara_rules_path()
        if cfg.abs_yara_rules_path is None:
            logger.info("No YARA rules found. Attempting to download default rule sets...")
            store = ensure_yara_rules_exist(verbose=args.verbose)
            if store:
                cfg.abs_yara_rules_path = store
                logger.info("Default YARA rules available at: %s", cfg.abs_yara_rules_path)
            else:
                logger.info("Could not obtain default YARA rules. YARA scanning will be skipped unless --yara-rules is provided.")
        else:
            logger.info("Using default YARA rules store: %s", cfg.abs_yara_rules_path)

    cfg.abs_capa_rules_dir = str(Path(args.capa_rules_dir).resolve()) if args.capa_rules_dir else None
    cfg.abs_capa_sigs_dir = str(Path(args.capa_sigs_dir).resolve()) if args.capa_sigs_dir else None

    # Validate user-supplied regex pattern early
    if args.regex_pattern:
        try:
            validate_regex_pattern(args.regex_pattern)
        except ValueError as e:
            print(f"[!] Error: Invalid --regex pattern: {e}", file=sys.stderr)
            sys.exit(1)

    # Resolve FLOSS configuration
    _resolve_floss_config(args, cfg)

    return cfg


# ---------------------------------------------------------------------------
#  Phase 4: FLOSS configuration resolution
# ---------------------------------------------------------------------------

def _resolve_floss_config(args: argparse.Namespace, cfg: _ResolvedConfig) -> None:
    """Resolve all FLOSS-related parameters into *cfg*."""
    cfg.floss_min_len = args.floss_min_length if args.floss_min_length is not None else FLOSS_MIN_LENGTH_DEFAULT
    cfg.floss_fmt = args.floss_format

    # Auto-detect architecture hint for shellcode mode
    if args.mode == 'shellcode' and cfg.floss_fmt == 'auto':
        cfg.floss_fmt = 'sc64'
        logger.info("Shellcode mode detected with 'auto' format. Defaulting to 'sc64' (64-bit). Use --floss-format sc32 for 32-bit.")

    floss_debug_level_map = {
        "NONE": Actual_DebugLevel_Floss.NONE, "DEFAULT": Actual_DebugLevel_Floss.DEFAULT,
        "DEBUG": Actual_DebugLevel_Floss.DEFAULT,
        "TRACE": Actual_DebugLevel_Floss.TRACE, "SUPERTRACE": Actual_DebugLevel_Floss.SUPERTRACE
    }
    cfg.floss_debug_level = floss_debug_level_map.get(args.floss_script_debug_level.upper(), Actual_DebugLevel_Floss.NONE)

    if args.verbose and cfg.floss_debug_level == Actual_DebugLevel_Floss.NONE:
        cfg.floss_debug_level = Actual_DebugLevel_Floss.TRACE
        logger.info("Verbose mode active, elevating FLOSS debug level to TRACE.")

    if args.floss_no_static: cfg.floss_disabled_types.append(Actual_StringType_Floss.STATIC)
    if args.floss_no_stack: cfg.floss_disabled_types.append(Actual_StringType_Floss.STACK)
    if args.floss_no_tight: cfg.floss_disabled_types.append(Actual_StringType_Floss.TIGHT)
    if args.floss_no_decoded: cfg.floss_disabled_types.append(Actual_StringType_Floss.DECODED)

    if args.floss_only_static: cfg.floss_only_types.append(Actual_StringType_Floss.STATIC)
    if args.floss_only_stack: cfg.floss_only_types.append(Actual_StringType_Floss.STACK)
    if args.floss_only_tight: cfg.floss_only_types.append(Actual_StringType_Floss.TIGHT)
    if args.floss_only_decoded: cfg.floss_only_types.append(Actual_StringType_Floss.DECODED)

    for func_str in (args.floss_functions or []):
        try:
            cfg.floss_functions.append(int(func_str, 0))
        except ValueError:
            logger.warning("Invalid FLOSS function address '%s', skipping.", func_str)

    cfg.floss_quiet = args.floss_quiet or (
        not args.verbose and args.mcp_server
        and not (cfg.floss_debug_level > Actual_DebugLevel_Floss.NONE)
    )


# ---------------------------------------------------------------------------
#  Phase 5: MCP pre-loading
# ---------------------------------------------------------------------------

def _preload_file(args: argparse.Namespace, cfg: _ResolvedConfig) -> None:
    """Pre-load a file into state for MCP server mode."""
    abs_input_file = cfg.abs_input_file
    logger.info("MCP Server: Loading input file: %s (Mode: %s)", abs_input_file, args.mode)
    # H4: Initialize before try block so except handlers always have it defined
    temp_pe_obj_for_preload = None
    try:
        if not os.path.isfile(abs_input_file):
            logger.critical("Input path for MCP server is not a file: %s", abs_input_file)
            sys.exit(1)

        # Auto-detect format if mode is 'auto'
        effective_mode = args.mode
        if effective_mode == 'auto':
            with open(abs_input_file, 'rb') as f:
                magic = f.read(4)
            effective_mode = detect_format_from_magic(magic)
            if effective_mode == "unknown":
                # M-ST6: Fall back to shellcode mode (consistent with open_file MCP tool)
                # rather than PE mode which can crash on non-PE files.
                effective_mode = 'shellcode'
                logger.warning(
                    "Unrecognized file format (magic: %s). "
                    "Falling back to raw/shellcode mode. Use --mode to specify the format explicitly.",
                    magic.hex(),
                )
            logger.info("Auto-detected format: %s", effective_mode)

        # M1-v11: Guard against excessively large files for ALL modes (not just shellcode/elf/macho)
        # M-11: Use _safe_env_int to handle non-numeric env values gracefully
        from arkana.constants import DEFAULT_MAX_FILE_SIZE_MB
        max_file_mb = _safe_env_int("ARKANA_MAX_FILE_SIZE_MB", DEFAULT_MAX_FILE_SIZE_MB)
        file_size = os.path.getsize(abs_input_file)
        if file_size > max_file_mb * 1024 * 1024:
            logger.critical("File too large for preload: %d bytes (limit: %d MB)", file_size, max_file_mb)
            sys.exit(1)

        # Loading logic with mode support
        if effective_mode == 'shellcode':
            with open(abs_input_file, 'rb') as f:
                raw_data = f.read()
            state.pe_object = MockPE(raw_data)
            state.filepath = abs_input_file
            state.pe_data = {
                "filepath": abs_input_file,
                "mode": "shellcode",
                "file_hashes": _parse_file_hashes(raw_data),
                "basic_ascii_strings": [{"offset": hex(o), "string": s} for o, s in _extract_strings_from_data(raw_data, 5)],
                "floss_analysis": {"status": "Pending..."}
            }
            if "floss" not in cfg.analyses_to_skip:
                state.pe_data['floss_analysis'] = _parse_floss_analysis(
                    abs_input_file, cfg.floss_min_len, args.floss_verbose_level,
                    cfg.floss_debug_level, cfg.floss_fmt,
                    cfg.floss_disabled_types, cfg.floss_only_types,
                    cfg.floss_functions, cfg.floss_quiet,
                    args.regex_pattern,
                    pe_object=state.pe_object,
                )
                _perform_unified_string_sifting(state.pe_data)

        elif effective_mode in ('elf', 'macho'):
            with open(abs_input_file, 'rb') as f:
                raw_data = f.read()
            state.pe_object = MockPE(raw_data)
            state.filepath = abs_input_file
            format_label = "ELF" if effective_mode == "elf" else "Mach-O"
            state.pe_data = {
                "filepath": abs_input_file,
                "mode": effective_mode,
                "format": format_label,
                "file_hashes": _parse_file_hashes(raw_data),
                "basic_ascii_strings": [{"offset": hex(o), "string": s} for o, s in _extract_strings_from_data(raw_data, 5)],
                "note": f"{format_label} binary loaded. Use format-specific tools (elf_analyze/macho_analyze) and angr tools for analysis.",
            }
            logger.info("Loaded %s binary: %s", format_label, abs_input_file)

        else:
            temp_pe_obj_for_preload = pefile.PE(abs_input_file, fast_load=False)
            state.filepath = abs_input_file
            state.pe_object = temp_pe_obj_for_preload
            state.pe_data = _parse_pe_to_dict(
                temp_pe_obj_for_preload, abs_input_file, cfg.abs_peid_db_path, cfg.abs_yara_rules_path,
                cfg.abs_capa_rules_dir, cfg.abs_capa_sigs_dir,
                args.verbose, args.skip_full_peid_scan, args.peid_scan_all_sigs_heuristically,
                floss_min_len_arg=cfg.floss_min_len,
                floss_verbose_level_arg=args.floss_verbose_level,
                floss_script_debug_level_arg=cfg.floss_debug_level,
                floss_format_hint_arg=cfg.floss_fmt,
                floss_disabled_types_arg=cfg.floss_disabled_types,
                floss_only_types_arg=cfg.floss_only_types,
                floss_functions_to_analyze_arg=cfg.floss_functions,
                floss_quiet_mode_arg=cfg.floss_quiet,
                analyses_to_skip=cfg.analyses_to_skip
            )
            _perform_unified_string_sifting(state.pe_data)

        logger.info("MCP: Successfully loaded analysis for: %s.", abs_input_file)

        # Background Angr analysis (mode aware)
        if ANGR_AVAILABLE:
            arch_hint = "amd64" if "64" in cfg.floss_fmt else "x86"
            start_angr_background(
                abs_input_file,
                mode=effective_mode,
                arch_hint=arch_hint,
                tool_label="startup_auto_analysis",
            )

    except (OSError, pefile.PEFormatError, ValueError, RuntimeError) as e:
        logger.critical("MCP: Failed to pre-load file: %s: %s", type(e).__name__, e, exc_info=True)
        if temp_pe_obj_for_preload is not None:
            temp_pe_obj_for_preload.close()
        state.filepath = None
        state.pe_data = None
        state.pe_object = None
        logger.error("MCP server startup aborted due to pre-load failure.")
        sys.exit(1)
    except Exception as e:
        logger.critical("MCP: Unexpected error during pre-load: %s: %s", type(e).__name__, e, exc_info=True)
        if temp_pe_obj_for_preload is not None:
            temp_pe_obj_for_preload.close()
        state.filepath = None
        state.pe_data = None
        state.pe_object = None
        sys.exit(1)


# ---------------------------------------------------------------------------
#  Phase 6: MCP server startup
# ---------------------------------------------------------------------------

def _start_mcp_server(args: argparse.Namespace, cfg: _ResolvedConfig, log_level: int) -> None:
    """Configure and run the MCP server."""
    if not MCP_SDK_AVAILABLE:
        logger.critical("MCP SDK ('modelcontextprotocol') not available. Cannot start MCP server. Please install it (e.g., 'pip install \"mcp[cli]\"') and re-run.")
        sys.exit(1)

    # Resolve brief descriptions: CLI flag > env var > default off
    # Must be set BEFORE tool registration so docstrings are trimmed at
    # decoration time when tool modules are imported.
    brief = args.brief_descriptions or os.environ.get("ARKANA_BRIEF_DESCRIPTIONS", "0") == "1"
    if brief:
        from arkana.mcp.server import set_brief_descriptions
        set_brief_descriptions(True)
        logger.info("Brief tool descriptions enabled — tool listing will use first-paragraph summaries only")

    # Register all tools
    count = _register_all_tools(refinery_available=REFINERY_AVAILABLE)
    logger.info("%d tool modules registered", count)
    if not REFINERY_AVAILABLE:
        logger.info("binary-refinery not installed — skipping refinery tool registration")

    # Configure path sandboxing — mandatory for HTTP transports
    if args.allowed_paths:
        state.allowed_paths = [str(Path(p).resolve()) for p in args.allowed_paths]
        logger.info("Path sandboxing enabled. Allowed paths: %s", state.allowed_paths)
    elif args.mcp_transport in ("sse", "streamable-http"):
        logger.critical(
            "Running in network mode (HTTP) requires --allowed-paths for security. "
            "Specify directories that MCP clients are allowed to access, e.g.: "
            "--allowed-paths /path/to/samples /tmp/analysis"
        )
        sys.exit(1)

    # Configure API key authentication for HTTP transports
    api_key = args.api_key or os.environ.get("ARKANA_API_KEY") or os.environ.get("PEMCP_API_KEY")
    if args.mcp_transport in ("sse", "streamable-http"):
        if api_key:
            state.api_key = api_key
            logger.info("API key authentication enabled for HTTP transport.")
        else:
            import secrets
            api_key = secrets.token_hex(16)
            state.api_key = api_key
            # M-S1: Only log truncated key to prevent plaintext credential in logs
            logger.warning(
                "No --api-key provided. Auto-generated API key for HTTP transport: %s...",
                api_key[:8],
            )
            # M4-v11: Show full key only in interactive terminals; mask in log captures
            if sys.stderr.isatty():
                print(f"Auto-generated API key: {api_key}", file=sys.stderr)
            else:
                print(f"Auto-generated API key: {api_key[:8]}... (run interactively to see full key)", file=sys.stderr)

    # Configure samples directory
    samples_path = args.samples_path or os.environ.get("ARKANA_SAMPLES") or os.environ.get("PEMCP_SAMPLES")
    if samples_path:
        resolved = str(Path(samples_path).resolve())
        if os.path.isdir(resolved):
            state.samples_path = resolved
            logger.info("Samples directory configured: %s", resolved)
        else:
            logger.warning("Samples path does not exist or is not a directory: %s", resolved)
    else:
        logger.info("No samples directory configured. Use --samples-path or set ARKANA_SAMPLES env var to enable the list_samples tool.")

    # Optional pre-loading
    if cfg.abs_input_file:
        _preload_file(args, cfg)
    else:
        logger.info("MCP Server: No --input-file provided. Server starting without a pre-loaded file.")
        logger.info("Use the 'open_file' tool to load a PE file for analysis.")

    logger.info("The MCP server is ready.")

    # --- Dashboard configuration ---
    dashboard_disabled = args.no_dashboard or os.environ.get("ARKANA_NO_DASHBOARD", "") == "1"
    dashboard_port = _safe_env_int("ARKANA_DASHBOARD_PORT", 8082)

    if args.mcp_transport in ("sse", "streamable-http"):
        mcp_server.settings.host = args.mcp_host
        mcp_server.settings.port = args.mcp_port
        mcp_server.settings.log_level = logging.getLevelName(log_level).lower()
        transport_label = "streamable-http" if args.mcp_transport == "streamable-http" else "SSE (deprecated)"
        logger.info("Starting MCP server (%s) on http://%s:%d", transport_label, args.mcp_host, args.mcp_port)
    else:
        logger.info("Starting MCP server (stdio).")
        # Start dashboard in background thread for stdio mode
        if not dashboard_disabled and dashboard_port > 0:
            try:
                from arkana.dashboard.app import start_dashboard_thread
                # M2: Default to 127.0.0.1 for security; Docker run.sh
                # sets ARKANA_DASHBOARD_HOST=0.0.0.0 explicitly.
                dashboard_host = os.environ.get("ARKANA_DASHBOARD_HOST", "127.0.0.1")
                start_dashboard_thread(host=dashboard_host, port=dashboard_port)
            except Exception as e:
                logger.warning("Failed to start dashboard server: %s", e)

    # Translate SIGTERM into KeyboardInterrupt so the existing cleanup
    # path (finally block) runs identically for both Ctrl-C and container
    # stop / kill signals. A watchdog ensures the process exits within
    # _SIGTERM_WATCHDOG_S even if asyncio's executor shutdown hangs on a
    # stuck thread.
    #
    # The 15-second ceiling matches the normal-exit watchdog in the
    # finally: block — the previous 5s budget could fire mid-write during
    # the final overlay flush on a heavily-loaded disk, losing exactly
    # the work the final flush was added to preserve. 15s is generous
    # enough for the largest realistic overlay (a few MB of notes/
    # artifacts gzipped) while still keeping ``docker stop`` responsive.
    _SIGTERM_WATCHDOG_S = 15
    _sigterm_watchdog_started = False
    def _sigterm_handler(signum, frame):
        nonlocal _sigterm_watchdog_started
        if not _sigterm_watchdog_started:
            _sigterm_watchdog_started = True
            def _watchdog():
                time.sleep(_SIGTERM_WATCHDOG_S)
                os._exit(1)
            threading.Thread(target=_watchdog, daemon=True).start()
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _sigterm_handler)

    server_exc = None
    try:
        # If using HTTP transport, compose the ASGI app
        if args.mcp_transport in ("sse", "streamable-http"):
            try:
                import uvicorn
                from arkana.auth import BearerAuthMiddleware
                # Import the official security settings class
                try:
                    from mcp.server.transport_security import TransportSecuritySettings
                    # Disable DNS rebinding protection to allow connections from your LAN/Docker network
                    security = TransportSecuritySettings(
                        enable_dns_rebinding_protection=True,
                        allowed_hosts=[
                            "192.168.0.*:8082"
                        ],
                        allowed_origins=[
                            "http://192.168.0.8:8082"
                        ],
                    )
                except ImportError:
                    security = None

                if args.mcp_transport == "streamable-http":
                    if security is not None:
                        mcp_app = mcp_server.streamable_http_app(transport_security=security)
                    else:
                        mcp_app = mcp_server.streamable_http_app()
                else:
                    mcp_app = mcp_server.sse_app()

                if api_key:
                    mcp_app = BearerAuthMiddleware(mcp_app, api_key)

                # Mount dashboard alongside MCP in HTTP mode
                if not dashboard_disabled:
                    try:
                        from starlette.applications import Starlette
                        from starlette.routing import Mount
                        from arkana.dashboard.app import create_dashboard_app
                        from contextlib import asynccontextmanager
                        from typing import AsyncIterator
                        dashboard_app = create_dashboard_app()
                        @asynccontextmanager
                        async def lifespan(app: Starlette) -> AsyncIterator[None]:
                            async with mcp_server.session_manager.run():
                                yield
                        combined = Starlette(
                            routes=[
                                Mount("/dashboard", app=dashboard_app),
                                Mount("/", app=mcp_app),
                            ],
                            lifespan=lifespan  # ADD THIS LINE
                        )
                        from arkana.dashboard.app import _ensure_token
                        token = _ensure_token()
                        logger.info(
                            "Snorington - Dashboard: http://%s:%d/dashboard/?token=%s",
                            args.mcp_host, args.mcp_port, token[:8] + "...",
                        )
                        app = combined
                    except Exception as e:
                        logger.warning("Could not mount dashboard (%s), running MCP only", e)
                        app = mcp_app
                else:
                    app = mcp_app

                uvicorn.run(
                    app,
                    host=args.mcp_host,
                    port=args.mcp_port,
                    log_level=logging.getLevelName(log_level).lower(),
                )
            except (ImportError, AttributeError) as e:
                logger.warning("Could not start HTTP server (%s), falling back to basic mode", e)
                mcp_server.run(transport=args.mcp_transport)
        else:
            mcp_server.run(transport=args.mcp_transport)
    except KeyboardInterrupt:
        logger.info("MCP Server stopped by user (KeyboardInterrupt).")
    except Exception as e:
        logger.critical("MCP Server encountered an unhandled error: %s", e, exc_info=True)
        server_exc = e
    finally:
        if state.pe_object:
            state.pe_object.close()
            logger.info("MCP: Closed pre-loaded object upon server exit.")
        # Final overlay flush — push any pending dirty session state to
        # disk BEFORE the watchdog can fire. The background flush daemon
        # only wakes every OVERLAY_FLUSH_INTERVAL_SECONDS, so a dirty
        # overlay added in the last 30s before shutdown would otherwise
        # be lost. Best-effort: per-state try/except so one slow flush
        # doesn't block the others.
        try:
            from arkana.state import get_all_session_states
            for st in get_all_session_states():
                try:
                    if hasattr(st, "is_overlay_dirty") and st.is_overlay_dirty():
                        st.flush_overlay()
                except Exception:
                    logger.debug("Final flush: per-state error", exc_info=True)
        except Exception:
            logger.debug("Final flush: skipped", exc_info=True)
        # Watchdog: ensure the process actually exits even if a daemon
        # thread (uvicorn dashboard, angr background, qiling subprocess
        # joiner, …) leaves the interpreter spinning during shutdown.
        # ``sys.exit`` raises SystemExit which runs atexit handlers and
        # joins non-daemon threads — historically that has hung in the
        # field on stuck angr/uvicorn shutdowns. The 15-second ceiling is
        # generous enough to absorb a slow final overlay flush on a
        # heavily-loaded disk; the existing SIGTERM watchdog (5s) is
        # tighter for the docker-stop case where the operator is actively
        # waiting.
        def _exit_watchdog():
            time.sleep(15)
            os._exit(1 if server_exc else 0)
        threading.Thread(target=_exit_watchdog, daemon=True).start()
        sys.exit(1 if server_exc else 0)


# ---------------------------------------------------------------------------
#  Phase 7: CLI analysis
# ---------------------------------------------------------------------------

def _run_cli_analysis(args: argparse.Namespace, cfg: _ResolvedConfig) -> None:
    """Run CLI-mode analysis and print results."""
    abs_input_file = cfg.abs_input_file
    try:
        if args.mode == 'shellcode':
            print(f"[*] CLI Mode: Shellcode Analysis ({abs_input_file})")
            with open(abs_input_file, 'rb') as f:
                data = f.read()

            print(f"\n--- File Hashes ---")
            hashes = _parse_file_hashes(data)
            for k, v in hashes.items(): print(f"  {k.upper()}: {v}")

            if args.extract_strings:
                print(f"\n--- Strings (Min Len: {args.min_str_len}) ---")
                for off, s in _extract_strings_from_data(data, args.min_str_len):
                    print(f"  {hex(off)}: {s}")

            if args.hexdump_offset is not None and args.hexdump_length is not None:
                 print(f"\n--- Hex Dump ---")
                 start = args.hexdump_offset
                 end = start + args.hexdump_length
                 lines = _format_hex_dump_lines(data[start:end], start, 16)
                 for l in lines[:args.hexdump_lines]: print(l)

            print("\n[!] Note: For deep shellcode analysis (Angr/FLOSS), please use MCP Server mode or FLOSS directly.")

        elif args.mode in ('elf', 'macho'):
            print(f"[!] Error: CLI mode does not support '{args.mode}' format analysis.", file=sys.stderr)
            print("[!] Please use MCP server mode (--mcp-server) for ELF and Mach-O analysis.", file=sys.stderr)
            sys.exit(1)
        else:
            # PE CLI Mode
            _cli_analyze_and_print_pe(
                abs_input_file, cfg.abs_peid_db_path, cfg.abs_yara_rules_path,
                cfg.abs_capa_rules_dir, cfg.abs_capa_sigs_dir,
                args.verbose, args.skip_full_peid_scan, args.peid_scan_all_sigs_heuristically,
                cfg.floss_min_len, args.floss_verbose_level,
                cfg.floss_debug_level, cfg.floss_fmt,
                cfg.floss_disabled_types, cfg.floss_only_types,
                cfg.floss_functions, cfg.floss_quiet,
                args.extract_strings, args.min_str_len, args.search_string,
                args.strings_limit, args.hexdump_offset, args.hexdump_length,
                args.hexdump_lines, cfg.analyses_to_skip
            )
    except KeyboardInterrupt:
        print("\n[*] CLI Analysis interrupted by user. Exiting.")
        sys.exit(1)
    except Exception as e_cli_main:
        print(f"\n[!] A critical unexpected error occurred during CLI analysis: {type(e_cli_main).__name__} - {e_cli_main}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
#  Entry point
# ---------------------------------------------------------------------------

def main():
    args = _parse_arguments()
    log_level = _configure_logging(args)
    cfg = _resolve_paths(args)

    if args.mcp_server:
        if not PEFILE_AVAILABLE:
            print("[!] WARNING: The 'pefile' library is not found.", file=sys.stderr)
            print("[!] PE file analysis will be unavailable. ELF and Mach-O analysis will still work.", file=sys.stderr)
            print("[!] Install it with: pip install pefile", file=sys.stderr)
        _start_mcp_server(args, cfg, log_level)
    else:
        if not PEFILE_AVAILABLE:
            print("[!] CRITICAL ERROR: The 'pefile' library is not found.", file=sys.stderr)
            print("[!] CLI mode requires pefile for PE analysis.", file=sys.stderr)
            print("[!] Install it with: pip install pefile", file=sys.stderr)
            sys.exit(1)
        _run_cli_analysis(args, cfg)
