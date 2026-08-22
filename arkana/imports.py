"""
Optional library imports and availability flags.

Every optional dependency is imported here with a corresponding
``*_AVAILABLE`` flag.  Other modules import these flags (and guarded
library objects) via ``config.py`` re-exports.
"""
import os
import sys
import logging
import shutil
import threading
import contextlib

__all__ = [
    # Availability flags
    "PEFILE_AVAILABLE",
    "CRYPTOGRAPHY_AVAILABLE", "REQUESTS_AVAILABLE",
    "SIGNIFY_AVAILABLE", "SIGNIFY_IMPORT_ERROR",
    "YARA_AVAILABLE", "YARA_IMPORT_ERROR",
    "RAPIDFUZZ_AVAILABLE", "RAPIDFUZZ_IMPORT_ERROR",
    "CAPA_AVAILABLE", "CAPA_IMPORT_ERROR",
    "FLOSS_AVAILABLE", "FLOSS_SETUP_OK", "FLOSS_ANALYSIS_OK",
    "FLOSS_IMPORT_ERROR_SETUP", "FLOSS_IMPORT_ERROR_ANALYSIS",
    "STRINGSIFTER_AVAILABLE", "STRINGSIFTER_IMPORT_ERROR",
    "MCP_SDK_AVAILABLE", "MCP_SDK_MAJOR", "MCP_SDK_VERSION", "MCP_SDK_IMPORT_ERROR",
    "ANGR_AVAILABLE",
    "LIEF_AVAILABLE", "CAPSTONE_AVAILABLE", "KEYSTONE_AVAILABLE",
    "SPEAKEASY_AVAILABLE", "SPEAKEASY_IMPORT_ERROR",
    "UNIPACKER_AVAILABLE", "UNIPACKER_IMPORT_ERROR",
    "QILING_AVAILABLE", "QILING_IMPORT_ERROR",
    "DOTNETFILE_AVAILABLE", "PPDEEP_AVAILABLE", "TLSH_AVAILABLE",
    "BINWALK_AVAILABLE", "BINWALK_CLI_ONLY",
    "PYGORE_AVAILABLE", "GORESYM_AVAILABLE", "PYELFTOOLS_AVAILABLE",
    "DNFILE_AVAILABLE", "DNCIL_AVAILABLE",
    "RUSTBININFO_AVAILABLE", "RUST_DEMANGLER_AVAILABLE",
    "REFINERY_AVAILABLE",
    "OLETOOLS_AVAILABLE",
    "AUTOIT_RIPPER_AVAILABLE",
    "TRITON_AVAILABLE",
    "PSUTIL_AVAILABLE",
    "DE4DOT_AVAILABLE", "DE4DOT_IMPORT_ERROR",
    "NETREACTORSLAYER_AVAILABLE", "NETREACTORSLAYER_IMPORT_ERROR",
    "ILSPYCMD_AVAILABLE", "ILSPYCMD_IMPORT_ERROR",
    # Key imports re-exported via config.py
    "pefile", "nx",
    "FastMCP", "Context",
    "DATA_DIR", "DEFAULT_PEID_DB_PATH", "VT_API_KEY",
    # FLOSS types
    "FLOSS_MIN_LENGTH_DEFAULT",
    "Actual_DebugLevel_Floss", "Actual_StringType_Floss",
    "Floss_ColorFormatter_Class", "FLOSS_TRACE_LEVEL_CONST",
    "FLOSS_LOGGERS_LIST",
    # Capa exception classes
    "CapaError", "InvalidRule", "RulesAccessError", "FreezingError",
    # Functions
    "log_library_availability",
]

from pathlib import Path
from enum import IntEnum, Enum
from typing import Type

from arkana.constants import MIN_STR_LEN_FALLBACK_FLOSS
from arkana.user_config import get_config_value

# Third-party (always available)
import networkx as nx  # noqa: F401

logger = logging.getLogger("Arkana")


def _quiet_stdout():
    """Redirect stdout to stderr for the duration of an import.

    In stdio MCP mode stdout *is* the JSON-RPC channel, so a library that
    prints a banner at import time corrupts the stream before the server
    has written a single byte and a strict client drops the connection.
    Wrap any third-party import known to print at import time.
    """
    return contextlib.redirect_stdout(sys.stderr)


# --- Data directory ---
DATA_DIR = Path(os.getenv("ARKANA_DATA_DIR") or os.getenv("PEMCP_DATA_DIR", Path(__file__).resolve().parent.parent))

# --- Derived path constants (depend on DATA_DIR) ---
from arkana.constants import CAPA_RULES_DEFAULT_DIR_NAME, CAPA_RULES_SUBDIR_NAME  # noqa: E402
DEFAULT_PEID_DB_PATH = DATA_DIR / "userdb.txt"

# --- VirusTotal API key (from user config) ---
VT_API_KEY = get_config_value("vt_api_key")

# --- pefile (Critical Dependency — checked at startup in main()) ---
PEFILE_AVAILABLE = False
pefile = None  # type: ignore[assignment]
try:
    import pefile as _pefile_mod
    pefile = _pefile_mod
    PEFILE_AVAILABLE = True
except ImportError:
    logger.critical(
        "The 'pefile' library is not installed. "
        "PE analysis will be unavailable. Install with: pip install pefile"
    )

# --- Optional Library Imports & Availability Flags ---
CRYPTOGRAPHY_AVAILABLE = False
try:
    from cryptography import x509  # noqa: F401
    from cryptography.hazmat.primitives.serialization import pkcs7  # noqa: F401
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    pass

REQUESTS_AVAILABLE = False
try:
    import requests  # noqa: F401
    REQUESTS_AVAILABLE = True
except ImportError:
    pass

# --- Corrected Signify Import ---
SIGNIFY_AVAILABLE = False
SIGNIFY_IMPORT_ERROR = None
try:
    from signify.authenticode import AuthenticodeFile, AuthenticodeVerificationResult  # noqa: F401
    SIGNIFY_AVAILABLE = True
except ImportError as e:
    SIGNIFY_IMPORT_ERROR = str(e)
    SIGNIFY_AVAILABLE = False
except Exception as e:
    # Signify can fail with non-ImportError exceptions (e.g. oscrypto
    # compatibility issues).  Log the error instead of printing to stderr
    # unconditionally — signify is genuinely optional.
    SIGNIFY_IMPORT_ERROR = str(e)
    SIGNIFY_AVAILABLE = False

YARA_AVAILABLE = False
YARA_IMPORT_ERROR = None
try:
    import yara  # noqa: F401
    YARA_AVAILABLE = True
except ImportError as e:
    YARA_IMPORT_ERROR = str(e)

RAPIDFUZZ_AVAILABLE = False
RAPIDFUZZ_IMPORT_ERROR = None
try:
    from rapidfuzz import fuzz  # noqa: F401
    RAPIDFUZZ_AVAILABLE = True
except ImportError as e:
    RAPIDFUZZ_AVAILABLE = False
    RAPIDFUZZ_IMPORT_ERROR = str(e)

# --- Capa custom exception classes ---
class CapaError(Exception):
    def __init__(self, msg="Generic Capa Error", status_code=None):
        super().__init__(msg)
        self.status_code = status_code

class InvalidRule(CapaError): pass
class RulesAccessError(CapaError): pass
class FreezingError(CapaError): pass

CAPA_AVAILABLE = False
CAPA_IMPORT_ERROR = None

try:
    import capa  # noqa: F401
    import capa.main  # noqa: F401
    import capa.rules  # noqa: F401
    import capa.loader  # noqa: F401
    import capa.capabilities.common  # noqa: F401
    import capa.render.result_document as rd  # noqa: F401
    import capa.engine  # noqa: F401
    import capa.render.json as capa_json_render  # noqa: F401
    import capa.features.extractors.pefile as capa_pefile_extractor  # noqa: F401
    import capa.features.common  # noqa: F401

    from capa.exceptions import (  # noqa: F401
        InvalidArgument,
        EmptyReportError,
        UnsupportedOSError,
        UnsupportedArchError,
        UnsupportedFormatError,
        UnsupportedRuntimeError,
    )

    CAPA_AVAILABLE = True
    CAPA_IMPORT_ERROR = None
    logger.info("Successfully imported capa modules and new-style exceptions. Arkana will attempt to use this capa API.")

except ImportError as e:
    CAPA_IMPORT_ERROR = str(e)
    CAPA_AVAILABLE = False
    logger.warning("Failed to import necessary capa modules: %s. Capa analysis will be skipped.", CAPA_IMPORT_ERROR)
except Exception as e_generic:
    CAPA_IMPORT_ERROR = f"An unexpected error occurred during capa import attempts: {e_generic}"
    CAPA_AVAILABLE = False
    logger.error(CAPA_IMPORT_ERROR, exc_info=True)

# --- FLOSS Import Section ---
class DebugLevelFallbackFloss(IntEnum):
    NONE = 0
    DEFAULT = 1
    TRACE = 2
    SUPERTRACE = 3

class StringTypeFallbackFloss(str, Enum):
    STATIC = "static"
    STACK = "stack"
    TIGHT = "tight"
    DECODED = "decoded"

FLOSS_MIN_LENGTH_DEFAULT = MIN_STR_LEN_FALLBACK_FLOSS
Actual_DebugLevel_Floss: Type = DebugLevelFallbackFloss
Actual_StringType_Floss: Type = StringTypeFallbackFloss
Floss_ColorFormatter_Class: Type = logging.Formatter
FLOSS_TRACE_LEVEL_CONST = logging.DEBUG

FLOSS_SETUP_OK = False
FLOSS_ANALYSIS_OK = False
FLOSS_AVAILABLE = False
FLOSS_IMPORT_ERROR_SETUP = None
FLOSS_IMPORT_ERROR_ANALYSIS = None

try:
    import floss.logging_ as floss_logging  # noqa: F401
    import floss.main as floss_main  # noqa: F401
    from floss.const import MIN_STRING_LENGTH as FLOSS_MIN_LENGTH_FROM_LIB

    Actual_DebugLevel_Floss = floss_logging.DebugLevel
    Actual_StringType_Floss = floss_main.StringType
    FLOSS_MIN_LENGTH_DEFAULT = FLOSS_MIN_LENGTH_FROM_LIB
    Floss_ColorFormatter_Class = floss_logging.ColorFormatter
    FLOSS_TRACE_LEVEL_CONST = floss_logging.TRACE
    FLOSS_SETUP_OK = True
    logger.info("Successfully imported basic FLOSS components (logging, main, const).")
except ImportError as e_floss_setup:
    FLOSS_IMPORT_ERROR_SETUP = str(e_floss_setup)
    logger.warning("Warning: Error importing basic FLOSS components (logging, main, const): %s", e_floss_setup)
    logger.warning("Using fallback values for FLOSS script setup. Full FLOSS functionality may be impaired.")
except (OSError, ValueError) as e_floss_setup_generic:
    FLOSS_IMPORT_ERROR_SETUP = f"Generic error during FLOSS setup import: {e_floss_setup_generic}"
    logger.error("FLOSS setup import failed unexpectedly: %s", e_floss_setup_generic, exc_info=True)

if FLOSS_SETUP_OK:
    try:
        import viv_utils  # noqa: F401
        from vivisect import VivWorkspace  # noqa: F401
        from floss.utils import get_static_strings, set_vivisect_log_level, get_imagebase  # noqa: F401
        from floss.identify import (  # noqa: F401
            find_decoding_function_features, get_top_functions, get_function_fvas,
            get_tight_function_fvas, append_unique, get_functions_with_tightloops
        )
        from floss.stackstrings import extract_stackstrings  # noqa: F401
        from floss.tightstrings import extract_tightstrings  # noqa: F401
        from floss.string_decoder import decode_strings  # noqa: F401
        from floss.results import ResultDocument, Metadata as FlossMetadata, Analysis as FlossAnalysis  # noqa: F401
        FLOSS_ANALYSIS_OK = True
        logger.info("Successfully imported FLOSS analysis functions and vivisect/viv_utils.")
    except ImportError as e_floss_analysis:
        FLOSS_IMPORT_ERROR_ANALYSIS = str(e_floss_analysis)
        logger.error("Error importing FLOSS analysis functions (or their dependencies like vivisect): %s", e_floss_analysis)
        FLOSS_ANALYSIS_OK = False
    except (OSError, ValueError) as e_floss_analysis_generic:
        FLOSS_IMPORT_ERROR_ANALYSIS = f"Generic error during FLOSS analysis import: {e_floss_analysis_generic}"
        logger.error("FLOSS analysis import failed unexpectedly: %s", e_floss_analysis_generic, exc_info=True)
        FLOSS_ANALYSIS_OK = False
else:
    logger.warning("Skipping import of FLOSS analysis functions due to earlier FLOSS setup import errors.")

FLOSS_AVAILABLE = FLOSS_SETUP_OK and FLOSS_ANALYSIS_OK

FLOSS_LOGGERS_LIST = [
    "floss", "floss.utils", "floss.identify", "floss.stackstrings",
    "floss.tightstrings", "floss.string_decoder", "EmulatorDriver", "Monitor",
    "envi", "envi.codeflow", "vtrace", "vtrace.platforms.win32",
    "vivisect", "vivisect.parsers.pe", "viv_utils.emulator_drivers",
]

STRINGSIFTER_AVAILABLE = False
STRINGSIFTER_IMPORT_ERROR = None
try:
    import stringsifter.lib.util as sifter_util  # noqa: F401
    import joblib  # noqa: F401
    import numpy  # noqa: F401
    STRINGSIFTER_AVAILABLE = True
except ImportError as e:
    STRINGSIFTER_AVAILABLE = False
    STRINGSIFTER_IMPORT_ERROR = str(e)

# --- MCP SDK (v2 preferred, v1 supported) ---
#
# The SDK renamed and relocated its high-level server class in v2.0:
#   v1:  mcp.server.fastmcp.FastMCP
#   v2:  mcp.server.mcpserver.MCPServer   (mcp.server.fastmcp removed entirely)
#
# Both classes expose the same surface Arkana relies on -- ``tool()``,
# ``run()``, ``sse_app()``, ``streamable_http_app()`` and a ``Context``
# that is auto-injected into tool signatures -- so a single alias covers
# both.  The name ``FastMCP`` is kept as the internal alias so the rest of
# the codebase (and the ``config.py`` re-export hub) is version-agnostic.
#
# The one genuine divergence is ``settings``: v1 carried ``host``/``port``
# on the settings object, v2 moved them to the app-factory / runner
# keyword arguments.  ``arkana.main._configure_mcp_transport`` handles that
# difference; nothing else in the codebase touches ``settings``.
MCP_SDK_AVAILABLE = False
MCP_SDK_MAJOR = 0
MCP_SDK_VERSION = None
MCP_SDK_IMPORT_ERROR = None
try:
    from mcp.server.mcpserver import MCPServer as FastMCP, Context  # noqa: F401
    MCP_SDK_AVAILABLE = True
    MCP_SDK_MAJOR = 2
except ImportError as _mcp_v2_err:
    try:
        from mcp.server.fastmcp import FastMCP, Context  # noqa: F401
        MCP_SDK_AVAILABLE = True
        MCP_SDK_MAJOR = 1
    except ImportError as _mcp_v1_err:
        # Distinguish "SDK missing" from "SDK present but neither entry
        # point resolves".  The latter means a future major version moved
        # the class again -- telling the user to reinstall 'mcp[cli]' (as
        # this branch used to) sends them in circles, because the package
        # *is* installed.
        try:
            import importlib.metadata as _md
            MCP_SDK_VERSION = _md.version("mcp")
        except Exception:
            MCP_SDK_VERSION = None
        if MCP_SDK_VERSION is None:
            MCP_SDK_IMPORT_ERROR = (
                "The MCP SDK is not installed. Install it with: "
                "pip install 'mcp[cli]>=2.0'"
            )
        else:
            MCP_SDK_IMPORT_ERROR = (
                f"The MCP SDK is installed (version {MCP_SDK_VERSION}) but neither "
                f"'mcp.server.mcpserver.MCPServer' (v2) nor 'mcp.server.fastmcp.FastMCP' "
                f"(v1) could be imported, so this release is not supported yet. "
                f"Pin a known-good version with: pip install 'mcp[cli]>=2.0,<3.0'. "
                f"(v2 import error: {_mcp_v2_err}; v1 import error: {_mcp_v1_err})"
            )

        class MockSettings: host = "127.0.0.1"; port = 8081; log_level = "INFO"
        class MockMCP:
            def __init__(self, name, description=""): self.name = name; self.description = description; self.app = object(); self.settings = MockSettings(); self._run_called_with_transport = None
            def tool(self): decorator = lambda func: func; return decorator
            def run(self, transport: str = "stdio", **kwargs): raise NotImplementedError(MCP_SDK_IMPORT_ERROR)
        FastMCP = MockMCP  # type: ignore
        class Context:  # type: ignore
            async def info(self, msg): print(f"(mock ctx info): {msg}")
            async def error(self, msg): print(f"(mock ctx error): {msg}")
            async def warning(self, msg): print(f"(mock ctx warning): {msg}")
            async def report_progress(self, current, total): pass

if MCP_SDK_AVAILABLE and MCP_SDK_VERSION is None:
    try:
        import importlib.metadata as _md
        MCP_SDK_VERSION = _md.version("mcp")
    except Exception:
        MCP_SDK_VERSION = None

# --- Angr Integration ---
ANGR_AVAILABLE = False

try:
    import angr  # noqa: F401
    import angr.analyses.decompiler  # noqa: F401
    ANGR_AVAILABLE = True
except (ImportError, AttributeError) as _angr_err:
    # AttributeError: archinfo may reference unicorn constants (e.g.
    # UC_ARCH_RISCV) that don't exist in older unicorn versions.
    # Degrade gracefully rather than crashing the entire server.
    ANGR_AVAILABLE = False

# --- Extended Library Availability Flags ---
LIEF_AVAILABLE = False
try:
    import lief  # noqa: F401
    LIEF_AVAILABLE = True
except ImportError:
    pass

CAPSTONE_AVAILABLE = False
try:
    import capstone  # noqa: F401
    CAPSTONE_AVAILABLE = True
except ImportError:
    pass

KEYSTONE_AVAILABLE = False
try:
    import keystone  # noqa: F401
    KEYSTONE_AVAILABLE = True
except ImportError:
    pass

SPEAKEASY_AVAILABLE = None  # None = not yet checked; will be lazy-checked
SPEAKEASY_IMPORT_ERROR = ""
_SPEAKEASY_VENV_PYTHON = Path("/app/speakeasy-venv/bin/python")
_SPEAKEASY_RUNNER = DATA_DIR / "scripts" / "speakeasy_runner.py"
_speakeasy_check_lock = threading.Lock()

def _check_speakeasy_available():
    """Lazy check for Speakeasy availability. Called on first use."""
    global SPEAKEASY_AVAILABLE, SPEAKEASY_IMPORT_ERROR
    if SPEAKEASY_AVAILABLE is not None:
        return SPEAKEASY_AVAILABLE
    with _speakeasy_check_lock:
        if SPEAKEASY_AVAILABLE is not None:
            return SPEAKEASY_AVAILABLE
        if _SPEAKEASY_VENV_PYTHON.is_file() and _SPEAKEASY_RUNNER.is_file():
            try:
                import subprocess as _sp
                logger.debug("Checking Speakeasy availability...")
                _speakeasy_result = _sp.run(
                    [str(_SPEAKEASY_VENV_PYTHON), "-c", "import speakeasy"],
                    capture_output=True, timeout=10,
                )
                SPEAKEASY_AVAILABLE = _speakeasy_result.returncode == 0
                if not SPEAKEASY_AVAILABLE:
                    SPEAKEASY_IMPORT_ERROR = f"speakeasy import failed in venv: {_speakeasy_result.stderr.decode('utf-8', errors='replace')[:200]}"
            except Exception as _e:
                SPEAKEASY_AVAILABLE = False
                SPEAKEASY_IMPORT_ERROR = f"Speakeasy venv check failed: {_e}"
        else:
            SPEAKEASY_AVAILABLE = False
            SPEAKEASY_IMPORT_ERROR = f"Speakeasy venv not found (expected {_SPEAKEASY_VENV_PYTHON})"
        return SPEAKEASY_AVAILABLE

UNIPACKER_AVAILABLE = None  # None = not yet checked; will be lazy-checked
UNIPACKER_IMPORT_ERROR = ""
_UNIPACKER_VENV_PYTHON = Path("/app/unipacker-venv/bin/python")
_UNIPACKER_RUNNER = DATA_DIR / "scripts" / "unipacker_runner.py"
_unipacker_check_lock = threading.Lock()

def _check_unipacker_available():
    """Lazy check for Unipacker availability. Called on first use."""
    global UNIPACKER_AVAILABLE, UNIPACKER_IMPORT_ERROR
    if UNIPACKER_AVAILABLE is not None:
        return UNIPACKER_AVAILABLE
    with _unipacker_check_lock:
        if UNIPACKER_AVAILABLE is not None:
            return UNIPACKER_AVAILABLE
        if _UNIPACKER_VENV_PYTHON.is_file() and _UNIPACKER_RUNNER.is_file():
            try:
                import subprocess as _sp
                logger.debug("Checking Unipacker availability...")
                _unipacker_result = _sp.run(
                    [str(_UNIPACKER_VENV_PYTHON), "-c", "from unipacker.core import UnpackerClient"],
                    capture_output=True, timeout=10,
                )
                UNIPACKER_AVAILABLE = _unipacker_result.returncode == 0
                if not UNIPACKER_AVAILABLE:
                    UNIPACKER_IMPORT_ERROR = f"unipacker import failed in venv: {_unipacker_result.stderr.decode('utf-8', errors='replace')[:200]}"
            except Exception as _e:
                UNIPACKER_AVAILABLE = False
                UNIPACKER_IMPORT_ERROR = f"Unipacker venv check failed: {_e}"
        else:
            UNIPACKER_AVAILABLE = False
            UNIPACKER_IMPORT_ERROR = f"Unipacker venv not found (expected {_UNIPACKER_VENV_PYTHON})"
        return UNIPACKER_AVAILABLE

QILING_AVAILABLE = None  # None = not yet checked; will be lazy-checked
QILING_IMPORT_ERROR = ""
_QILING_VENV_PYTHON = Path("/app/qiling-venv/bin/python")
_QILING_RUNNER = DATA_DIR / "scripts" / "qiling_runner.py"
_DEBUG_RUNNER = DATA_DIR / "scripts" / "debug_runner.py"
_QILING_EMULATE_RUNNER = DATA_DIR / "scripts" / "qiling_emulate_runner.py"
_SPEAKEASY_EMULATE_RUNNER = DATA_DIR / "scripts" / "speakeasy_emulate_runner.py"
_QILING_DEFAULT_ROOTFS = Path("/app/qiling-rootfs")
_qiling_check_lock = threading.Lock()

def _check_qiling_available():
    """Lazy check for Qiling Framework availability. Called on first use."""
    global QILING_AVAILABLE, QILING_IMPORT_ERROR
    if QILING_AVAILABLE is not None:
        return QILING_AVAILABLE
    with _qiling_check_lock:
        if QILING_AVAILABLE is not None:
            return QILING_AVAILABLE
        if _QILING_VENV_PYTHON.is_file() and _QILING_RUNNER.is_file():
            try:
                import subprocess as _sp
                logger.debug("Checking Qiling availability...")
                _qiling_result = _sp.run(
                    [str(_QILING_VENV_PYTHON), "-c", "from qiling import Qiling"],
                    capture_output=True, timeout=15,
                )
                QILING_AVAILABLE = _qiling_result.returncode == 0
                if not QILING_AVAILABLE:
                    QILING_IMPORT_ERROR = f"qiling import failed in venv: {_qiling_result.stderr.decode('utf-8', errors='replace')[:200]}"
            except Exception as _e:
                QILING_AVAILABLE = False
                QILING_IMPORT_ERROR = f"Qiling venv check failed: {_e}"
        else:
            QILING_AVAILABLE = False
            QILING_IMPORT_ERROR = f"Qiling venv not found (expected {_QILING_VENV_PYTHON})"
        return QILING_AVAILABLE

DOTNETFILE_AVAILABLE = False
try:
    import dotnetfile  # noqa: F401
    DOTNETFILE_AVAILABLE = True
except ImportError:
    pass

# --- .NET Deobfuscation CLI Tools (not Python packages) ---
DE4DOT_AVAILABLE = None  # None = not yet checked; lazy-checked on first use
DE4DOT_IMPORT_ERROR = ""
# de4dot-cex is a .NET Framework app — runs via mono on Linux
_DE4DOT_PATH = Path("/app/dotnet-tools/de4dot/de4dot.exe")
_de4dot_check_lock = threading.Lock()

def _check_de4dot_available():
    """Lazy check for de4dot-cex availability. Called on first use."""
    global DE4DOT_AVAILABLE, DE4DOT_IMPORT_ERROR
    if DE4DOT_AVAILABLE is not None:
        return DE4DOT_AVAILABLE
    with _de4dot_check_lock:
        if DE4DOT_AVAILABLE is not None:
            return DE4DOT_AVAILABLE
        if _DE4DOT_PATH.is_file() and shutil.which("mono"):
            DE4DOT_AVAILABLE = True
        else:
            parts = []
            if not _DE4DOT_PATH.is_file():
                parts.append(f"de4dot.exe not found at {_DE4DOT_PATH}")
            if not shutil.which("mono"):
                parts.append("mono runtime not found on PATH")
            DE4DOT_AVAILABLE = False
            DE4DOT_IMPORT_ERROR = "; ".join(parts) if parts else "de4dot not available"
        return DE4DOT_AVAILABLE

NETREACTORSLAYER_AVAILABLE = None
NETREACTORSLAYER_IMPORT_ERROR = ""
# NRS linux64 is a self-contained .NET 6 binary — no runtime needed
_NETREACTORSLAYER_PATH = Path("/app/dotnet-tools/netreactorslayer/NETReactorSlayer.CLI")
_netreactorslayer_check_lock = threading.Lock()

def _check_netreactorslayer_available():
    """Lazy check for NETReactorSlayer availability. Called on first use."""
    global NETREACTORSLAYER_AVAILABLE, NETREACTORSLAYER_IMPORT_ERROR
    if NETREACTORSLAYER_AVAILABLE is not None:
        return NETREACTORSLAYER_AVAILABLE
    with _netreactorslayer_check_lock:
        if NETREACTORSLAYER_AVAILABLE is not None:
            return NETREACTORSLAYER_AVAILABLE
        if _NETREACTORSLAYER_PATH.is_file() and os.access(str(_NETREACTORSLAYER_PATH), os.X_OK):
            NETREACTORSLAYER_AVAILABLE = True
        else:
            NETREACTORSLAYER_AVAILABLE = False
            NETREACTORSLAYER_IMPORT_ERROR = f"NETReactorSlayer not found (expected {_NETREACTORSLAYER_PATH})"
        return NETREACTORSLAYER_AVAILABLE

ILSPYCMD_AVAILABLE = None
ILSPYCMD_IMPORT_ERROR = ""
_ILSPYCMD_PATH = Path("/app/dotnet-tools/ilspy/ilspycmd")
_ilspycmd_check_lock = threading.Lock()

def _check_ilspycmd_available():
    """Lazy check for ilspycmd (ILSpy CLI) availability. Called on first use."""
    global ILSPYCMD_AVAILABLE, ILSPYCMD_IMPORT_ERROR
    if ILSPYCMD_AVAILABLE is not None:
        return ILSPYCMD_AVAILABLE
    with _ilspycmd_check_lock:
        if ILSPYCMD_AVAILABLE is not None:
            return ILSPYCMD_AVAILABLE
        if _ILSPYCMD_PATH.is_file():
            ILSPYCMD_AVAILABLE = True
        elif shutil.which("ilspycmd"):
            ILSPYCMD_AVAILABLE = True
        else:
            ILSPYCMD_AVAILABLE = False
            ILSPYCMD_IMPORT_ERROR = f"ilspycmd not found (expected {_ILSPYCMD_PATH} or on PATH)"
        return ILSPYCMD_AVAILABLE

PPDEEP_AVAILABLE = False
try:
    import ppdeep  # noqa: F401
    PPDEEP_AVAILABLE = True
except ImportError:
    pass

TLSH_AVAILABLE = False
try:
    import tlsh  # noqa: F401
    TLSH_AVAILABLE = True
except ImportError:
    pass

BINWALK_AVAILABLE = False
BINWALK_CLI_ONLY = False
try:
    import binwalk  # noqa: F401
    if hasattr(binwalk, 'scan'):
        BINWALK_AVAILABLE = True
    else:
        BINWALK_CLI_ONLY = bool(shutil.which("binwalk"))
        BINWALK_AVAILABLE = BINWALK_CLI_ONLY
except Exception:
    BINWALK_CLI_ONLY = bool(shutil.which("binwalk"))
    BINWALK_AVAILABLE = BINWALK_CLI_ONLY

PYGORE_AVAILABLE = False
try:
    import pygore  # noqa: F401
    PYGORE_AVAILABLE = True
except ImportError:
    pass

GORESYM_AVAILABLE = False
_GORESYM_PATH = ""
# Check standard locations for GoReSym binary
for _candidate in [
    shutil.which("GoReSym") or "",
    shutil.which("goresym") or "",
    os.path.expanduser("~/.arkana/tools/GoReSym"),
    os.path.expanduser("~/.arkana/tools/goresym"),
]:
    if _candidate and os.path.isfile(_candidate):
        GORESYM_AVAILABLE = True
        _GORESYM_PATH = _candidate
        break

PYELFTOOLS_AVAILABLE = False
try:
    from elftools.elf.elffile import ELFFile  # noqa: F401
    from elftools.elf.sections import SymbolTableSection  # noqa: F401
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    pass

DNFILE_AVAILABLE = False
try:
    import dnfile  # noqa: F401
    DNFILE_AVAILABLE = True
except ImportError:
    pass

DNCIL_AVAILABLE = False
try:
    from dncil.cil.body import CilMethodBody  # noqa: F401
    from dncil.cil.body.reader import read_method_body_from_bytes  # noqa: F401
    from dncil.cil.error import MethodBodyFormatError as CilError  # noqa: F401
    from dncil.clr.token import Token  # noqa: F401
    DNCIL_AVAILABLE = True
except ImportError:
    pass

RUSTBININFO_AVAILABLE = False
try:
    import rustbininfo  # noqa: F401
    RUSTBININFO_AVAILABLE = True
except ImportError:
    pass

RUST_DEMANGLER_AVAILABLE = False
try:
    import rust_demangler  # noqa: F401
    RUST_DEMANGLER_AVAILABLE = True
except ImportError:
    pass

REFINERY_AVAILABLE = False
try:
    import refinery  # noqa: F401
    REFINERY_AVAILABLE = True
except ImportError:
    pass

OLETOOLS_AVAILABLE = False
try:
    # olevba pulls in XLMMacroDeobfuscator, which prints a "pywin32 is not
    # installed" banner to stdout at import time.
    with _quiet_stdout():
        import oletools.olevba  # noqa: F401
        import oletools.oleid  # noqa: F401
    OLETOOLS_AVAILABLE = True
except ImportError:
    pass

AUTOIT_RIPPER_AVAILABLE = False
try:
    import autoit_ripper  # noqa: F401
    AUTOIT_RIPPER_AVAILABLE = True
except ImportError:
    pass

TRITON_AVAILABLE = False
try:
    from triton import TritonContext  # noqa: F401
    TRITON_AVAILABLE = True
except ImportError:
    pass

PSUTIL_AVAILABLE = False
try:
    import psutil  # noqa: F401
    PSUTIL_AVAILABLE = True
except ImportError:
    pass


def log_library_availability():
    """Log availability of optional libraries. Called once from main()."""
    if MCP_SDK_AVAILABLE:
        logger.info(
            "MCP SDK found (version %s, API v%d).",
            MCP_SDK_VERSION or "unknown", MCP_SDK_MAJOR,
        )
    else:
        logger.warning("MCP SDK unusable. %s", MCP_SDK_IMPORT_ERROR)
    if CAPA_AVAILABLE:
        logger.info("Capa library found.")
    else:
        logger.warning("Capa library (flare-capa) not found. Capability analysis will be skipped. Import error: %s", CAPA_IMPORT_ERROR)
    if SIGNIFY_AVAILABLE:
        logger.info("Signify library found.")
    else:
        logger.warning("Signify library not found. Authenticode validation will be skipped. Import error: %s", SIGNIFY_IMPORT_ERROR)
    if FLOSS_AVAILABLE:
        logger.info("FLOSS library and analysis components found.")
    elif FLOSS_SETUP_OK:
        logger.warning("FLOSS basic setup OK, but analysis components (or vivisect) failed to import. FLOSS analysis will be limited/skipped. Analysis import error: %s", FLOSS_IMPORT_ERROR_ANALYSIS)
    else:
        logger.warning("FLOSS library (flare-floss) not found or basic setup failed. FLOSS analysis will be skipped. Setup import error: %s", FLOSS_IMPORT_ERROR_SETUP)
    if STRINGSIFTER_AVAILABLE:
        logger.info("StringSifter library found. String ranking will be available.")
    else:
        logger.warning("StringSifter library not found. String ranking will be skipped. Import error: %s", STRINGSIFTER_IMPORT_ERROR)
    if RAPIDFUZZ_AVAILABLE:
        logger.info("RapidFuzz library found. Fuzzy string search will be available.")
    else:
        logger.warning("RapidFuzz library not found. Fuzzy search will be skipped. Import error: %s", RAPIDFUZZ_IMPORT_ERROR)
    if ANGR_AVAILABLE:
        logger.info("Angr library found. Advanced binary analysis (Decompilation, Symbolic Execution) enabled.")
    else:
        logger.warning("Angr library not found. Advanced binary analysis tools will be unavailable.")
    if GORESYM_AVAILABLE:
        logger.info("GoReSym binary found at %s. Go binary deep analysis enabled.", _GORESYM_PATH)
    else:
        logger.info("GoReSym binary not found. Go analysis will use pygore or string-scan fallback.")
    if REFINERY_AVAILABLE:
        logger.info("Binary Refinery library found. Data transformation tools enabled.")
    else:
        logger.warning("Binary Refinery (binary-refinery) not found. Refinery-based tools will be unavailable.")
