# Testing Guide

Arkana has two layers of testing: **unit tests** for fast, isolated verification of core modules, and **integration tests** for end-to-end validation of all 308 MCP tools against a running server. A **CI/CD pipeline** via GitHub Actions runs unit tests automatically on every push and pull request. The unit test suite currently includes 3125 passing tests across 20+ files.

---

## Table of Contents

- [Quick Reference](#quick-reference)
- [CI/CD Pipeline](#cicd-pipeline)
- [Unit Tests](#unit-tests)
  - [Running Unit Tests](#running-unit-tests)
  - [Running with Coverage](#running-with-coverage)
  - [Test Modules](#test-modules)
  - [Writing New Unit Tests](#writing-new-unit-tests)
- [Integration Tests](#integration-tests)
  - [Prerequisites](#prerequisites)
  - [Starting the Server](#starting-the-server)
  - [Running Integration Tests](#running-integration-tests)
  - [Running Specific Test Categories](#running-specific-test-categories)
  - [Environment Variables](#environment-variables)
  - [Test Categories](#test-categories)
- [Pytest Configuration](#pytest-configuration)
- [Markers Reference](#markers-reference)
- [Troubleshooting](#troubleshooting)

---

## Quick Reference

```bash
# Run all unit tests (no server needed, ~2 seconds)
pytest tests/ -v

# Run unit tests with coverage report
pytest tests/ -v --cov=arkana --cov-report=term-missing

# Run integration tests (requires running server)
pytest mcp_test_client.py -v

# Run everything
pytest -v
```

---

## CI/CD Pipeline

Arkana uses **GitHub Actions** to run unit tests automatically on every push and pull request to the `main`/`master` branches, and supports manual runs via `workflow_dispatch`. The workflow is defined in `.github/workflows/ci.yml`.

### What CI runs

1. **Unit tests**  - Runs `pytest tests/` with coverage (including branch coverage) on Python 3.10, 3.11, and 3.12.
2. **Coverage enforcement**  - Fails the build if code coverage drops below **65%** (with branch coverage enabled).
3. **Syntax checking**  - Verifies core modules compile without errors.
4. **Dependency updates**  - Dependabot checks for pip dependency updates weekly.

### Running locally (same as CI)

```bash
# Replicate the CI pipeline locally
pip install -r requirements.txt -r requirements-test.txt
pytest tests/ -v --cov=arkana --cov-report=term-missing --cov-config=.coveragerc --cov-fail-under=65
```

---

## Unit Tests

Unit tests live in the `tests/` directory (3125 tests across 20+ files) and test individual functions and classes in isolation. They do **not** require a running MCP server, binary samples, or heavy optional dependencies like Angr, Capa, or FLOSS.

### Running Unit Tests

#### Install test dependencies

```bash
pip install -r requirements-test.txt
```

The core project dependencies are also required:

```bash
pip install pefile networkx "mcp[cli]>=2.0,<3.0"
```

#### Run all unit tests

```bash
pytest tests/ -v
```

#### Run a specific test file

```bash
pytest tests/test_cache.py -v
pytest tests/test_hashing.py -v
```

#### Run a specific test class

```bash
pytest tests/test_state.py::TestBackgroundTasks -v
pytest tests/test_parsers_strings.py::TestExtractStrings -v
```

#### Run a specific test

```bash
pytest tests/test_utils.py::TestShannonEntropy::test_all_256_bytes -v
```

#### Run with short output (dots only)

```bash
pytest tests/
```

### Running with Coverage

Arkana uses `pytest-cov` for code coverage measurement. A **65% minimum** coverage floor (with branch coverage) is enforced in CI.

```bash
# Terminal report with missing lines highlighted
pytest tests/ -v --cov=arkana --cov-report=term-missing --cov-config=.coveragerc

# Generate HTML coverage report
pytest tests/ -v --cov=arkana --cov-report=html --cov-config=.coveragerc
# Open htmlcov/index.html in a browser

# Generate XML report (for CI upload)
pytest tests/ -v --cov=arkana --cov-report=xml --cov-config=.coveragerc

# Fail if coverage drops below threshold
pytest tests/ --cov=arkana --cov-config=.coveragerc --cov-fail-under=65
```

Coverage configuration is in `.coveragerc` (single source of truth):

```ini
[run]
branch = True
omit =
    arkana/mcp/tools_*.py
    arkana/mcp/server.py
    ...

[report]
exclude_lines =
    pragma: no cover
    if TYPE_CHECKING
    raise NotImplementedError
```

### Test Modules

| File | Module Under Test | Tests | What It Covers |
|---|---|---|---|
| `test_utils.py` | `arkana/utils.py` | 13 | `shannon_entropy` (empty, uniform, max entropy, ASCII text), `format_timestamp` (zero, negative, valid, overflow, future dates), `get_symbol_type_str`, `get_symbol_storage_class_str` (COFF symbol constants) |
| `test_hashing.py` | `arkana/hashing.py` | 17 | `SSDeep.hash` (empty, bytes, string, deterministic, invalid types), `SSDeep.compare` (identical, different, invalid format), `_levenshtein` (edit distance), `_strip_sequences` (run-length reduction) |
| `test_mock.py` | `arkana/mock.py` | 13 | `MockPE` class (init, headers, sections, directories, `get_data` with offset/length, `close`, `generate_checksum`, `get_warnings`, empty data) |
| `test_state.py` | `arkana/state.py` | 21 | `AnalyzerState` (init, `touch`), background tasks (set/get/update, eviction of completed tasks, running tasks preserved), path sandboxing (`allowed_paths`, `check_path_allowed`), angr state (set/get/reset), session management (default/new/activate, `StateProxy` delegation) |
| `test_cache.py` | `arkana/cache.py` | 15 | `AnalysisCache` put/get, cache miss, case-insensitive SHA, filepath not persisted, format version invalidation, Arkana version invalidation, LRU eviction, clear, stats, remove by hash, corrupt gzip handling, disabled cache |
| `test_user_config.py` | `arkana/user_config.py` | 14 | `load_user_config` (missing file, valid/invalid JSON, non-dict), `save_user_config` (save/reload, 0o600 permissions), `get_config_value` (from file, env override, missing key), `set_config_value`, `delete_config_value`, `get_masked_config` (sensitive key masking, env override notes) |
| `test_parsers_strings.py` | `arkana/parsers/strings.py` | 23 | `_extract_strings_from_data` (basic, min_length, offsets, empty, trailing, memoryview), `_search_specific_strings_in_data` (present/missing terms, offsets), `_format_hex_dump_lines` (format, address, ASCII, dots, multi-line), `_get_string_category` (IPv4, URL, domain, filepath, registry, email, none), `_decode_single_byte_xor` (known key, empty, random data) |
| `test_mcp_helpers.py` | `arkana/mcp/` helpers | 17 | `_parse_addr` (hex, decimal, invalid, empty, negative, zero), `_raise_on_error_dict` (passthrough, error dict, hint, non-dict, many-key dict), `_check_lib` (available, unavailable, custom pip name), `_check_pe_loaded` (no file, partial load, loaded), `_check_data_key_available` (present, missing, skipped analysis hint) |
| `test_parametrized.py` | Multiple modules | 95+ | Parametrized tests for broader coverage: `shannon_entropy` (6 known values, 5 bounds checks), `format_timestamp` (4 valid, 7 invalid), `get_symbol_storage_class_str` (11 known + 4 unknown), `_get_string_category` (20 categorisation + 3 invalid IPs), `SSDeep` (5 format, 3 determinism), Levenshtein (8 known distances), string extraction (6 min_length variations), hex dump (6 line counts), path sandboxing (7 allow/deny combinations) |
| `test_concurrency.py` | `arkana/state.py` | 5 | Thread isolation (4 threads, barrier sync), concurrent task updates (200 tasks across 4 threads), concurrent angr state set/get consistency, path sandboxing under concurrent load (20 threads), `StateProxy` per-thread delegation (8 threads) |
| `test_format_detect.py` | `arkana/mcp/_format_helpers.py`, `tools_format_detect.py` | 22 | Binary format detection (PE, ELF, Mach-O, ZIP, PDF, GZIP) and language-specific marker comprehensiveness for Go and Rust |
| `test_rust_tools.py` | `arkana/mcp/tools_rust.py` | 7 | Rust binary analysis via string scanning on stripped binaries, including panic handlers, allocators, and version detection |
| `test_streamline.py` | `arkana/mcp/` (multiple) | 25 | Streamlined analysis tools: category maps, container detection, focused imports, strings summary, auto-notes, analysis digest, session phase detection |
| `test_go_tools.py` | `arkana/mcp/tools_go.py` | 14 | Go binary analysis helper functions for safe type conversions (`_safe_str`, `_safe_int`) |
| `test_review_fixes.py` | Multiple modules | 65 | Comprehensive fixes: env var parsing, subprocess handling, regex validation, hook state, dataflow counters, safe dict access, regex timeouts, cache validation, IP filtering |
| `test_triage_helpers.py` | `arkana/mcp/tools_triage.py` | 14 | Triage helper functions for compiler/language detection (Go, Rust, .NET, MSVC, Delphi) and mode normalisation for PE parser output |
| `test_truncation.py` | `arkana/mcp/server.py` | 14 | MCP response size checking and smart truncation logic for large lists, strings, dicts, and deeply nested structures |
| `test_auth.py` | `arkana/auth.py` | 7 | Bearer token authentication middleware for ASGI with constant-time token comparison |
| `test_debug.py` | `arkana/mcp/tools_debug.py` | 76 | Debug session lifecycle (creation, eviction, cleanup, auto-select), execution control (step, step_over, continue, run_until), breakpoints (address, API, conditional, max enforcement), watchpoints (read, write, size validation), inspection (registers, memory hex/disasm, write), snapshots (save, restore, list, diff, max enforcement), error handling (no file, Qiling unavailable, subprocess crash, timeout), session state updates, MCP tool integration (all 20 tools) |
| `test_mcp_sdk_compat.py` | `arkana/imports.py`, `arkana/main.py`, `arkana/state.py` | 34 | MCP SDK v1/v2 compatibility: SDK detection and alias resolution, `_apply_mcp_settings` (v1 host/port vs v2 which dropped them), `_mcp_run_kwargs` per generation, `_mounted_lifespan` forwarding for mounted ASGI apps, and session-key resolution (transport `Mcp-Session-Id` stability across the per-request `ServerSession` v2 creates, non-mapping `ctx.headers`, isolation between distinct sessions) |
| `test_path_allowlist_projects.py` | `arkana/state.py` | 14 | Path allowlist vs project storage: active project's `binaries/`/`artifacts/` reachable, project root and *other* projects denied, unbinding revokes access, scratch projects grant nothing, and symlink-escape rejection (a link planted in `binaries/` resolving outside the allowed set) |
| `test_docker_healthcheck.py` | `scripts/docker_healthcheck.py` | 28 | Container healthcheck: any HTTP status (401/404/…) counts as alive, connection failure is unhealthy only when a listener is expected, transport/port parsing from `/proc/1/cmdline`, and the no-HTTP-surface case (stdio + `--no-dashboard`) |

### Writing New Unit Tests

When adding new unit tests, follow these conventions:

1. **File naming**: `tests/test_<module_name>.py`  - mirrors the source module path.

2. **Class organisation**: Group related tests into classes named `Test<FeatureName>`:

   ```python
   class TestMyFeature:
       def test_basic_case(self):
           ...
       def test_edge_case(self):
           ...
   ```

3. **Use fixtures** for shared setup (especially `tmp_path` for filesystem tests and `monkeypatch` for mocking globals):

   ```python
   @pytest.fixture
   def my_state():
       s = AnalyzerState()
       s.filepath = "/test.exe"
       s.pe_data = {"file_hashes": {"md5": "abc"}}
       return s
   ```

4. **Skip when dependencies are unavailable**:

   ```python
   @pytest.mark.skipif(not HAS_FEATURE, reason="Feature X not available")
   class TestFeatureX:
       ...
   ```

5. **Test isolation**: Each test should be independent. Use `setup_method` or fixtures to reset state  - never rely on test execution order.

6. **Monkeypatch module globals** when testing code that depends on `arkana.config` constants or paths:

   ```python
   def test_something(monkeypatch):
       monkeypatch.setattr("arkana.cache.CACHE_DIR", tmp_path / "cache")
   ```

---

## Integration Tests

The integration test suite (`mcp_test_client.py`) covers all **308 MCP tools** across 19 test categories. Tests connect to a running Arkana server over streamable-http (or SSE) and exercise every tool end-to-end. Tests gracefully skip when a tool is unavailable or a required library is not installed.

### Prerequisites

```bash
pip install -r requirements-test.txt
```

### Starting the Server

The integration tests require a running Arkana server. Start it in a separate terminal:

#### Option A: Local Python

```bash
# Start with a sample file loaded
python arkana.py --mcp-server --mcp-transport streamable-http \
  --samples-path ./samples --input-file samples/test.exe
```

#### Option B: Docker / Podman

```bash
# Using run.sh helper
./run.sh --input-file /samples/test.exe

# Or manually
podman run --rm -it -p 8082:8082 \
  --user "$(id -u):$(id -g)" -e HOME=/app/home \
  -v ./samples:/samples:ro arkana-toolkit \
  --mcp-server --mcp-transport streamable-http --mcp-host 0.0.0.0 \
  --samples-path /samples --input-file /samples/test.exe
```

> **Note**: When running in a container, `--mcp-host 0.0.0.0` is required for the test client to connect from the host.

### Running Integration Tests

```bash
# Run all integration tests
pytest mcp_test_client.py -v

# Run against a different server
ARKANA_TEST_URL=http://192.168.1.10:9000 pytest mcp_test_client.py -v
```

### Running Specific Test Categories

```bash
# Tests that don't require a loaded file (config, cache, deobfuscation, assembly)
pytest mcp_test_client.py -v -m no_file

# Tests that require a loaded PE file
pytest mcp_test_client.py -v -m pe_file

# Angr-powered analysis tests (may be slow)
pytest mcp_test_client.py -v -m angr

# Tests for optional library tools (LIEF, Capstone, Speakeasy, etc.)
pytest mcp_test_client.py -v -m optional_lib

# Run a specific test class
pytest mcp_test_client.py -v -k "TestPEData"          # All 25 get_pe_data keys
pytest mcp_test_client.py -v -k "TestAngrCore"         # Core Angr tools
pytest mcp_test_client.py -v -k "TestMultiFormat"       # ELF/Mach-O/Go/Rust/.NET
pytest mcp_test_client.py -v -k "TestStringAnalysis"    # String analysis tools
pytest mcp_test_client.py -v -k "TestToolDiscovery"     # Verify all 308 tools exist
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ARKANA_TEST_URL` | `http://127.0.0.1:8082` | Server URL to test against |
| `ARKANA_TEST_TRANSPORT` | `auto` | Transport: `auto` (try streamable-http then SSE), `streamable-http`, or `sse` |
| `ARKANA_TEST_SAMPLE` | *(not set)* | Path to a sample file for `open_file` tests |

```bash
# Test against a remote server
ARKANA_TEST_URL=http://192.168.1.10:9000 pytest mcp_test_client.py -v

# Test using SSE transport (legacy)
ARKANA_TEST_TRANSPORT=sse pytest mcp_test_client.py -v
```

### Test Categories

The integration test suite is organised into 19 classes:

| Class | Tools Tested | Marker |
|---|---|---|
| `TestConfigAndUtility` | `get_current_datetime`, `get_config`, `get_extended_capabilities`, `check_task_status` | `no_file` |
| `TestCacheManagement` | `get_cache_stats`, `remove_cached_analysis` | `no_file` |
| `TestFileManagement` | `get_analyzed_file_summary`, `get_full_analysis_results`, `detect_binary_format` | `pe_file` |
| `TestPEData` | `get_pe_data` (all 25 keys + `list` discovery) | `pe_file` |
| `TestPEExtended` | 14 PE extended tools (entropy, crypto, XOR, API hashes, etc.) | `pe_file` |
| `TestStringAnalysis` | 10 string tools (FLOSS, fuzzy search, sifter, context) | `pe_file` |
| `TestDeobfuscation` | `deobfuscate_base64`, `deobfuscate_xor_single_byte`, `is_mostly_printable_ascii`, `get_hex_dump` | mixed |
| `TestCapaAnalysis` | `get_capa_analysis_info`, `get_capa_rule_match_details` | `pe_file`, `optional_lib` |
| `TestTriageAndClassification` | `get_triage_report`, `classify_binary_purpose` | `pe_file` |
| `TestVirusTotal` | `get_virustotal_report_for_loaded_file` | `pe_file` |
| `TestAngrCore` | 13 core Angr tools (decompile, CFG, slicing, loops, etc.) | `pe_file`, `angr` |
| `TestAngrDisasm` | 5 disassembly tools (disassemble, calling conventions, etc.) | `pe_file`, `angr` |
| `TestAngrDataflow` | 5 data flow tools (reaching defs, dependencies, VSA) | `pe_file`, `angr` |
| `TestAngrHooks` | `hook_function`, `list_hooks`, `unhook_function` | `pe_file`, `angr` |
| `TestAngrForensic` | 5 forensic tools (packing, code caves, call graph, etc.) | `pe_file`, `angr` |
| `TestExtendedLibraries` | 9 extended library tools (LIEF, Capstone, Keystone, Speakeasy, etc.) | `optional_lib` |
| `TestQilingEmulation` | 8 Qiling tools (emulation, shellcode, tracing, API hooks, unpacking, memory search, rootfs download) | `optional_lib` |
| `TestMultiFormat` | 8 multi-format tools (ELF, Mach-O, .NET, Go, Rust) | `optional_lib` |
| `TestErrorHandling` | Invalid inputs, nonexistent files, bad addresses | mixed |
| `TestToolDiscovery` | Lists server tools and reports coverage (warns on missing) | `no_file` |

---

## Pytest Configuration

The `pytest.ini` file configures test discovery and markers:

```ini
[pytest]
testpaths = tests
markers =
    no_file: test does not require a loaded file
    pe_file: test requires a loaded PE file
    angr: test uses Angr (may be slow)
    optional_lib: test requires an optional library
    unit: fast unit tests with no external dependencies

```

Coverage configuration lives in `.coveragerc` (not `pytest.ini`). See the "Running with Coverage" section above for details.

The `testpaths = tests` directive means `pytest` (with no arguments) runs unit tests by default. To run integration tests, specify the file explicitly:

```bash
# Unit tests only (default)
pytest -v

# Unit tests with coverage
pytest -v --cov=arkana --cov-report=term-missing

# Integration tests only
pytest mcp_test_client.py -v

# Both
pytest tests/ mcp_test_client.py -v
```

---

## Markers Reference

| Marker | Description | Used In |
|---|---|---|
| `no_file` | Test does not require a loaded file | Integration tests |
| `pe_file` | Test requires a loaded PE file | Integration tests |
| `angr` | Test uses Angr (may be slow, 30s+ per test) | Integration tests |
| `optional_lib` | Test requires an optional library (LIEF, Capstone, etc.) | Integration tests |
| `unit` | Fast unit test with no external dependencies | Unit tests |

Filter by marker with `-m`:

```bash
pytest -m "not angr" -v        # Skip slow Angr tests
pytest -m "no_file" -v         # Only tests that need no file
pytest -m unit -v              # Only unit tests
```

---

## Troubleshooting

### Unit tests fail with `ModuleNotFoundError: No module named 'networkx'`

Install the core dependencies:

```bash
pip install pefile networkx "mcp[cli]>=2.0,<3.0"
```

### Unit tests fail with `pyo3_runtime.PanicException` (cryptography)

The system `cryptography` package may be broken. Install it via pip:

```bash
pip install cffi cryptography
```

### Unit tests show `SKIPPED` for `TestGetSymbolTypeStr`

This is expected when the installed `pefile` version lacks `IMAGE_SYM_DTYPE_*` constants. These tests are automatically skipped and do not indicate a problem.

### Integration tests fail to connect

Ensure the MCP server is running and accessible:

```bash
# Check the server is listening
curl -s http://127.0.0.1:8082/mcp | head

# Start the server if not running
python arkana.py --mcp-server --mcp-transport streamable-http
```

### Integration tests skip most tests

If tests are skipping with messages about missing tools or libraries, the server may be running without all optional dependencies. This is expected behaviour  - install additional libraries on the server to enable more tests.

### Tests fail with `AnalysisCache` errors

Unit tests for the cache use `tmp_path` and `monkeypatch` to redirect cache operations to a temporary directory. If you see unexpected cache errors, ensure no other process is modifying `~/.arkana/cache/` concurrently.
