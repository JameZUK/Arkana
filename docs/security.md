# Security & Testing

Arkana's security model, sandboxing configuration, and testing infrastructure.

---

## Path Sandboxing

When running Arkana in HTTP mode (`--mcp-transport streamable-http`), any MCP client can call `open_file` to read files on the server. Use `--allowed-paths` to restrict access:

```bash
# Only allow access to /samples and /tmp
python arkana.py --mcp-server --mcp-transport streamable-http \
  --allowed-paths /samples /tmp

# Docker with sandboxing (via run.sh  - extra flags are passed through)
./run.sh --allowed-paths /samples

# Equivalent manual docker command
docker run --rm -it -p 8082:8082 \
  --user "$(id -u):$(id -g)" \
  -e HOME=/app/home \
  -v "$(pwd)/samples:/samples:ro" \
  arkana-toolkit \
  --mcp-server --mcp-transport streamable-http --mcp-host 0.0.0.0 \
  --allowed-paths /samples \
  --samples-path /samples
```

If `--allowed-paths` is not set in HTTP mode, Arkana logs a warning at startup.

### Arkana's own project storage

`open_file` adopts every binary into the active project's `binaries/` directory
(`~/.arkana/projects/{id}/binaries/`) and rewrites the internal file path to that
copy. `--allowed-paths` normally points at your samples directory, not at
`~/.arkana`, so the allowlist also accepts two directories belonging to the
**active** project:

| Location | Why |
|---|---|
| `~/.arkana/projects/{active}/binaries/` | Where `open_file` puts the sample; tools that re-read their own loaded file resolve here |
| `~/.arkana/projects/{active}/artifacts/` | Where tool output (unpacked payloads, dumps) is adopted |

Files reach those directories only by Arkana copying an input you already
authorised, so this grants no reach a caller did not already have. The scope is
deliberately tight:

- **Active project only.** The allowlist is per-session state. Permitting the
  whole `projects/` tree would let one session read a binary another session had
  adopted, simply by guessing the path.
- **`binaries/` and `artifacts/` only**  - not the project root. `overlay/` and
  `manifest.json` hold your notes and triage flags rather than sample data, and
  no tool reads them by path.
- **Symlinks cannot tunnel out.** Candidate paths are resolved with `realpath`
  before comparison, so a symlink planted inside `binaries/` is judged by its
  target and rejected if that target sits outside the allowed set.
- **Nothing is granted** when no project is bound, or when the active project is
  an unpromoted in-memory scratch project.

---

## Other Security Measures

- **Non-root Docker**: The `run.sh` helper runs the container as your host UID/GID (`--user "$(id -u):$(id -g)"`), never as root.
- **API key storage**: Keys are stored in `~/.arkana/config.json` with 0o600 (owner-only) permissions.
- **Zip-slip protection**: Archive extraction validates member paths against directory traversal.
- **No hardcoded secrets**: API keys are sourced from environment variables or the config file.
- **CSP**: Dashboard Content-Security-Policy uses `script-src 'self'` (no inline scripts) and restricts `img-src` to `'self'` only (no `data:` URIs). All event handlers use `addEventListener` or event delegation with `data-*` attributes.
- **Dashboard XSS prevention**: All dynamic values in dashboard JS (functions.js, strings.js, callgraph.js) are escaped via `escapeHtml()` before innerHTML insertion — including addresses, names, numeric counts, scores, and complexity values.
- **`Cache-Control: no-store`**: Security middleware injects `Cache-Control: no-store` on all non-static dashboard responses to prevent browser caching of sensitive API data.
- **`fetchJSON()` HTTP error checking**: All dashboard JS files use a shared `fetchJSON()` helper that checks `r.ok` before parsing JSON and throws on HTTP errors, preventing silent consumption of error responses.
- **Diff path traversal prevention**: `get_diff_data()` validates comparison file paths via `os.path.realpath()` with samples directory containment check.
- **Dashboard query bounds**: Code search queries capped at 500 chars; callgraph edges capped at 5,000; URL redirect parameters use `urllib.parse.urlencode()`.
- **Dashboard `asyncio.to_thread()`**: All API endpoints and htmx partials run data functions off the event loop via `asyncio.to_thread()`, with `try/except` fallbacks on partials.

---

## Input Validation & Safety Guards

Arkana applies defence-in-depth input validation across all layers:

- **Search regex safety**: `search` parameters on decompile/disassembly tools validate patterns via `validate_regex_pattern()` — rejects patterns longer than 1,000 chars, nested quantifiers (ReDoS), and invalid syntax. Context lines clamped to `[0, 20]`, matches capped at 500.
- **Emulation limits**: Qiling tools validate `max_instructions` (0–10M) via `_validate_max_instructions()` to prevent CPU/memory exhaustion.
- **Auth header handling**: `BearerAuthMiddleware` lowercases ASGI header keys defensively before matching.
- **Error message sanitisation**: Crypto tool errors truncate user input to 50 chars to prevent information disclosure.
- **Address validation**: Dashboard endpoints reject address parameters longer than 40 characters.
- **Content-Length parsing**: POST endpoints wrap `int(content_length)` in try/except for malformed values.
- **Delay-load imports**: PE parser bounds delay-load thunk iteration at 10,000 to prevent infinite loops on malformed binaries.
- **ThreadPool cap**: PE parser limits `ThreadPoolExecutor` workers to `min(cpu_count, 8)`.
- **IOC regex**: Domain TLD matching tightened to `{2,16}` characters.
- **Cache eviction**: CAPA and YARA rule caches use LRU (OrderedDict) instead of FIFO.
- **ELF symbol parsing**: Per-symbol error handling continues iteration on individual failures.
- **Path validation**: `_get_filepath()` always validates paths via `state.check_path_allowed()`, even when falling back to the default loaded file.
- **Recursion depth guard**: `_make_hashable()` enforces a max depth of 20 to prevent stack overflow on cyclic data structures.
- **Cache size bounds**: `ARKANA_CACHE_MAX_SIZE_MB` env var is clamped to 1–50,000 MB to prevent misconfiguration.
- **File size limit**: `DEFAULT_MAX_FILE_SIZE_MB` (256) caps file loading, overridable via `ARKANA_MAX_FILE_SIZE_MB` env var (parsed safely via `_safe_env_int()`).
- **Systemic limit clamping**: All ~60 tool functions that accept a `limit` parameter clamp it via `max(1, min(limit, MAX_TOOL_LIMIT))` where `MAX_TOOL_LIMIT` is 100,000 (from `arkana.constants`).
- **Decompression bomb protection**: `refinery_decompress` uses streaming chunk iteration with a cumulative byte counter, aborting when output exceeds 100 MB (`_MAX_DECOMPRESS_OUTPUT`). Prevents zip-bomb style attacks.
- **Hex input validation**: All `bytes.fromhex()` call sites validate input length before decoding. `_hex_to_bytes()` in `_refinery_helpers.py` provides friendly error messages for invalid hex. `patch_binary_memory` caps hex input at 2 MB.
- **Refinery pipeline loop limits**: Pipeline iteration loops break when item count reaches the configured `limit`, preventing unbounded output accumulation.
- **IOC IP filtering**: `_is_non_routable_ip()` uses Python's `ipaddress` module to correctly filter CGNAT (100.64.0.0/10), multicast, and other non-routable ranges.
- **Session limits**: `MAX_ACTIVE_SESSIONS` (default 100) caps concurrent HTTP sessions with oldest-session eviction. Overridable via `ARKANA_MAX_SESSIONS` env var.
- **Debug session limits**: `MAX_DEBUG_SESSIONS` (3) caps concurrent debug sessions with oldest-session eviction. `DEBUG_SESSION_TTL` (1800s) auto-cleans idle sessions. `DEBUG_COMMAND_TIMEOUT` (300s) pauses execution commands via `emu_stop()` (session preserved, not killed). `DEBUG_RUNNER_TIMEOUT_BUFFER` (15s) provides a client-side safety net beyond the runner deadline. `MAX_DEBUG_INSTRUCTIONS` (10M) caps execution per continue/run_until. `MAX_DEBUG_MEMORY_READ` (1MB) and `MAX_DEBUG_WATCHPOINT_SIZE` (1MB) cap memory operations. `MAX_DEBUG_BREAKPOINTS` (100) and `MAX_DEBUG_WATCHPOINTS` (50) cap per-session hook counts. `MAX_DEBUG_SNAPSHOTS` (10) caps saved states.
- **Emulation inspect session limits**: `MAX_EMULATION_SESSIONS` (3) caps concurrent emulation inspect sessions with oldest-session eviction. `EMULATION_SESSION_TTL` (1800s) auto-cleans idle sessions. `EMULATION_COMMAND_TIMEOUT` (60s) per-command timeout for memory operations. `EMULATION_RUN_TIMEOUT` (300s) fallback timeout for the initial emulation run; user's `timeout_seconds` takes precedence when larger. `MAX_EMULATION_MEMORY_READ` (1MB) caps memory read per call. `MAX_EMULATION_SEARCH_MATCHES` (100) caps search results. Defense-in-depth timeouts prevent infinite hangs: runner hard timer (`os._exit` at timeout+15s), MCP `threading.Timer` subprocess kill (at timeout+45s), `asyncio.wait_for` (at timeout+30s). `emulation_resume` (Qiling only) allows staged long-running emulation with per-resume timeout enforcement.
- **Cache atomic writes**: `cache.put()` and `update_session_data()` use `tempfile.NamedTemporaryFile()` + `os.replace()` for atomic writes, preventing `.tmp` file collisions and partial writes on crash.
- **Resource entry cap**: PE resource directory traversal is bounded at 1,000 entries (`_MAX_RESOURCE_ENTRIES`).
- **Config atomic writes**: `user_config.py` uses `tempfile.mkstemp()` + `os.replace()` for atomic config file writes.
- **Result cache defensive copy**: `_ToolResultCache.set()` stores a shallow copy of the items list to prevent callers from mutating cached data.

---

## Testing & CI/CD

Arkana has two layers of testing, with automated CI via **GitHub Actions**:

- **Unit tests** (`tests/`)  - 3125 fast tests covering core modules (utils, cache, state, hashing, parsers, MCP helpers), plus parametrised edge-case tests, concurrency tests for session isolation, and ResettableLock/partial CFG tests. No server or binary samples required. Run in ~13 seconds.
- **Integration tests** (`mcp_test_client.py`)  - End-to-end tests for all 308 MCP tools against a running server, organised into 19 test categories with pytest markers.
- **CI/CD** (`.github/workflows/ci.yml`)  - Automated unit tests on Python 3.10/3.11/3.12, coverage enforcement (65% floor with branch coverage), and syntax checking on every push, PR, and manual dispatch. Dependabot monitors pip dependencies weekly.

```bash
# Run unit tests (no server needed)
pytest tests/ -v

# Run unit tests with coverage
pytest tests/ -v --cov=arkana --cov-report=term-missing

# Run integration tests (requires running server)
pytest mcp_test_client.py -v
```

For detailed instructions on running tests, writing new tests, coverage, CI/CD, environment variables, test categories, markers, and troubleshooting, see **[Testing](testing.md)**.
