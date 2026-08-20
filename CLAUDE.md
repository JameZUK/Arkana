# Arkana Development Guide

## What is Arkana?

Arkana is a Model Context Protocol (MCP) server exposing 308 binary analysis tools to AI clients. It supports PE, ELF, and Mach-O formats with integrations for angr, capa, FLOSS, YARA, Binary Refinery, Qiling, Speakeasy, oletools, and GoReSym.

## Project Structure

```
arkana/                  # Main package
├── main.py             # Entry point, arg parsing, server startup
├── state.py            # Thread-safe AnalyzerState + StateProxy (per-session isolation)
├── config.py           # Central re-export hub (constants, imports, state, cache)
├── constants.py        # Pure constants (response limits, timeouts, URLs)
├── imports.py          # Optional library imports with *_AVAILABLE flags
├── cache.py            # Gzip-compressed LRU disk cache (~/.arkana/cache/)
├── auth.py             # Bearer token ASGI middleware
├── integrity.py        # Pre-parse file integrity checks (PE/ELF/Mach-O)
├── utils.py            # ReDoS-safe regex, safe_slice, safe_env_int
├── tool_registry.py    # Tool module groups and startup registration
├── parsers/            # PE/FLOSS/capa/YARA/strings parsers
├── dashboard/          # Web dashboard (Starlette + htmx + Jinja2)
│   ├── app.py          # ASGI app factory, routes, auth, SSE events
│   ├── state_api.py    # Data extraction layer (reads AnalyzerState for dashboard views)
│   ├── __init__.py     # Package init
│   ├── templates/      # Jinja2 templates (overview, functions, callgraph, sections, strings, timeline, notes)
│   │   └── partials/   # htmx partials (_global_status, _overview_stats, _task_list, _timeline_entry)
│   └── static/         # CSS (CRT theme), JS (htmx, Cytoscape.js, strings.js), logo
├── resource_monitor.py  # Process-level RSS/CPU monitoring (psutil daemon thread)
    └── mcp/                # MCP tool modules (308 tools across 67 files)
    ├── server.py       # MCP server instance, tool_decorator, response truncation
    ├── _*.py           # Private helpers (angr, input, format, progress, refinery, rename, search)
    └── tools_*.py      # Tool modules grouped by domain
tests/                  # Unit tests (pytest)
tests/integration/      # Integration tests (requires running server)
.claude/skills/         # Claude Code analysis and learning skills
```

## Running Tests

```bash
# Unit tests (no server needed, ~2 seconds)
python -m pytest tests/ -v

# Unit tests with coverage
python -m pytest tests/ -v --cov=arkana --cov-config=.coveragerc

# Integration tests (requires running server)
./run.sh  # Start server in one terminal
python -m pytest tests/integration/mcp_test_client.py -v  # In another
```

Coverage configuration lives in `.coveragerc` (single source of truth). MCP tool modules are excluded from unit test coverage — they are tested via integration tests.

## Lint

```bash
ruff check arkana/ tests/ \
  --select=E9,F63,F7,F82,F841,W291,W292,W293,B006,B007,B018,UP031,UP032,RUF005,RUF010,RUF019,G010
```

## Key Patterns

- **File integrity checks**: `arkana/integrity.py` validates binaries pre-parse using only `struct`. `open_file` runs this automatically. The `force` parameter overrides smart fallback. `open_file`/`close_file` **block when background tasks are active** — they return an error with `active_tasks` and `hint` suggesting `abort_background_task()` or `force_switch=True`. When `open_file` is called on a new file without `close_file()`, it clears all module-level caches to prevent cross-file data contamination. `open_file` PE analysis uses soft/overtime timeouts (task ID `"pe-analysis"`): `PE_ANALYSIS_SOFT_TIMEOUT` (300s) → `TASK_OVERTIME` with stall detection → `PE_ANALYSIS_MAX_RUNTIME` (3600s) ceiling. Set `ARKANA_PE_ANALYSIS_SOFT_TIMEOUT=0` for old hard-timeout behavior.
- **MCP SDK version**: Arkana supports SDK **v1 and v2**; `mcp[cli]>=2.0,<3.0` is the pinned target. v2.0 removed `mcp.server.fastmcp` outright — `FastMCP` became `mcp.server.mcpserver.MCPServer` with no deprecation shim, so an unbounded pin broke builds on release day (issue #118). `arkana/imports.py` tries v2 then v1 and exports `MCP_SDK_MAJOR` / `MCP_SDK_VERSION` / `MCP_SDK_IMPORT_ERROR`; the alias is still called `FastMCP` internally so the rest of the codebase is version-agnostic. When neither entry point resolves, the error names the installed version instead of telling the user to install a package they already have. The one real API divergence is `settings`: v1 carried `host`/`port` there, v2 moved them to the app-factory/runner kwargs — `main._apply_mcp_settings()` assigns only fields the settings model declares, and `main._mcp_run_kwargs()` passes host/port to `run()` on v2 only. Client-side, v2 renamed `isError`→`is_error`, `structuredContent`→`structured_content` and made the streamable-http transport yield a 2-tuple; `tests/integration/mcp_test_client.py` handles both shapes.
- **MCP session identity**: `get_session_key_from_context()` in `state.py` resolves, in order: (1) `Mcp-Session-Id` from `ctx.headers`, (2) a UUID stamped on the `ServerSession` object, (3) `"default"`. The ordering exists because **SDK v2 builds a fresh `ServerSession` per request** — stamping it hands every tool call a new `AnalyzerState`, so `open_file()` succeeds and the next call reports "No file is currently loaded" (hit on both stdio and HTTP). Behaviour matrix (`ctx.headers` / session object): v1 stdio `str`/stable, v1 HTTP `None`/stable, v2 stdio `None`/per-request, v2 HTTP mapping/per-request. Only v2 HTTP has a stable transport id and only v1 has a stable object, hence all three tiers. `headers` access is guarded — it is a plain `str` on v1 stdio, so `.get()` is called only when callable. Step 2 is gated on `_SESSION_OBJECT_PER_REQUEST`, probed by a local `import mcp.server.mcpserver` rather than importing `arkana.imports`, keeping `state.py` off the heavy optional-dependency graph. Tier 3 is correct for v2 stdio (single session). Concurrent-client isolation is covered by tests — regressing it silently merges every HTTP client's state.
- **Mounted-app lifespan**: In HTTP mode `main.py` mounts the MCP app and the dashboard under one wrapper `Starlette`. Starlette dispatches lifespan events to the **top-level app only**, and the MCP SDK starts its session manager's anyio task group in that lifespan — so mounting it without forwarding startup made every MCP request fail with `RuntimeError: Task group is not initialized. Make sure to use run().` (affected v1 and v2 alike, whenever the dashboard was enabled — i.e. the default). `_mounted_lifespan(*apps)` forwards each mounted app's `router.lifespan_context` via an `AsyncExitStack`. Note `BearerAuthMiddleware` wraps the MCP app into a plain ASGI callable, so `main.py` keeps an unwrapped handle (`mcp_starlette`) for the lifespan lookup.
- **Optional deps**: Every library is guarded by `*_AVAILABLE` flags in `imports.py`. Tools return actionable error messages when a dep is missing — never crash.
- **PE object guard**: `_check_pe_object(tool_name, require_headers=False)` in `server.py` validates `state.pe_object` is not `None` before tools access it. Use `require_headers=True` for tools needing `OPTIONAL_HEADER`/`FILE_HEADER` (rejects ELF/Mach-O/shellcode). Call after `_check_pe_loaded()`.
- **Thread safety**: All shared state uses locks. `StateProxy` + `contextvars` isolates HTTP sessions. `_cached_*` fields on `AnalyzerState` rely on CPython's GIL for atomic reference replacement (never mutated in place after assignment).
- **Session limits**: `MAX_ACTIVE_SESSIONS` (default 100, env: `ARKANA_MAX_SESSIONS`). Per-session caps: `MAX_NOTES` (10K), `MAX_TOOL_HISTORY` (500), `MAX_ARTIFACTS` (1K), `MAX_RENAMES` (10K), `MAX_COMPLETED_TASKS` (50).
- **Response truncation**: Dual-limit — soft char limit (8K default) plus hard byte limit (64KB). `tool_decorator` auto-enforces even for tools that don't call `_check_mcp_response_size`. Set `ARKANA_MCP_RESPONSE_LIMIT_CHARS=65536` for non-Claude-Code clients.
- **Pagination**: Two patterns: (1) **Response-level** (`_paginated_response`) for large-output tools using `line_offset`/`line_limit`, cached via `_ToolResultCache`. (2) **Field-level** (`_paginate_field`) for dict tools with multiple list fields, adding `{field}_pagination` metadata. Pagination params listed in `_SKIP` so they don't affect cache keys.
- **Search/grep in decompilation**: `decompile_function_with_angr`, `batch_decompile`, `get_annotated_disassembly` accept `search` (regex), `context_lines`, `case_sensitive`. Search is a view/filter on cached results. `_search_helpers.py` validates via `validate_regex_pattern()` for ReDoS safety.
- **`tool_decorator`**: Wraps every MCP tool — handles session activation, heartbeat, history recording, error enrichment, and sets `_current_tool_var` contextvar for warning attribution.
- **Brief descriptions**: `--brief-descriptions` CLI flag / `ARKANA_BRIEF_DESCRIPTIONS=1` env var. Extracts the `---compact:` shorthand line from each tool's docstring, replacing the full description in the MCP tool listing. Reduces listing size by ~90%. Grammar: `---compact: <action> [| <details>] [| needs: <prereqs>]`. Every `@tool_decorator` function **must** include a `---compact:` line — enforced by `tests/test_compact_descriptions.py`. Applied at registration time via `_extract_brief_description()` in `server.py`.
- **Skill structure**: Skills in `.claude/skills/` follow Anthropic's progressive disclosure pattern. **SKILL.md must stay under 500 lines** — it loads into context on every invocation. Reference material (tool selection tables, vocabulary guides, decision matrices, search patterns) goes in separate `.md` files in the same directory, loaded on demand when Claude needs them. When adding content to a skill, ask: "Is this workflow (keep in SKILL.md) or reference (extract to a separate file)?" Current structure: `arkana-analyze/SKILL.md` (~125 lines) + 2 reference files; `arkana-learn/SKILL.md` (~115 lines) + 2 reference files.
- **Warning capture**: `arkana/warning_handler.py` captures WARNING+ from library loggers into `state.analysis_warnings`, deduplicated, attributed via `_current_tool_var`/`_current_task_var`. Session-scoped (not persisted to cache).
- **Resource monitor**: `arkana/resource_monitor.py` — psutil daemon thread. Alerts injected into `_collect_background_alerts()`. Returns `None` when psutil unavailable.
- **Null-region detection**: `_is_null_region_artifact()` filters null-byte regions (angr interprets as `add [rax], al`) from `get_function_map` and enrichment. `release_angr_memory` drops angr project/CFG, calls `gc.collect()` + `malloc_trim(0)`, preserves PE data/notes/session.
- **Background task timeout**: 14 background tools use progress-adaptive timeouts via `_run_background_task_wrapper`. Soft timeout → `TASK_OVERTIME` → stall-kill/ceiling. `_background_alerts` injected into every tool response. `cancel_all_background_tasks()` called by `open_file`/`close_file`. Generation guard prevents stale threads from writing results after file switches. Set soft timeout to 0 for old single hard-timeout behavior.
- **Decompile lock**: `ResettableLock` in `state.py` — a `threading.Lock` replacement with `force_reset()`. On file switch, `cancel_all_background_tasks()` calls `force_reset()` to release the lock even if a thread is stuck in angr's uninterruptible C Decompiler call. Uses thread-ID-to-generation mapping so stale threads' `release()` becomes a no-op. `_last_force_reset` timestamp powers transient `_background_alerts` for MCP client visibility. Enrichment decompile sweep caps functions at `MAX_ENRICHMENT_BLOCKS` (300, env: `ARKANA_MAX_ENRICHMENT_BLOCKS`) to avoid long uninterruptible decompiles.
- **Partial CFG acceptance**: When CFG build stalls, times out, accumulates too many errors, or crashes after discovering functions, `_accept_partial_cfg()` in `background.py` stores a `_PartialCFG` wrapper backed by the live `project.kb.functions`. Tools see it as a normal CFG — `.functions`, `.model`, `.functions.callgraph` all work. `_cfg_stall_monitor` tracks both function discovery rate AND error accumulation. Four acceptance triggers: (1) stall-kill with ≥`CFG_PARTIAL_MIN_FUNCS` (100) discovered, (2) max-runtime exceeded with enough funcs, (3) high error rate (`CFG_ERROR_RATE_THRESHOLD`=50, env: `ARKANA_CFG_ERROR_RATE_THRESHOLD`) with stalled progress, (4) exception during/after CFG build with enough funcs in `project.kb` (`_try_salvage_partial`). Quality metadata stored in `state._cfg_quality` and surfaced via `_background_alerts`. Functions discovered after acceptance appear automatically (live KB reference).
- **Emulation debugger**: 29 tools in `tools_debug.py`, persistent Qiling subprocess (`scripts/debug_runner.py`), JSONL IPC. Three stub layers: CRT (~47 APIs), I/O (console), API trace hooks. All use `hook_address()` per IAT entry. `debug_stub_api` supports `set_last_error` for anti-emulation bypass. **Trace query language**: `debug_get_api_trace` supports structured `query` predicates (`api=VirtualAlloc,args.p3=0x40`), operators `=`, `!=`, `~`, `>`, `<`, `>=`, `<=`, and ordered `sequence` matching (`VirtualAlloc;WriteProcessMemory;CreateRemoteThread`). Query parser in `scripts/trace_query.py` (no external deps, runs in Qiling venv subprocess). **Snapshot attribution**: `debug_snapshot_diff(attribute_changes=True)` correlates memory changes with API calls between snapshots — categorises allocations, writes, I/O reads, and protection changes. `trace_seq` stored in snapshots for temporal correlation.
- **Emulation inspect sessions**: 8 tools in `tools_emulate_inspect.py` for post-emulation memory inspection. Keep subprocess alive after `run()` for memory search/read without re-emulation. `emulation_resume` continues execution from current CPU state for staged long-running operations (e.g. UPX decompression). Defense-in-depth timeouts: runner hard timer (`os._exit`), MCP `threading.Timer` backup, `asyncio.wait_for`. User's `timeout_seconds` properly propagated to all layers.
- **BSim function similarity**: `_bsim_features.py` — architecture-independent matching. SQLite DB at `~/.arkana/bsim/signatures.db`. Two-phase query: SQL pre-filter then full scoring. TF-IDF confidence scoring distinguishes meaningful matches from trivial ones. `triage_binary_similarity` compares whole binary against DB. Auto-indexes during enrichment (`ARKANA_BSIM_AUTO_INDEX=1` default). `seed_signature_db` indexes library files tagged `source='library'`. `transfer_annotations` copies renames from matched functions. `validate_signature_db` runs diagnostics. Schema: `binaries` table has `source` (user/library) and `library_name` columns. **Rename sync**: `_sync_renames_to_bsim()` in `tools_rename.py` mirrors user function renames into the BSim DB via `sync_all_renames()` so `transfer_annotations` can carry them to variants. (Renames themselves are persisted via project overlays, not the cache.) **Limitations**: BSim detects code sharing between variants and binary-level library usage, but does NOT reliably identify individual function names from dynamically-linked system DLLs. Use FLIRT (`identify_library_functions`) for that. 8 feature groups: cfg_structural (0.15), api_calls (0.20), vex_profile (0.10), string_refs (0.15), constants (0.10), size_metrics (0.05), block_hashes (0.15), call_context (0.10). `ANGR_PSEUDO_APIS` filtered from all API comparisons.
- **Notes system**: Categories: `general`, `function`, `tool_result`, `ioc`, `hypothesis`, `conclusion`, `manual`. Hypothesis notes support `confidence`, `hypothesis_status`, `evidence` list, `superseded_by`. `update_hypothesis` MCP tool manages lifecycle.
- **Sandbox report ingestion**: `tools_sandbox.py` — 3 tools parsing CAPE/Cuckoo/ANY.RUN/Hybrid Analysis/Joe Sandbox JSON into unified schema on `state._sandbox_report`. Cleared on file switch.
- **CTI report generator**: `generate_cti_report` aggregates all cached analysis into markdown or JSON. Optional `output_path` saves to file.
- **Ghidra/IDA export**: `export_ghidra_script`/`export_ida_script` generate Python scripts from renames, types, notes, triage status.
- **VBA/XLM macro analysis**: `tools_macro.py` — 3 tools. Requires `oletools`. Works on Office docs directly without `open_file`.
- **VM protection detection**: `detect_vm_protection` characterizes VMProtect/Themida/etc via 6 heuristics. Does NOT require angr.
- **Decompilation digest**: `batch_decompile(digest=True)` — ~17x token compression via structured behavioral summaries. `_build_function_digest()` extracts API calls, strings, 12 behavioral patterns, complexity metrics.
- **Rename/annotation layer**: `apply_variable_renames_to_lines()` uses single-pass combined regex to prevent cascading substitutions. `batch_rename` uses two-pass validate-then-apply for atomicity.
- **Custom types**: Structs reuse `_parse_fields`. Cycle detection prevents recursive references. Persisted via cache.
- **Decompiler cffi fallback**: `_safe_decompile()` retries with `cfg=None` on pickle errors. Returns `(result, used_fallback)` tuple. All 4 Decompiler call sites use this helper.
- **Extended enrichment pipeline**: After IOC collection, runs 5 additional phases (family ID, API hash scan, C2 indicators, DGA detection, crypto constants). All cached and persisted via `_save_enrichment_cache()`.
- **Incremental enrichment saves**: Saves at 3 points: after Phase 2g, every 60s during decompile sweep, and async after on-demand decompiles (throttled 30s).
- **Decompile meta cache**: `_decompile_meta` — `OrderedDict` with LRU eviction (cap 2000). Dashboard functions build keys using `_get_state()._state_uuid` directly (not `_make_decompile_key()`) since dashboard threads lack MCP session contextvar.
- **`_ToolResultCache` GC safety**: `_ToolResultCache` uses a `WeakSet` for instance tracking. Fixed: `weakref.finalize` removed from `_ToolResultCache.__init__` — periodic `sweep_all_expired()` handles recount instead. The finalizer caused single-thread deadlocks on Python 3.10 when GC fired during `_commit_removals` while `_global_lock` was held.
- **Code coverage import**: `tools_coverage.py` — 2 tools (`import_coverage_data`, `get_coverage_summary`). Parses DynamoRIO drcov binary format, Frida/Lighthouse JSON, and CSV coverage. Overlays on function map via angr CFG. Stored on `state._cached_coverage`.
- **Anti-VM bypass hooks**: `_anti_vm_hooks.py` + `scripts/_anti_vm_hooks_qiling.py` — CPUID hypervisor bit spoofing, RDTSC timing normalisation, VMware I/O port masking. Enabled via `anti_vm_bypass=True` on `emulate_binary_with_qiling` and `debug_start`. Based on IEEE paper techniques (Lee et al., 2021). Trigger capped at 10K.
- **VM protection option identification**: `detect_vm_protection` enhanced with protector-specific option detection (Themida: anti_debug/api_wrapping/vm_code/string_encryption; VMProtect: virtualization/mutation/import_protection; Enigma: anti_vm/virtualization), import obfuscation scoring (0.0–1.0), and protector-specific analysis recommendations. Based on UnThemida research.
- **Frida DBI script generation**: `generate_frida_stalker_script` — 4 script types: Stalker coverage (drcov/JSON), anti-VM bypass (registry/firmware/process/MAC hooks), injection detector (VirtualAllocEx→WriteProcessMemory→CreateRemoteThread sequence monitoring), API logger (structured JSON with arg resolution from FRIDA_API_SIGNATURES).
- **Trace analysis & MBA detection**: `tools_trace_analysis.py` — 2 tools. `analyze_instruction_trace` parses PIN/CSV/JSON traces with optional Triton symbolic analysis (`TRITON_AVAILABLE`). `detect_mba_obfuscation` scans decompiled pseudocode for 9 MBA pattern types (XOR-via-NOT-AND-OR, algebraic identities, tautologies, double negation). Pure-Python fallback when Triton unavailable.

## Input Validation & Safety Guards

- **Emulation limits**: Qiling validates `max_instructions` (0–10M). Inspect sessions: max 3, 30-min TTL, user-specified run timeout (default 60s, propagated to all timeout layers), 1MB max read, 100 max search matches. Resume supported (Qiling only) for staged long-running emulation.
- **Debug session limits**: Max 3 sessions, 1MB max read, 100 max breakpoints, 50 max watchpoints, 10 max snapshots, 10K max trace entries. User stubs: 200 max, validated names.
- **Security**: Auth lowercases ASGI headers. Error messages truncate input to 50 chars. Dashboard validates address length (≤40), escapes all dynamic values (`escapeHtml()`). Path validation via `state.check_path_allowed()`.
- **Path allowlist vs project storage**: `check_path_allowed()` accepts `--allowed-paths` **plus** the *active* project's `binaries_dir` and `artifacts_dir` (via `_active_project_storage_dirs()`). Needed because `open_file()` adopts every binary into `~/.arkana/projects/{id}/binaries/` and rewrites `state.filepath` to that copy — so `_get_filepath()` (19 call sites) validates the in-project path, which no user would think to pass to `--allowed-paths`. Without it, any tool re-reading its own loaded file fails with "Access denied" in HTTP mode, where `--allowed-paths` is mandatory; cached-data tools are unaffected, which is why it stayed hidden. Deliberately scoped to the **active** project only — allowing the whole projects tree would let one session read another session's adopted binary by guessing the path, turning per-session allowlist state into a shared read channel. The project *root* stays excluded (`overlay/`, `manifest.json` hold notes, not sample data). Candidates are `realpath`'d before comparison, so a symlink planted in `binaries/` resolves to its target and is rejected. Covered by `tests/test_path_allowlist_projects.py`.
- **Resource bounds**: Delay-load imports capped at 10K. ThreadPool capped at `min(cpu_count, 8)`. PE resources capped at 1K. IOC TLD regex `{2,16}`. Cache size clamped 1–50000 MB. File size limit 256MB (env: `ARKANA_MAX_FILE_SIZE_MB`). Enrichment decompile sweep skips functions with >`MAX_ENRICHMENT_BLOCKS` (300) basic blocks.
- **Safety**: Decompression bomb protection (100MB limit). Hex input validated before `fromhex()`. Refinery pipeline loops break at `limit`. Cache uses atomic writes (`tempfile` + `os.replace()`). Search regex validated for ReDoS. `_make_hashable()` enforces depth 20. `_ToolResultCache.set()` stores shallow copies.
- **Systemic limit clamping**: All ~60 tools accepting `limit` clamp via `max(1, min(limit, MAX_TOOL_LIMIT))` where `MAX_TOOL_LIMIT` = 100K.

## Dashboard

Port 8082, auto-starts. Access URL logged at startup with token query parameter.

Pages: **Projects** (card grid + importable archives panel), Overview, Functions (sortable, triage, XREF panel, code search, symbol tree), Call Graph (Cytoscape.js, dagre), Sections (entropy heatmap), Imports, Hex View (infinite scroll, restores hex_offset from project), Strings (FLOSS detail, sifter scores), CAPA, MITRE, Types (struct/enum editor), Similarity (BSim triage + BinDiff, DB management), Timeline, Notes, **Artifacts** (sortable table with bulk actions, expand-row for details, 10s polling).

Global status bar shows active tool + background tasks, 3s htmx refresh, collapses when idle. Triage flags persisted to cache. Active project shown in nav as `▶ {project_name} / {active_binary}` when bound.

**CSP**: `script-src 'self'`, no inline scripts. Event delegation with `data-*` attributes. `fetchJSON()` shared helper. `Cache-Control: no-store` on non-static responses. Dedicated thread pool (`_dash_to_thread()`, 4 threads, env: `ARKANA_DASHBOARD_THREADS`). Diff path validation includes samples directory containment. Callgraph capped at 5K edges. Code search capped at 500 chars. Responsive nav overflow. Functions scroll preservation on enrichment reloads. Persisted dashboard state (last_tab, hex_offset, last_function_address) saved into the active project's manifest via `saveDashboardState()` JS helper.

## Projects

A "project" is a named multi-binary investigation container backed by `~/.arkana/projects/{project_id}/`. Sits *on top* of the SHA256 cache:

- **Cache** (`~/.arkana/cache/`) — derived analysis only (PE headers, triage heuristics, IOCs, MITRE mapping, enrichment results). Read-only; regeneratable from the binary.
- **Project overlay** (`~/.arkana/projects/{id}/overlay/{sha256}.json.gz`) — user-mutable state per binary: notes, artifacts, renames, custom types, triage flags, coverage, sandbox reports. Two projects can contain the same binary with independent overlays.

**Layout**:
```
~/.arkana/projects/
├── index.json                 # {project_id: {name, last_opened, primary_sha256, ...}}
└── {project_id}/              # uuid4().hex[:16]
    ├── manifest.json          # name, members, primary, tags, dashboard_state, last_active_sha
    ├── binaries/              # copies of member binaries (hardlinked when same FS)
    ├── artifacts/             # adopted artifact files + directory bundles
    └── overlay/{sha256}.json.gz  # per-binary user state
```

**Active project lives on `state.active_project`** — `Project` (real, on-disk) or `ScratchProject` (in-memory, promoted on first state mutation). Per-session isolation comes for free via `StateProxy`. `state.bind_project()` / `state.unbind_project()` / `state.flush_overlay()` are the binding API.

**Lazy promotion**: `open_file()` always creates a project context. If the binary's sha256 is a member of any existing project (most-recently-opened wins on multi-match), bind to it. Otherwise create a `ScratchProject` (in-memory, no disk presence). On the first state mutation (`add_note`, `register_artifact`, `rename_function`, `set_triage_status`, `create_struct/enum`), `state._maybe_promote_scratch()` calls `project_manager.promote_scratch()` which:
1. Allocates a project ID and creates `~/.arkana/projects/{id}/`.
2. Calls `_build_sample_slug()` (extracted from `auto_name_sample`) for a descriptive name like `stealer_packed_persistence_a3f9c211`. Falls back to `{filename_stem}_{sha8}` when enrichment hasn't run.
3. Copies the binary into `binaries/`, writes the manifest, flushes the current overlay.

**MCP tools**: `tools_projects.py` (11 tools — list, create, open, current, rename, tag, delete, add_binary, remove_binary, set_primary, close), `tools_artifacts.py` (3 tools — list, update_metadata, delete). Both registered in `CORE_MODULES` in `tool_registry.py`.

**Artifact storage**: every `_write_output_and_register_artifact` call adopts the file into the active project's `artifacts/` dir (hardlink when same filesystem, copy otherwise). The artifact's `path` is rewritten to the in-project location; `original_path` is retained for traceability. `_register_artifact_directory()` does the same for directory bundles (depth-capped, no symlinks, member/size-limit-enforced). Used by `tools_dotnet_deobfuscate`, `tools_refinery_extract`, `tools_refinery_dotnet`, `tools_payload`.

**Cache wrapper format v2 (V1 retired)**: `CACHE_FORMAT_VERSION = 2`. `cache.get()` rejects any wrapper that isn't v2 — there is **no** v1 read fallback. v2 wrappers contain only derived analysis (pe_data + cache_meta); user-mutable state (notes/artifacts/renames/types/triage_status/coverage/sandbox) lives exclusively in project overlays, persisted via `Project.save_overlay()` and the background `_overlay_flush_loop` daemon. The retired helpers `cache.update_session_data()`, `cache.get_session_metadata()`, and `cache.insert_raw_entry()` have all been removed. `_sync_renames_to_bsim()` in `tools_rename.py` is a thin BSim sync helper (no cache write). **Legacy v1 → v2 migration** runs once at `ProjectManager.__init__` when no projects exist — reads each v1 wrapper directly via gzip, extracts user state into a project (tagged `migrated`) with a stub member, re-writes the wrapper as v2. Idempotent. Per-entry try/except — never crashes startup. **Archives**: `export_project` and `import_project` MCP tools, plus the dashboard's `import_archive_data`, only handle v2 project archives — v1 single-binary session exports were retired with the format split.

**Background overlay flush**: `_overlay_flush_loop` in `state.py` is a daemon thread (started lazily by `get_or_create_session_state`) that wakes every `OVERLAY_FLUSH_INTERVAL_SECONDS` (30s) and calls `flush_overlay()` on every session state with `_overlay_dirty=True`. Without this loop, mutations only persisted on `close_file`/`close_project`, so a SIGKILL between mutations and close lost work.

**Project archive (v2) safety**: `_import_project_v2` in `tools_export.py` enforces strict containment via `Path.resolve() + relative_to(new_root_resolved)` — defends against `..`-based path-traversal that simple `normpath` checks miss. Per-file size cap `_MAX_V2_MEMBER_BYTES` (1 GB), total cap `_MAX_V2_ARCHIVE_BYTES` (4 GB), member-count cap `_MAX_V2_ARCHIVE_MEMBERS` (50k). Symlinks/hardlinks/devices/fifos rejected outright. Failed extraction triggers `shutil.rmtree(new_root)` for clean rollback. All caps tunable via `ARKANA_MAX_PROJECT_ARCHIVE_*` env vars.

**Dashboard project member resolution**: `_locate_binary_for_stub` in `dashboard/app.py` walks `state.allowed_paths` + `state.samples_path` + `ARKANA_EXPORT_DIR`/`ARKANA_HOST_EXPORT`/`ARKANA_OUTPUT` env vars to find a binary by sha256 when a project member's `copy_path` is missing (migrated stubs). Untrusted env-var roots must be inside the path allowlist AND have ≥4 path components (rejects `/`, `/etc`, `/etc/foo`). Bounds: `_LOCATE_MAX_HASH=8`, `_LOCATE_MAX_WALK=20000`, `_LOCATE_MAX_FILE_BYTES=512MB`. Filename matches prioritised, then non-name candidates as fallback for renames. **Result cache**: `_locate_cache` (256-entry LRU, 5min TTL) re-hashes the cached path on every hit so a file replaced (not deleted) at the cached path is detected and evicted. Used by `api_projects_open` to materialise stubs via `Project.adopt_binary_into_stub` instead of returning 409.

**Dashboard project list payload split**: `_project_card_summary` (no member breakdown) for `GET /api/projects` (list view), `_project_card_detail` (full member list with batched `member_present` under one lock acquisition) for `GET /api/projects/detail` (expand view). Halves the list-payload size and avoids N×M lock acquisitions per dashboard poll.

**`PROJECT_NAME_RE` is ASCII-only** (`[A-Za-z0-9_\-. ]{1,100}`) — unicode `\w` previously allowed RTL-overrides and confusables that enabled visual spoofing across `find_by_name` dedup.

**Public `Project.snapshot_members*` helpers**: `Project.snapshot_members()`, `Project.snapshot_members_with_presence()`, and `Project.register_stub_member()` are the public API for the dashboard layer to read/write project members. The dashboard MUST NOT reach into `project._lock` or `project.manifest.members` directly. `register_stub_member` enforces that `member.copy_path` resolves inside the project's `binaries_dir` so a future caller can't land an external path in the manifest.

**Project comparison endpoint bounds** (`get_project_comparison_data` + `compare_indexed_binaries`): hard pair-grid cap `MAX_PROJECT_COMPARE_PAIRS=500`, overall wallclock budget `PROJECT_COMPARE_TIME_BUDGET_S=120s`, per-pair wallclock `BSIM_COMPARE_TIME_BUDGET_S=30s`, per-pair candidate cap `BSIM_COMPARE_MAX_CANDIDATES=200`, per-side function cap `BSIM_COMPARE_MAX_FUNCS_PER_SIDE=50000` (refused outright above this), block-count tolerance `max(BSIM_COMPARE_BLOCK_TOLERANCE=5, ceil(blocks * BSIM_COMPARE_BLOCK_TOLERANCE_PCT=0.10))` so big functions still match. Inner candidate loop checks the deadline every `BSIM_COMPARE_INNER_DEADLINE_CHECK=32` candidates. Side A is streamed via the sqlite cursor (not pre-materialised) to avoid 100MB+ memory spikes at the 50K ceiling. Pair-grid comparisons share a single sqlite connection across all pairs; `is_binaries_indexed_batch` does one `IN(...)` query for all members instead of N round-trips.

**`compare_indexed_binaries` jaccard math**: `shared = min(matched_a_count, matched_b_count)` where `matched_b_count` is a set count of distinct B addresses chosen. The naive `len(pair_scores)` overcounts when many A functions collapse onto the same B function, producing jaccard > 1.0. Always returns `matched_a_count` and `matched_b_count` so callers can surface asymmetric collapses (e.g. "20 A funcs collapsed onto 1 B func"). Centred bucket iteration (`fa_blocks` first, then ±1, ±2, …) ensures the candidate cap retains the closest-block matches.

**Project membership cache**: `_project_membership_for_shas` builds a full `{sha256: [{id, name}, ...]}` reverse-index ONCE and caches it for `_PROJECT_MEMBERSHIP_TTL_S=10s`. Invalidated by mtime on `~/.arkana/projects/index.json` so create/rename/delete flushes the cache the next call. Concurrent rebuilds are coordinated via a `Condition` variable so two dashboard polls can't both walk the projects index. Triage cache enrichment happens AFTER cache fetch (`_enrich_triage_with_projects`) — never baked into the cached payload — so a project rename during the TTL window is reflected immediately.

**Bulk artifact batch helpers**: `AnalyzerState.delete_artifacts_batch(ids)` and `AnalyzerState.update_artifacts_metadata_batch(ids, ...)` do single-pass O(L+N) work under one `_artifacts_lock` acquisition each. The dashboard's `bulk_delete_artifacts` / `bulk_tag_artifacts` route through these instead of looping per-id, which previously was O(L*N).

**`_build_directory_tarball` TOCTOU defence**: opens the source dir with `O_RDONLY|O_DIRECTORY|O_NOFOLLOW`, then walks via `os.fwalk(dir_fd=dir_fd, follow_symlinks=False)`. Once the fd is held, all subsequent `os.open(name, dir_fd=walk_dir_fd, ...)` calls are anchored to that inode regardless of what happens to the path on disk. Defends against both leaf-symlink-swap and parent-symlink-swap attacks. Inner symlinked files/dirs are skipped silently.

**Exit watchdogs**: both the `finally:` watchdog and the SIGTERM handler use a 15-second `os._exit` ceiling (was 5s for SIGTERM). Lower bound let the final overlay flush get killed mid-write on heavily-loaded disks. The 15s budget is generous enough for the largest realistic overlay (a few MB gzipped) while still keeping `docker stop` responsive.

## Docker

**Healthcheck**: `scripts/docker_healthcheck.py` (wired via `HEALTHCHECK`). Any HTTP response counts as alive — `/mcp` is behind bearer auth and HTTP transport **always** has a key (auto-generated when `--api-key` is omitted), so an unauthenticated probe gets 401; in stdio mode the dashboard owns the port and has no `/mcp` route, so it gets 404. The previous inline `urlopen()` treated both as failures, leaving every container permanently `unhealthy`. Configurations that serve no HTTP at all (stdio + `--no-dashboard`, or `ARKANA_DASHBOARD_PORT=0`) report healthy rather than flapping red; a connection failure when a listener *is* expected still reports unhealthy. Port and transport are read from `/proc/1/cmdline` so a non-default `--mcp-port` is probed correctly.

```bash
./run.sh --stdio          # stdio mode (for Claude Code)
./run.sh                  # HTTP mode (port 8082)
./run.sh --samples ~/dir  # Mount samples directory
./run.sh --brief-descriptions  # Short tool descriptions (~60% smaller listing)
```

4 venvs isolate incompatible unicorn versions (angr v2, Speakeasy/Unipacker/Qiling v1). .NET tools via subprocess (de4dot-cex/mono, NETReactorSlayer, ilspycmd/dotnet). SIGTERM handler and the normal `finally:` cleanup both include a 15s watchdog (`os._exit`) to force shutdown if `asyncio.run()`'s executor join hangs on a stuck angr thread or the final overlay flush takes longer than expected on a heavily-loaded disk.

## Known Tool Limitations

These are inherent limitations from underlying frameworks, not bugs:

- **`get_data_dependencies`**: Returns raw angr internals. Prefer `get_reaching_definitions` or `propagate_constants`.
- **`get_backward_slice`/`get_forward_slice`**: CFG reachability, not true data-flow slices.
- **`extract_function_constants`**: Includes code addresses alongside data constants.
- **Qiling emulation**: Requires manual rootfs setup. `qiling_setup_check()` verifies.
- **Debug sessions**: Fidelity limited by Qiling/Unicorn. **Register writes don't redirect execution** — use code patching instead. **Unresolved MSVCRT imports** need IAT patching. **Threading unsupported** — stub and redirect. **Timeout pauses, not kills** — session preserved for inspection. `DEBUG_COMMAND_TIMEOUT` (300s, env: `ARKANA_DEBUG_COMMAND_TIMEOUT`).
- **`auto_unpack_pe`**: FSG may fail. Use `qiling_dump_unpacked_binary()` as fallback.
- **`qiling_dump_unpacked_binary`**: `smart_unpack` hooks VirtualAlloc to track allocations, scans for PE headers. Falls back to largest-region heuristic.
- **`get_virustotal_report_for_loaded_file`**: Requires API key via `set_api_key(key_name="vt_api_key", key_value="...")`.
- **`analyze_batch`**: 8KB soft limit can truncate. Use 5-10 files max.
- **`search_decompiled_code`**: Searches pseudocode, not assembly. Use `get_annotated_disassembly(search=...)` for assembly.
- **DFS symbolic execution**: angr DFS triggers cffi pickle errors. `solve_constraints_for_path` uses BFS by default. `find_path_to_address` has `use_dfs` param.
- **`reconstruct_pe_from_dump`**: LIEF Builder API varies between versions. Auto-detects signature.
- **`get_value_set_analysis`**: Known angr compatibility issues. Prefer `get_reaching_definitions`.
- **`detect_compression_headers`**: May false-positive on code sections.
- **`save_patched_binary`**: `bytes_patched` includes loader differences, not just user patches.
- **`go_analyze`**: GoReSym→pygore→gopclntab→string_scan fallback. GoReSym needs PATH or `~/.arkana/tools/`. gopclntab parser (`arkana/parsers/go_pclntab.py`) is pure-Python, supports Go 1.2–1.26+, extracts function names/addresses from stripped binaries. **Type descriptor parsing**: `arkana/parsers/go_types.py` parses typelink/itab sections to extract struct field layouts, interface method sets, and itab dispatch tables (Go 1.7–1.26+). Integrated into gopclntab fallback path. **Go ABI annotations**: `_go_abi.py` detects Go binaries and annotates call instructions in `get_annotated_disassembly` with register/stack parameter mappings (Go 1.17+ register ABI on AMD64/ARM64, stack ABI on x86/pre-1.17). Go version cached on state (`_cached_go_version`, `_cached_go_abi_detected`).
- **`detect_null_regions`**: May flag legitimate null-initialized data sections.
- **`release_angr_memory`**: After release, angr tools rebuild from disk.
- **Anti-VM bypass vs VM protection**: `anti_vm_bypass=True` defeats VM *detection* (CPUID/RDTSC/registry checks) but NOT code *virtualization* (custom bytecode interpreters). VM-protected binaries have 4 layers: (1) anti-VM detection → bypassed by hooks, (2) unpacking/decryption → partially handled by Qiling, (3) code virtualization → NOT addressed (unsolved research problem), (4) original code. For VM-protected samples, use `detect_vm_protection` + `generate_frida_stalker_script` to generate scripts for real Windows execution, then import results back via `import_coverage_data`/`analyze_instruction_trace`.
- **Speakeasy allocation tracking**: `emulate_pe_with_windows_apis(track_allocations=True)` for VirtualAlloc/Protect anomaly detection.

## CI

GitHub Actions runs on every push/PR: unit tests (Python 3.10-3.12), ruff lint, smoke tests. Coverage floor 65% with branch coverage. CI timeout 10 minutes. Dependabot weekly pip updates.
