# Arkana Tool Reference

Complete catalog of all 308 MCP tools organized by use case.
Source files: `arkana/mcp/tools_*.py`

> **Address format:** All address/offset parameters accept both hex (`0x401000`) and decimal (`4198400`). Hex strings with a `0x` prefix are auto-detected via `int(x, 0)`.

---

## Tool Selection: Prefer / Avoid

| Instead of... | Prefer... | Why |
|---|---|---|
| `get_full_analysis_results()` | `get_pe_data(key='...')` | Full dump exceeds 8K char soft limit; targeted queries are faster |
| `extract_strings_from_binary()` | `get_strings_summary()` | Raw dumps are noisy; summary categorizes by type (URLs, IPs, paths) |
| `get_pe_data(key='imports')` for security | `get_focused_imports()` | Focused imports categorizes by threat behavior |
| `get_function_map(limit=100)` | `get_function_map(limit=15)` | Too many functions overwhelms context; start small, expand if needed |
| Ignoring `has_more` in pagination | Check `_pagination` / `{field}_pagination` dicts | Many tools paginate lists — `has_more: true` means data was dropped; request more with offset/limit |
| Calling `get_analysis_digest()` repeatedly | Call at phase transitions | Digest has overhead; use it strategically |
| `get_notes()` to check findings | `get_analysis_digest()` | Digest aggregates notes with triage data and coverage |
| `get_hex_dump()` + `refinery_xor(data_hex=...)` | `refinery_xor(file_offset=..., length=...)` | Single step; avoids hex-encoding large blobs |
| Extracting payload without `output_path` | `refinery_xor/pipeline/carve(..., output_path=...)` | Saves to disk AND registers as artifact with hashes and type detection |
| Writing a Python crypto script (RC4, XOR, AES) | `refinery_pipeline` / `refinery_decrypt` | Internal tools are logged, reproducible, auditable |
| Repeated single-item tool calls (e.g., 50× `get_string_at_va`) | Batch parameters (`data_hex_list`, `virtual_addresses`, `function_addresses`, `rule_ids`) | Single call, cleaner history, per-item error isolation |
| Calling `decompile_function_with_angr` many times | `batch_decompile(addresses)` | Decompile up to 20 in one call; per-function caching and 60s timeout |
| Paginating through full decompilation to find a pattern | `decompile_function_with_angr(address, search="pattern")` | Regex grep returns only matching lines with context — saves tokens |
| Decompiling many functions looking for a pattern | `batch_decompile(addresses, search="pattern")` | Grep across up to 20 functions; only functions with matches are returned |
| `get_hex_dump()` + manual byte matching | `search_hex_pattern(pattern)` | Direct hex pattern search with `??` wildcards, section filter support |
| Manually checking each function for buffer overflows | `find_dangerous_data_flows()` | Automated source->sink tracing with RDA; covers all functions at once |
| Checking taint flows across multiple function calls | `trace_taint_flows()` | Inter-procedural taint tracking through entire call graph with 3-phase validation |
| Calling `decompile_function_with_angr` + `get_function_xrefs` + `get_strings_for_function` + `get_notes` + triage check separately | `get_analysis_context_for_function(address)` | Single-call aggregator returns decompilation, xrefs, strings, notes, complexity, and triage status; use individual tools only for deeper data (full paginated decompilation, CFG, data flow) |

---

## Loading & Sample Management

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `open_file` | Loading any binary for analysis. Returns `file_integrity` assessment. Unknown formats auto-fallback to raw mode. Blocks when background tasks active — use `force_switch=True` to override. | `file_path`, `mode`, `force` (override format fallback), `force_switch` (override active task block) |
| `close_file` | Done with current file, loading another. Blocks when background tasks active — use `force_switch=True` to override. | `force_switch` (override active task block) |
| `check_file_integrity` | Pre-parse validation of a binary — detects truncation, null-padding, header corruption. Can run before or after `open_file`. Does not modify state. | `file_path` (optional — defaults to loaded file) |
| `reanalyze_loaded_pe_file` | Need fresh analysis after patching | — |
| `list_samples` | Browsing available samples in /samples | — |
| `detect_binary_format` | File type unknown, need magic byte detection | — |

## Environment & Configuration

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_config` | **First call** — discover libraries, paths, container mode | — |
| `get_current_datetime` | Need timestamp for notes or reports | — |
| `check_task_status` | Checking background task progress/completion. Returns `elapsed_seconds`/`elapsed_human`, `stall_detection` (triggers after 60s without progress), and `timed_out`/`partial_result` for tasks that exceeded their timeout | `task_id` |
| `set_api_key` | Configuring VT or other API keys | `key_name`, `key_value` |

## Triage & Risk Assessment

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_triage_report` | **Second call** — comprehensive automated triage | `compact=True`, `indicator_limit` (default 50), `indicator_offset` (default 0) |
| `classify_binary_purpose` | Determine binary type (GUI, DLL, driver, service) | — |
| `get_virustotal_report_for_loaded_file` | Check community reputation | — |
| `get_analyzed_file_summary` | Quick summary without full triage | — |
| `get_capa_analysis_info` | CAPA capability analysis overview | — |
| `get_capa_rule_match_details` | Detailed match info for a specific capa rule | `rule_name` |
| `get_extended_capabilities` | Extended capability detection beyond capa | — |

## PE Structure

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_pe_data` | Specific PE field needed | `key`: imports, exports, sections, tls_info, digital_signature, yara_matches, header, debug, resources, relocations, rich_header |
| `get_focused_imports` | Security-relevant imports only | `category` (optional filter) |
| `get_full_analysis_results` | Complete PE analysis dump | — |
| `get_section_permissions` | Check section R/W/X flags | — |
| `get_pe_metadata` | Extended metadata (timestamps, linker, compiler) | — |
| `get_load_config_details` | Load config directory (SEH, CFG, guard) | — |
| `extract_resources` | Extract PE resource data | `resource_type` (optional) |
| `extract_manifest` | Extract embedded manifest XML | — |
| `get_import_hash_analysis` | Imphash, section hash analysis | — |
| `parse_binary_with_lief` | Cross-format PE/ELF/Mach-O parsing via LIEF. **Use as fallback** when pefile fails (timeout, crash, corrupt headers). LIEF handles malformed binaries that pefile cannot. | — |
| `modify_pe_section` | Modify section content for patching | `section_name`, `data` |

## Multi-Format Analysis

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `elf_analyze` | Analyzing ELF binaries | — |
| `elf_dwarf_info` | Extracting DWARF debug symbols from ELF | — |
| `macho_analyze` | Analyzing Mach-O binaries | — |
| `dotnet_analyze` | .NET assembly analysis (dnfile + dotnetfile fallback) | — |
| `dotnet_disassemble_method` | Disassemble specific .NET CIL method by RVA (from `dotnet_analyze` method_definitions) | `method_rva` |
| `vb6_analyze` | VB6 binary analysis: project metadata, forms/modules, Declare Function externals, security-relevant API flagging. Use when MSVBVM60/50.DLL in imports. | `limit` |
| `go_analyze` | Go binary analysis (packages, version, type descriptors). Parses typelink/itab for struct fields, interface methods, itab dispatch tables (Go 1.7–1.26+). Fallback chain: GoReSym→pygore→gopclntab→string-scan. Use `elf_analyze()` for full symbols when all fail | `file_path`, `limit` |
| `rust_analyze` | Rust binary metadata | — |
| `rust_demangle_symbols` | Demangle Rust symbol names | — |

## String Analysis

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_strings_summary` | Categorized string overview (URLs, IPs, paths) | — |
| `extract_strings_from_binary` | Raw string extraction | `min_length`, `encoding` |
| `extract_wide_strings` | Unicode/wide string extraction | — |
| `search_for_specific_strings` | Search for known string patterns | `patterns` |
| `fuzzy_search_strings` | Approximate string matching | `query`, `threshold` |
| `get_top_sifted_strings` | ML-ranked strings by relevance (StringSifter) | `limit` |
| `get_strings_for_function` | Strings referenced by a specific function | `address` |
| `get_string_usage_context` | Disassembly context around a string reference | `string_value` |
| `get_string_at_va` | Read string at specific virtual address or file offset | `address`, `address_type` (`va` or `file_offset`) |
| `get_floss_analysis_info` | FLOSS decoded/stacked strings | — |
| `search_floss_strings` | Regex search against FLOSS results | `pattern` |
| `search_yara_custom` | Custom YARA rule scanning | `rule` |
| `detect_format_strings` | Find printf-style format strings (vuln audit) | — |
| `search_hex_pattern` | Search binary for hex byte patterns with `??` wildcards | `pattern`, `section` (optional), `limit` (default 50) |

## Decompilation & Disassembly

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `decompile_function_with_angr` | Get C-like pseudocode for a function (paginated); works without full CFG; applies user renames; supports regex grep via `search`. If the response includes a `note` field mentioning "cffi pickle incompatibility", the decompiler fell back to a reduced-quality path — cross-references and type propagation may be limited; verify critical logic against `get_annotated_disassembly()` | `address`, `line_offset` (default 0), `line_limit` (default 80), `search` (optional regex), `context_lines` (default 2), `case_sensitive` (default False) |
| `batch_decompile` | Decompile up to 20 functions in one call; per-function 60s timeout; applies renames; `search` filters to matching functions only. Per-function `note` field indicates if cffi fallback was used | `addresses`, `max_lines_per_function` (default 30), `summary_mode`, `search` (optional regex), `context_lines` (default 2), `case_sensitive` (default False) |
| `get_angr_partial_functions` | List functions discovered so far (works during/after CFG build) | `limit` (default 50) |
| `get_annotated_disassembly` | Disassembly with variable names and xrefs; supports regex grep via `search`. Auto-annotates Go binary call sites with ABI parameter/return mappings (register ABI Go 1.17+, stack ABI pre-1.17) | `address`, `limit` (default 50), `search` (optional regex), `context_lines` (default 2), `case_sensitive` (default False) |
| `disassemble_at_address` | Raw disassembly at arbitrary address; works without full CFG | `address`, `count` |
| `disassemble_raw_bytes` | Disassemble arbitrary byte sequences | `bytes`, `arch` |
| `get_function_map` | List functions ranked by interestingness | `offset` (default 0), `limit` (default 30) |
| `get_function_complexity_list` | Functions sorted by cyclomatic complexity | — |
| `get_function_cfg` | Control flow graph for a function | `address`, `node_limit` (default 50), `edge_limit` (default 100) |
| `get_function_xrefs` | Cross-references (callers + callees) | `address` |
| `get_cross_reference_map` | Batch cross-reference lookup | `function_addresses` |
| `get_function_variables` | Stack and register variables (VEX IR temporaries filtered) | `address` |
| `get_calling_conventions` | Recovered calling conventions and params | `address` |
| `identify_library_functions` | Identify standard library functions | — |
| `extract_function_constants` | Constant values used in a function | `address` |
| `get_global_data_refs` | Global data references across binary | — |
| `scan_for_indirect_jumps` | Find indirect jumps/calls (filters constant targets and returns, classifies flow_type) | — |
| `identify_cpp_classes` | C++ class structure identification (background, timeout 300s) | `method_limit` (default 20) |
| `get_call_graph` | Inter-procedural call graph from a function | `address`, `limit` (default 20) |

**Search workflow**: Use `search` to test hypotheses before committing to full output.
`batch_decompile` with `search` scans up to 20 functions and returns only those with
matches — ideal for triage sweeps. `get_annotated_disassembly` with `search` finds
specific instructions (e.g., `search="rdtsc|cpuid"` for anti-debug). Default
`context_lines=2`; increase to 5-8 for crypto loops or switch/case handlers. See
[search-patterns.md](search-patterns.md) for the full pattern catalog.

## Data Flow Analysis

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_reaching_definitions` | Track where variable values come from (background, timeout 300s) | `address` |
| `get_data_dependencies` | Def-use chains within a function (background, timeout 300s) | `address` |
| `get_control_dependencies` | Which conditions control which blocks | `address` |
| `propagate_constants` | Resolve constant values through computation | `address` |
| `get_value_set_analysis` | Pointer target tracking (background, timeout 600s) | `address` |
| `get_backward_slice` | Trace data origin backward from a point | `address`, `variable` |
| `get_forward_slice` | Trace data propagation forward | `address`, `variable` |
| `get_dominators` | Dominator tree for CFG analysis (diagnostic note when empty) | `address` |
| `analyze_binary_loops` | Loop detection and analysis (background, timeout 300s) | — |
| `find_dangerous_data_flows` | Trace untrusted input→dangerous sink flows within single functions. Use for vuln audit after `get_function_map`. High-confidence RDA + structural fallback. | `function_address` (optional — scan all if omitted), `limit` (default 30) |
| `trace_taint_flows` | Inter-procedural taint analysis — trace data from source APIs (recv, read, getenv, etc.) to sink APIs (strcpy, system, send, etc.) across function call-chain boundaries. 3-phase: structural BFS, decompile validation, optional RDA. Auto-reverses when target is a sink. | `source_category` (network/file/user_input/environment/registry/all), `sink_category` (memory/execution/format/exfiltration/all), `max_depth` (1-20), `validate`, `deep_validate`, `target_function` |

## Emulation

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `emulate_function_execution` | Execute a single function with concrete args (background, timeout 300s, partial results on timeout: steps/stdout) | `address`, `args` |
| `emulate_binary_with_qiling` | Full binary emulation with API tracking | `timeout`, `rootfs`, `trace_syscalls`, `syscall_filter`, `track_memory`, `anti_vm_bypass` |
| `emulate_shellcode_with_qiling` | Shellcode emulation (x86/x64/ARM/MIPS) | `shellcode`, `arch` |
| `qiling_trace_execution` | Detailed API call tracing during emulation | — |
| `qiling_hook_api_calls` | Hook specific APIs in Qiling emulation | `api_names` |
| `qiling_dump_unpacked_binary` | Dump unpacked binary from emulation memory | — |
| `qiling_resolve_api_hashes` | Resolve API hash constants to names | — |
| `qiling_memory_search` | Search emulation memory for patterns/strings | `pattern` |
| `qiling_setup_check` | Verify Qiling rootfs setup | — |
| `emulate_pe_with_windows_apis` | PE emulation with Windows API sim (Speakeasy) | — |
| `emulate_shellcode_with_speakeasy` | Shellcode with Speakeasy | `shellcode`, `arch` |
| `emulate_with_watchpoints` | Emulation with memory/register breakpoints (timeout 300s, partial results on timeout: captured events) | `address`, `watchpoints` |
| `emulate_and_inspect` | Emulate binary/shellcode and keep session alive for post-emulation memory inspection. Supports both Qiling and Speakeasy engines. Returns behavioral report + session_id | `engine` (qiling/speakeasy), `file_path`, `shellcode_hex`, `architecture`, `timeout_seconds` |
| `emulation_resume` | Resume emulation from current CPU state (Qiling only). For staged long-running operations: run 300s → check memory → resume 300s → repeat. Speakeasy does not support resume | `timeout_seconds`, `max_instructions`, `session_id` |
| `emulation_read_memory` | Read memory from a completed emulation session (max 1MB). `format="disasm"` adds Capstone disassembly | `address`, `length`, `format`, `session_id` |
| `emulation_write_memory` | Write bytes to emulated memory for patching | `address`, `hex_bytes`, `session_id` |
| `emulation_search_memory` | Search emulated memory for string (UTF-8+UTF-16LE) or hex patterns | `search_patterns`, `search_hex`, `context_bytes`, `limit`, `session_id` |
| `emulation_memory_map` | Get full memory map of the emulated process (regions, permissions, labels) | `session_id` |
| `emulation_session_status` | List all active emulation inspect sessions | — |
| `close_emulation_session` | Close an emulation session and release resources | `session_id` |
| `debug_start` | Start interactive debug session — persistent Qiling subprocess, pauses at entry. `stub_crt` (default True) installs ~47 CRT stubs, `stub_io` (default True) installs console stubs, `anti_vm_bypass` (default False) enables anti-VM hooks | `rootfs_path`, `stub_crt`, `stub_io`, `anti_vm_bypass` |
| `debug_stop` | Stop and destroy a debug session | `session_id` |
| `debug_status` | Check session liveness and current state | `session_id` |
| `debug_step` | Step N instructions (default 1) | `count`, `session_id` |
| `debug_step_over` | Step over CALL (temp BP after call) | `session_id` |
| `debug_continue` | Continue until BP/WP hit, max instructions, or timeout. **Timeout pauses (not kills)** — session stays alive for memory inspection and can be resumed with another `debug_continue` | `max_instructions`, `session_id` |
| `debug_run_until` | Run until specific address reached. Same timeout-pause behavior as `debug_continue` | `address`, `max_instructions`, `session_id` |
| `debug_set_breakpoint` | Set address/API/conditional breakpoint | `address`, `api_name`, `conditions`, `session_id` |
| `debug_remove_breakpoint` | Remove breakpoint by ID | `breakpoint_id`, `session_id` |
| `debug_set_watchpoint` | Set memory read/write watchpoint | `address`, `size`, `watch_type`, `session_id` |
| `debug_remove_watchpoint` | Remove watchpoint by ID | `watchpoint_id`, `session_id` |
| `debug_list_breakpoints` | List all breakpoints and watchpoints | `session_id` |
| `debug_read_state` | Full state: registers, flags, PC, stack, next 5 insns, memory map | `session_id` |
| `debug_read_memory` | Read N bytes at address (hex + optional disasm, max 1MB) | `address`, `length`, `format`, `session_id` |
| `debug_write_memory` | Write bytes to memory | `address`, `hex_bytes`, `session_id` |
| `debug_write_register` | Set register value (arch-validated) | `register`, `value`, `session_id` |
| `debug_snapshot_save` | Save full emulation state with metadata | `name`, `note`, `session_id` |
| `debug_snapshot_restore` | Restore saved snapshot | `snapshot_id`, `session_id` |
| `debug_snapshot_list` | List snapshots with metadata | `session_id` |
| `debug_snapshot_diff` | Compare two snapshots (registers + memory regions). `attribute_changes=True` correlates memory changes with API calls between snapshots (allocations, writes, I/O, protection changes) | `snapshot_id_a`, `snapshot_id_b`, `attribute_changes` (default False), `session_id` |
| `debug_set_input` | Queue input for stubbed ReadConsole (stdin/cin/scanf) | `data`, `encoding` (utf-8/hex), `session_id` |
| `debug_get_output` | Retrieve captured console output (WriteConsoleA/W → printf/cout/puts) | `clear`, `offset`, `limit`, `session_id` |
| `debug_get_api_trace` | Get paginated API call trace log (all Windows API calls with args/retval). Supports structured `query` predicates (`api=VirtualAlloc,args.p3=0x40`; operators: `=`,`!=`,`~`,`>`,`<`,`>=`,`<=`) and ordered `sequence` matching (`VirtualAlloc;WriteProcessMemory;CreateRemoteThread`) | `offset`, `limit`, `filter`, `query`, `sequence`, `gap_max`, `session_id` |
| `debug_clear_api_trace` | Clear API trace buffer | `session_id` |
| `debug_set_trace_filter` | Configure API trace whitelist or enable/disable tracing | `apis` (comma-sep), `enabled`, `session_id` |
| `debug_search_memory` | Search all mapped memory for string (UTF-8+UTF-16LE) or hex patterns with ?? wildcards | `pattern`, `pattern_type`, `max_matches`, `context_bytes`, `region_filter`, `session_id` |
| `debug_stub_api` | Create custom API stub at runtime (set return value, write to output pointers) | `api_name`, `return_value`, `num_params`, `writes` (JSON), `session_id` |
| `debug_list_stubs` | List all installed stubs: builtin I/O (8), builtin CRT (~47), user-defined | `session_id` |
| `debug_remove_stub` | Remove a user-defined API stub (builtin stubs cannot be removed) | `api_name`, `session_id` |
| `import_coverage_data` | Import drcov/JSON/CSV coverage data and overlay on function map | `file_path`, `format` (auto/drcov/json/csv) |
| `get_coverage_summary` | Summarise imported coverage: percent, uncovered/covered functions | `show_uncovered`, `show_covered` |
| `analyze_instruction_trace` | Import PIN/CSV/JSON instruction traces; optional Triton symbolic analysis | `trace_path`, `format` (auto/pin/csv/json) |
| `detect_mba_obfuscation` | Scan decompiled code for MBA obfuscation patterns (XOR-via-NOT-AND, identities) | `function_address` |
| `generate_frida_stalker_script` | Generate Frida DBI scripts: coverage, anti-VM bypass, injection detector, API logger | `script_type`, `target_module`, `apis`, `output_format`, `output_path` |
| `find_path_to_address` | Symbolic execution to find reaching inputs (timeout 600s, partial results on timeout: steps/active states) | `target_address` |
| `find_path_with_custom_input` | Path finding with custom constraints (timeout 600s, partial results on timeout: steps/active states) | `target`, `constraints` |
| `explore_symbolic_states` | BFS/DFS symbolic exploration towards target addresses, avoiding others. **OOM risk**: keep `max_active` ≤ 10 and `max_steps` ≤ 10000 for complex binaries — angr clones entire state objects per branch, and hash-heavy or CRT-heavy code causes exponential memory growth that can OOM-kill the container | `find_addresses`, `avoid_addresses`, `strategy`, `max_steps`, `max_active`, `timeout_seconds` |
| `solve_constraints_for_path` | Solve for concrete stdin/argv/register values that reach a target. Supports `start_address` to skip CRT init. Same OOM caveats as `explore_symbolic_states` — use `max_steps` ≤ 10000 | `target_address`, `start_address`, `avoid_addresses`, `max_steps`, `timeout_seconds` |

## Cryptography

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `identify_crypto_algorithm` | Detect crypto constants and algorithm signatures | — |
| `auto_extract_crypto_keys` | Automatically extract embedded crypto keys | — |
| `brute_force_simple_crypto` | Brute-force simple ciphers (XOR, Caesar, SUB) | `data`, `method` |
| `detect_crypto_constants` | Scan for known crypto S-boxes and constants | — |

## Deobfuscation

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `find_and_decode_encoded_strings` | Decode Base64/hex/XOR obfuscated strings | — |
| `deobfuscate_base64` | Decode hex-encoded Base64 data | `data_hex` |
| `deobfuscate_xor_single_byte` | Single-byte XOR decryption | `data`, `key` |
| `deobfuscate_xor_multi_byte` | Multi-byte XOR decryption | `data`, `key` |
| `brute_force_simple_crypto` | Brute-force XOR/RC4/ADD/SUB/ROL/ROR with known-plaintext support | `data_hex`, `known_plaintext` |
| `is_mostly_printable_ascii` | Check if data is mostly printable | `data` |
| `get_hex_dump` | Hex dump of a binary region | `offset`, `length` |

## Binary Refinery — Encoding & Decoding

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_codec` | Encode/decode (base64, hex, url, utf8, etc.) | `data`, `operation`, `codec` |
| `refinery_xor` | XOR with known key; can read slices from loaded file and save output | `data_hex` or `file_offset`+`length`, `key_hex`, `output_path` |
| `refinery_auto_decrypt` | Auto-detect and decrypt XOR/SUB patterns | `data` |
| `refinery_decompress` | Decompress gzip/bzip2/lz4/zlib/lzma | `data`, `algorithm` |
| `refinery_hash` | Compute MD5/SHA1/SHA256/ssdeep/imphash | `data`, `algorithm` |
| `refinery_string_operations` | String manipulation (trim, split, case) | `data`, `operation` |
| `refinery_pretty_print` | Pretty-print JSON/XML/hex/structures | `data`, `format` |

## Binary Refinery — Encryption

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_decrypt` | AES/RC4/DES/ChaCha20/Blowfish decryption | `data`, `algorithm`, `key`, `iv` |
| `refinery_key_derive` | Key derivation (PBKDF2, scrypt, etc.) | `password`, `algorithm` |

## Binary Refinery — Carving & Extraction

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_carve` | Carve embedded files from binary data; save carved items to disk | `data`, `pattern`, `output_path` |
| `refinery_extract` | Extract from archives/containers | `data`, `format` |
| `refinery_regex_extract` | Extract data matching regex patterns | `data`, `pattern` |
| `refinery_regex_replace` | Find and replace with regex | `data`, `pattern`, `replacement` |
| `refinery_extract_iocs` | Extract IOCs via refinery patterns | `data` |
| `refinery_extract_domains` | Extract domain names from data | `data` |

## Binary Refinery — .NET

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_dotnet` | .NET resource extraction, deobfuscation | `data`, `operation` |

## Binary Refinery — Executable & Forensic

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_executable` | Executable analysis operations via refinery | `data`, `operation` |
| `refinery_forensic` | Forensic analysis via refinery | `data`, `operation` |
| `refinery_pe_operations` | PE repair, overlay extraction, rebuilding | `data`, `operation` |

## Binary Refinery — Script Deobfuscation

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_deobfuscate_script` | Deobfuscate batch/PowerShell/VBS scripts | `data`, `script_type` |
| `refinery_decompile` | Decompile code/scripts via refinery | `data` |
| `autoit_decrypt` | Decrypt AutoIt3 compiled scripts (.a3x / PE-embedded). Supports **MT19937** (standard) and **RanRot PRNG** (modified builds). Auto-detects algorithm by scanning PE for RanRot multiplier (0x53A9B4FB). | `data_hex`, `file_offset`, `file_path`, `prng_type` (auto/mt/ranrot), `custom_key`, `output_path` |

## Binary Refinery — Utilities

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `refinery_pipeline` | Chain multiple refinery operations (encoding, compression, crypto, slicing, bitwise, padding); supports batch mode (`data_hex_list` up to 100 items) and file offset input | `data_hex` or `file_offset`+`length`, `steps`, `output_path`, `data_hex_list` (batch) |
| `refinery_list_units` | List all available refinery units | `category` (optional) |

**Pipeline step categories** (use `refinery_list_units(category)` to discover all operations):

| Category | Example Operations | Use Case |
|----------|-------------------|----------|
| encoding | `b64`, `hex`, `url`, `utf8` | Decode/encode Base64, hex, URL-encoded data |
| compression | `zl`, `lzma`, `bzip2`, `lz4` | Decompress compressed payloads |
| crypto | `xor`, `rc4`, `aes`, `des`, `chacha` | Decrypt with known keys |
| slicing | `snip`, `chop`, `pick` | Extract byte ranges or split data |
| bitwise | `ror`, `rol`, `shl`, `shr`, `add`, `sub`, `and`, `or`, `not` | Bitwise transforms |
| padding | `pad`, `terminate` | Add/remove padding |
| utility | `nop` | No-op passthrough (for debugging) |

> **Always discover before use**: Call `refinery_list_units(category)` to confirm
> exact operation names and parameters before constructing pipelines. Operation names
> must match exactly — guessing leads to errors.

## Payload & Config Extraction

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `extract_config_automated` | Auto-extract C2 configurations | — |
| `extract_steganography` | Detect data hidden after image EOF | — |
| `parse_custom_container` | Parse custom malware container formats | `format_hint` |
| `scan_for_embedded_files` | Detect nested PE/ZIP/PDF/scripts | — |
| `detect_compression_headers` | Find compression/archive headers in data | — |
| `extract_config_for_family` | KB-driven config extraction for a confirmed malware family | `family`, `section_hint` (optional), `offset_hint` (optional) |
| `parse_binary_struct` | Parse binary data according to a typed field schema (ints, strings, IPs) | `schema`, `data_hex` or `file_offset`+`length` |

## Unpacking

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `auto_unpack_pe` | Known packers (UPX, ASPack, Themida, etc.) | — |
| `try_all_unpackers` | Orchestrate multiple unpacking methods | — |
| `find_oep_heuristic` | Find original entry point heuristically | — |
| `reconstruct_pe_from_dump` | Rebuild PE from memory dump | `dump_data`, `oep` |
| `detect_packing` | Detect packing/compression indicators | — |

## IOC Extraction

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_iocs_structured` | Aggregate IOCs into STIX/OpenIOC/JSON | `format` |
| `refinery_extract_iocs` | IOC extraction via refinery patterns | `data` |
| `refinery_extract_domains` | Domain extraction from data | `data` |
| `scan_for_api_hashes` | Scan for API hash constants used by shellcode/malware (ror13, djb2, crc32, fnv1a); supports `family_hint` for KB-driven config | `hash_algorithm`, `seed`, `family_hint`, `include_extended_db` |

## Binary Modification & Patching

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `patch_binary_memory` | Patch binary memory/sections | `address`, `data` |
| `patch_with_assembly` | Patch with assembled instructions | `address`, `instructions` |
| `assemble_instruction` | Assemble instructions to bytes | `instructions`, `arch` |
| `modify_pe_section` | Modify PE section content | `section_name`, `data` |
| `save_patched_binary` | Save patched binary to disk | `output_path` |

## Function Similarity (BSim-style)

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `extract_function_features` | Extract feature vectors (CFG, API, VEX IR, strings, constants) from functions | `function_address` (optional), `limit`, `include_vex` |
| `find_similar_functions` | Compare a function against all functions in another binary (background, timeout 600s) | `function_address`, `file_path_b`, `threshold`, `metrics` |
| `build_function_signature_db` | Index all functions into persistent SQLite DB for cross-binary search (background) | `limit` |
| `query_signature_db` | Search signature DB for similar functions (two-phase: SQL pre-filter + scoring) | `function_address`, `threshold`, `metrics` |
| `list_signature_dbs` | List all indexed binaries in the signature database | — |

## Comparison & Diffing

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `diff_binaries` | Compare two binaries (matching/differing functions, background, timeout 600s) | `file_path_2` |
| `diff_payloads` | Byte-by-byte comparison of two payloads | `payload_1`, `payload_2` |
| `compute_similarity_hashes` | ssdeep/TLSH/imphash similarity hashes | — |
| `compare_file_similarity` | Compare two files for similarity scores | `file_path_2` |

## Anti-Analysis Detection

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `find_anti_debug_comprehensive` | Comprehensive anti-debug + anti-VM + instruction scan | `compact`, `limit` (default 60) |
| `detect_self_modifying_code` | Detect self-modifying code patterns | — |
| `find_code_caves` | Find executable gaps in code sections | — |
| `detect_control_flow_flattening` | Detect CFF obfuscation patterns (dispatcher blocks, state vars, back-edges). Use when triage shows suspected obfuscation or abnormal control flow | `function_address` (optional), `min_confidence` (default 40), `limit` (default 20) |
| `detect_opaque_predicates` | Detect opaque predicates via Z3 constraint solving — conditional branches where only one path is satisfiable | `function_address` (optional), `limit` (default 20) |
| `detect_vm_protection` | Detect VMProtect/Themida/Enigma/Code Virtualizer protection. Returns protector-specific options, import obfuscation score (0.0-1.0), and recommendations. No angr required | — |

## PE Forensics & Detection Engineering

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `generate_yara_rule` | Generate YARA detection rule from analysis | `rule_name`, `scan_after_generate` |
| `generate_sigma_rule` | Generate Sigma detection rules | `rule_type` (`process_creation`, `file_event`, `registry`, `all`) |
| `parse_authenticode` | Analyze PE code signing certificates | — |
| `unify_artifact_timeline` | Correlate all temporal artifacts, detect timestomping | — |
| `analyze_debug_directory` | Deep PDB/POGO/Rich header analysis | — |
| `analyze_relocations` | Parse relocations, detect ASLR bypass | `limit` |
| `analyze_seh_handlers` | Analyze SEH/x64 exception handlers | `limit` |

## Threat Intelligence & Attribution

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `detect_dga_indicators` | Scan for DGA capability indicators | `confidence_threshold`, `limit` (default 20) |
| `match_c2_indicators` | Match against C2 framework profiles | `frameworks`, `scan_depth`, `limit` (default 20) |
| `analyze_kernel_driver` | Analyze kernel driver (.sys) characteristics | `limit` (default 30) |
| `map_mitre_attack` | Map findings to MITRE ATT&CK techniques | `include_navigator_layer` |
| `analyze_batch` | Multi-file comparison and clustering | `directory` or `file_paths`, `include_similarity` |

## Hooking (Emulation Control)

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `hook_function` | Hook a function for emulation/symbolic execution | `address`, `handler` |
| `list_hooks` | List all active function hooks | — |
| `unhook_function` | Remove a function hook | `address` |
| `list_angr_analyses` | List all available angr analysis types | — |

## Session, Notes & History

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `add_note` | Record a finding or observation | `content`, `category` |
| `get_notes` | Retrieve all notes for current file | — |
| `update_note` | Edit an existing note | `note_id`, `content` |
| `delete_note` | Remove a note | `note_id` |
| `auto_note_function` | Auto-generate behavioral summary for function | `address` |
| `get_tool_history` | Review tools run during session | — |
| `clear_tool_history` | Clear tool history | — |
| `get_analysis_timeline` | Timeline of analysis activities | `offset` (default -1, most recent), `limit` (default 50) |
| `get_session_summary` | Comprehensive session summary; includes `analysis_warnings` count when library warnings present | `notes_offset` (default 0), `notes_limit` (default 50), `history_limit` (default 30) |
| `get_analysis_warnings` | View library warnings (angr, cle, capa, FLOSS, etc.) captured during analysis — explains failures/incomplete results | `logger_name`, `level`, `tool_name`, `offset`, `limit` |
| `clear_analysis_warnings` | Clear captured warnings buffer | — |

## Analysis Progress & Guidance

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_analysis_digest` | Aggregated findings summary (call at phase transitions); includes `user_flagged_functions` from dashboard triage and `coverage_detail` field with per-area analysis progress | `findings_offset/limit`, `functions_offset/limit`, `ioc_offset/limit`, `unexplored_offset/limit`, `notes_offset/limit` |
| `get_progress_overview` | Analysis coverage and gaps | — |
| `suggest_next_action` | AI-suggested next analysis steps; prioritises dashboard-flagged functions | `max_suggestions` (default 5) |
| `list_tools_by_phase` | Tools organized by workflow phase | — |

> **Dashboard triage integration:** The web dashboard (port 8082) allows the analyst to flag functions as FLAG/SUS/CLN via the Functions page. These triage flags are surfaced in `get_session_summary()` (`user_triage_flags`), `get_analysis_digest()` (`user_flagged_functions`), and `suggest_next_action()` (flagged functions inserted at top priority). Always check these tools for analyst-flagged targets before selecting your own.

## Reporting & Export

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `generate_analysis_report` | Generate comprehensive formatted report | `format` |
| `auto_name_sample` | Generate descriptive filename from findings | — |
| `export_project` | Export portable project archive (includes artifacts up to 50 MB) | `output_path` |
| `import_project` | Import a project archive (restores artifacts to ~/.arkana/imported/artifacts/) | `project_path` |

## Cache Management

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `get_cache_stats` | Check disk cache usage statistics | — |
| `clear_analysis_cache` | Clear entire analysis cache | — |
| `remove_cached_analysis` | Remove specific cached analysis | `sha256` |

## Malware Family Identification

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `identify_malware_family` | After decompiling API hash routines, finding config encryption, or identifying distinctive constants — matches evidence against 123-family knowledge base | `hash_algorithm`, `hash_seed`, `hash_constants`, `config_encryption`, `config_pattern`, `compiler`, `command_count`, `network_headers`, `network_uris`, `constants`, `dll_names`, `matched_strings`, `matched_hex_patterns` |
| `list_malware_signatures` | To browse known malware families and their fingerprints before analysis, or review a specific family's full indicator profile | `family` (optional — omit for summary of all families) |
| `verify_malware_attribution` | After `identify_malware_family()` returns a candidate — confirms attribution with per-evidence pass/fail verdicts. Catches misattribution between similar families | `family` (required), plus same evidence params as `identify_malware_family` |

## Rename / Annotation Layer

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `rename_function` | Assign user-defined name to function (persisted, applied in decompilation output) | `address`, `new_name` |
| `rename_variable` | Rename variable within function scope (applied in decompilation) | `function_address`, `old_name`, `new_name` |
| `add_label` | Add labelled marker at address (shown in annotated disassembly) | `address`, `label_name`, `category` |
| `list_renames` | List all renames and labels | `rename_type` (optional: functions, variables, labels) |
| `delete_rename` | Remove a specific rename or label | `address`, `rename_type` |
| `batch_rename` | Bulk apply up to 50 renames in one call | `renames` (list of dicts) |

## Custom Types

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `create_struct` | Define named struct for parsing binary data | `name`, `fields` |
| `create_enum` | Define named enum with value mappings | `name`, `values`, `size` (default 4) |
| `apply_type_at_offset` | Parse binary at offset using a custom type | `type_name`, `file_offset`, `count` (default 1) |
| `list_custom_types` | List all defined structs and enums | — |
| `delete_custom_type` | Remove a type definition | `name` |

## Frida Dynamic Instrumentation

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `generate_frida_hook_script` | Hook specific APIs or addresses for runtime interception | `targets` (API names or hex addresses), `include_backtrace`, `include_args`, `output_path` |
| `generate_frida_bypass_script` | Bypass anti-debug techniques detected in imports/triage | `auto_detect` (default True), `techniques` (manual override), `output_path` |
| `generate_frida_trace_script` | Generate broad API tracing script from binary's imports | `categories` (filter by behavior), `limit` (default 50), `output_path` |

## Vulnerability Analysis

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `scan_for_vulnerability_patterns` | Scan for common vulnerability patterns (buffer overflow, format string, integer overflow, use-after-free, command injection, path traversal) | `categories`, `limit` |
| `assess_function_attack_surface` | Assess attack surface of a specific function | `function_address` |

## .NET Deobfuscation

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `detect_dotnet_obfuscation` | Detect .NET obfuscation tools (ConfuserEx, .NET Reactor, etc.) | — |
| `dotnet_deobfuscate` | Run deobfuscation tools (de4dot, NETReactorSlayer) | `tool`, `output_path` |
| `dotnet_decompile` | Decompile .NET assembly to C# via ILSpy | `type_name` (optional), `output_path` |

## Code Search & Context

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `search_decompiled_code` | Full-text search across all cached decompiled functions | `query`, `limit` |
| `get_analysis_context_for_function` | Get comprehensive context for a function (decompilation, xrefs, strings, complexity) | `function_address` |

## Entropy Analysis

| Tool | Use When | Key Parameters |
|------|----------|----------------|
| `analyze_entropy_by_offset` | Entropy visualization by file offset | `window_size` |

---

## Known Limitations

**Data flow tools**: `get_data_dependencies` returns raw angr internals — prefer `get_reaching_definitions` or `propagate_constants`. `get_backward_slice`/`get_forward_slice` return CFG reachability, not true data-flow slices. `extract_function_constants` includes code addresses alongside data constants.

**Emulation**: Qiling requires manual rootfs setup (`qiling_setup_check()`). FSG-packed binaries may fail with `auto_unpack_pe` — use `qiling_dump_unpacked_binary` as fallback. Speakeasy/Qiling have limited success with complex anti-emulation packers.

**External deps**: `get_virustotal_report_for_loaded_file` requires API key via `set_api_key()`. `scan_for_embedded_files` requires binwalk v3+.

**Output**: `analyze_batch` can be truncated by the 8KB response limit for large file sets. `search_decompiled_code` searches C pseudocode, not assembly — use `get_annotated_disassembly(search=...)` for assembly. `refinery_carve`/`refinery_extract_iocs` may have false positives on raw binary data.
