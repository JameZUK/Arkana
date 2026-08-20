# MCP Tools Reference

Arkana exposes **308 tools** organised into the following categories. All list-returning tools support pagination via `limit` and `offset` parameters  - see [Pagination & Result Limits](architecture.md#pagination--result-limits) for details.

> **Address format:** All tools accept both hex (`0x401000`) and decimal (`4198400`) for address/offset parameters. Hex strings with a `0x` prefix are auto-detected.

---

## Capability Overview

### Multi-Format Binary Support

Arkana automatically detects and analyses binaries across all major platforms:

- **PE (Windows)**  - Full parsing of DOS/NT Headers, Imports/Exports, Resources, TLS, Debug, Load Config, Rich Header, Overlay, and more.
- **ELF (Linux)**  - Headers, sections, segments, symbols, dynamic dependencies, DWARF debug info.
- **Mach-O (macOS)**  - Headers, load commands, segments, symbols, dynamic libraries, code signatures.
- **.NET Assemblies**  - CLR headers, metadata tables, type/method definitions, CIL bytecode disassembly.
- **Go Binaries**  - Compiler version, packages, function names, type definitions (works on stripped binaries via pclntab).
- **Rust Binaries**  - Compiler version, crate dependencies, toolchain info, symbol demangling.
- **Raw Shellcode**  - Architecture-aware loading with FLOSS string extraction.

### Advanced Binary Analysis (Powered by Angr)

46 tools powered by the **Angr** binary analysis framework, working across PE, ELF, and Mach-O:

- **Decompilation**  - Convert assembly into human-readable C-like pseudocode on the fly.
- **Control Flow Graph (CFG)**  - Generate and traverse function blocks and edges.
- **Symbolic Execution**  - Automatically find inputs to reach specific code paths.
- **Emulation**  - Execute functions with concrete arguments using the Unicorn engine.
- **Slicing & Dominators**  - Perform forward/backward slicing to track data flow and identify critical code dependencies.
- **Reaching Definitions & Data Dependencies**  - Track how values propagate through registers and memory.
- **Function Hooking**  - Replace functions with custom SimProcedures for analysis.
- **Value Set Analysis**  - Determine possible values of variables at each program point.
- **Binary Diffing**  - Compare two binaries to find added/removed/modified functions.
- **Code Cave Detection**  - Find unused space in binaries for patching.
- **C++ Class Recovery**  - Identify vtables and class hierarchies.
- **Packing Detection**  - Heuristic analysis of entropy and structure anomalies.

### Comprehensive Static Analysis

- **PE Structure**  - 24 dedicated tools for every PE data directory and header.
- **Signatures**  - Authenticode validation (Signify), certificate parsing (Cryptography), packer detection (PEiD), YARA scanning with bundled rules from [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (MIT) and [Yara-Rules Community](https://github.com/Yara-Rules/rules) (GPL-2.0), and custom YARA rule execution.
- **Capabilities**  - Integrated Capa analysis to map binary behaviours to the MITRE ATT&CK framework.
- **Strings**  - FLOSS integration for extracting static, stack, tight, and decoded strings, ranked by relevance using StringSifter. VA-based string extraction for decompilation follow-up.
- **Crypto Analysis**  - Detect crypto constants (AES S-box, DES, RC4), scan for API hashes, entropy analysis. Advanced crypto algorithm identification, automated key extraction, and brute-force decryption.
- **Deobfuscation**  - Multi-byte XOR brute-forcing, format string detection, wide string extraction.
- **Payload Extraction**  - Steganography detection, custom container parsing, and automated C2 configuration extraction.
- **IOC Export**  - Structured IOC aggregation with JSON, CSV, and STIX 2.1 bundle export formats.
- **Unpacking**  - Multi-method unpacking orchestration, PE reconstruction from memory dumps, and heuristic OEP detection.

### Extended Library Integrations

- **LIEF**  - Multi-format binary parsing and modification (PE/ELF/Mach-O section editing). Serves as a fallback parser when pefile cannot handle malformed or corrupt PE files.
- **Capstone**  - Multi-architecture standalone disassembly (x86, ARM, MIPS, etc.).
- **Keystone**  - Multi-architecture assembly (generate patches from mnemonics).
- **Speakeasy**  - Windows API emulation for malware analysis (full PE and shellcode).
- **Qiling**  - Cross-platform binary emulation (Windows/Linux/macOS, x86/x64/ARM/MIPS).
- **Un{i}packer**  - Automatic PE unpacking (UPX, ASPack, FSG, etc.).
- **Binwalk**  - Embedded file and firmware detection.
- **ppdeep/TLSH**  - Fuzzy hashing for sample similarity comparison.
- **dnfile/dncil**  - .NET metadata parsing and CIL bytecode disassembly.
- **pygore**  - Go binary reverse engineering.
- **rustbininfo**  - Rust binary metadata extraction.
- **pyelftools**  - ELF and DWARF debug info parsing.
- **Binary Refinery**  - 23 context-efficient tools (consolidated from 56 via dispatch pattern) for composable binary data transforms: encoding/decoding, crypto, compression, IOC extraction, PE/ELF/Mach-O section operations, .NET metadata, archive extraction, Office documents, PCAP/EVTX forensics, steganography, and multi-step pipelines. Only registered when binary-refinery is installed.

### Session Continuity & AI Progress Tracking

Arkana is designed for **large binary corpus analysis** where AI clients need to maintain analytical context across long investigations and limited context windows:

- **Persistent Notes**  - Record findings with `add_note()`, auto-summarise functions with `auto_note_function()`, and aggregate everything with `get_analysis_digest()`. Notes survive server restarts and are restored automatically when the same file is reopened.
- **Tool History**  - Every tool invocation is recorded with parameters, result summaries, and timing. Use `get_tool_history()` to review what was done, or `get_session_summary()` for full session state.
- **Cross-Session Restoration**  - When a previously analysed file is reopened, `open_file` returns a `session_context` field containing restored notes and prior tool history, enabling the AI to resume where it left off.
- **Analysis Digest**  - `get_analysis_digest()` compiles all accumulated notes, triage findings, IOCs, coverage stats, and unexplored targets into a single context-efficient summary  - what was *learned*, not just what tools ran.
- **Discoverability**  - `list_tools_by_phase()` organises tools by workflow stage, `suggest_next_action()` recommends specific next steps based on session state, and `get_analysis_timeline()` merges tool history with notes into a chronological narrative.
- **Workflow Automation**  - `generate_analysis_report()` produces a comprehensive Markdown report from accumulated findings, and `auto_name_sample()` suggests descriptive filenames based on detected capabilities and C2 indicators.
- **Project Export/Import**  - Bundle analysis + notes + history + binary into a `.arkana_project.tar.gz` for sharing or archiving with `export_project`.

### Dynamic File Loading & Caching

- **Auto-Detection**  - `open_file` automatically detects PE/ELF/Mach-O from magic bytes. Unknown formats (ZIP, PDF, PCAP, DEX, etc.) are identified and fall back to raw/shellcode mode instead of crashing in PE mode. Use `force=True` to override.
- **Pre-Parse Integrity Checks**  - Every `open_file` call includes a `file_integrity` assessment in the response: status (healthy/suspicious/partial/corrupt), issues list, flags, format details, and recommendation. The standalone `check_file_integrity` tool can run before loading. Flagged files automatically use a reduced analysis timeout to prevent hangs.
- **No Pre-loading Required**  - The MCP server starts without needing a file path. Use the `open_file` tool to load files dynamically.
- **Analysis Caching**  - Results are cached to disk in `~/.arkana/cache/`, keyed by SHA256 hash and compressed with gzip (~12x compression). Re-opening a previously analysed file loads instantly from cache.
- **Persistent Configuration**  - API keys are stored securely in `~/.arkana/config.json` and recalled automatically across sessions.
- **Progress Reporting**  - Over 50 long-running tools report fine-grained progress to the MCP client in real time (percentage, stage descriptions). Tools running in background threads use a thread-safe `ProgressBridge` to push updates back to the async MCP context.
- **Progress-Adaptive Background Timeouts**  - Background tasks use a soft timeout → OVERTIME → stall-kill system. After the soft timeout (5 min for generic tasks, 15 min for CFG), the task enters `overtime` status (still running). During overtime, progress is checked every 60s — if progressing, the task keeps running; if stalled for 5 min with zero progress, it is killed. A 6-hour absolute ceiling prevents pathological cases. Passive `_background_alerts` are injected into every tool response when tasks are in overtime. Use `abort_background_task(task_id)` to explicitly stop any task. Eight tools capture partial results on stall-kill. All timeout values are configurable via environment variables.

---

## File Management & Sample Discovery

| Tool | Description |
|---|---|
| `open_file` | Load and analyse a binary (PE/ELF/Mach-O/shellcode). Auto-detects format with smart fallback (unknown formats → raw mode). Returns `file_integrity` assessment and `quick_indicators` for PE files. Use `force=True` to override format fallback. **Blocks when background tasks are active** — returns an error listing active tasks. Use `abort_background_task()` to stop them first, or pass `force_switch=True` to proceed anyway. |
| `check_file_integrity` | Pre-parse integrity check on a binary file. Detects truncation, null-padding, impossible sizes, and header corruption for PE/ELF/Mach-O. Can run before or after `open_file`. Does not modify state. |
| `close_file` | Close the loaded file and clear analysis data from memory. **Blocks when background tasks are active** — returns an error listing active tasks. Use `abort_background_task()` to stop them first, or pass `force_switch=True` to proceed anyway. |
| `reanalyze_loaded_pe_file` | Re-run PE analysis with different options (skip/enable specific analyses). |
| `detect_binary_format` | Auto-detect binary format and suggest appropriate analysis tools. |
| `list_samples` | List files in the configured samples directory. Supports flat (top-level only) and recursive listing, glob pattern filtering (e.g. `*.exe`), and returns file metadata including size and magic-byte format hints (PE/ELF/Mach-O/ZIP/etc.). Paginated with `limit` and `offset`. Configured via `--samples-path` or `ARKANA_SAMPLES`. |

## Configuration & Utilities

| Tool | Description |
|---|---|
| `set_api_key` | Store an API key persistently in `~/.arkana/config.json`. |
| `get_config` | View current configuration, available libraries, and loaded file status. |
| `get_current_datetime` | Retrieve current UTC and local date/time. |
| `check_task_status` | Monitor progress of background tasks. Returns `elapsed_seconds`/`elapsed_human` for all tasks, generic `stall_detection` (triggers after 60s without progress), `timed_out`/`partial_result` for stall-killed tasks. For overtime tasks: `overtime_seconds`, `progress_trend` (progressing/stalled), `stall_seconds`, `recommendation`, and `discovery_rate_per_min` (CFG tasks). |
| `abort_background_task` | Abort a running or overtime background task. Marks it as failed/aborted; the worker thread result is discarded. Returns partial data if available (e.g. functions discovered during CFG build). |
| `get_extended_capabilities` | List all available tools and library versions. |
| `get_cache_stats` | View analysis cache statistics (entries, size, utilisation). |
| `clear_analysis_cache` | Clear the entire disk-based analysis cache. |
| `remove_cached_analysis` | Remove a specific cached analysis by SHA256 hash. |

## PE Structure Analysis (3 tools)

| Tool | Description |
|---|---|
| `get_analyzed_file_summary` | High-level summary with counts of sections, imports, matches. Paginated (default limit 20). |
| `get_full_analysis_results` | Complete analysis data (all keys, with size guard). Requires explicit `limit`. |
| `get_pe_data` | **Unified data retrieval**  - retrieve any PE analysis key by name (e.g., `get_pe_data(key='imports')`). Use `key='list'` to discover all 25 available keys with descriptions and sizes. Supports `limit` (default 20) and `offset` (default 0) for pagination. Replaces 25 individual `get_*_info` tools. |

Available `get_pe_data` keys: `file_hashes`, `dos_header`, `nt_headers`, `data_directories`, `sections`, `imports`, `exports`, `resources_summary`, `version_info`, `debug_info`, `digital_signature`, `peid_matches`, `yara_matches`, `rich_header`, `delay_load_imports`, `tls_info`, `load_config`, `com_descriptor`, `overlay_data`, `base_relocations`, `bound_imports`, `exception_data`, `coff_symbols`, `checksum_verification`, `pefile_warnings`.

## PE Extended Analysis (14 tools)

Many PE extended analysis tools support pagination via `limit` and `offset` parameters.

| Tool | Description |
|---|---|
| `get_section_permissions` | Human-readable section permission matrix (RWX). Paginated (default limit 20). |
| `get_pe_metadata` | Compilation timestamps, linker info, subsystem, DLL characteristics. |
| `extract_resources` | Extract and decode PE resources by type. Paginated (default limit 20). |
| `extract_manifest` | Extract and parse embedded application manifest XML. |
| `get_load_config_details` | Extended load config (SEH, CFG, RFG, CET details). |
| `extract_wide_strings` | Extract UTF-16LE wide strings from the binary. Paginated (default limit 20). |
| `detect_format_strings` | Detect printf/scanf format strings (format string vuln hunting). Paginated (default limit 20). |
| `detect_compression_headers` | Detect embedded compressed data (zlib, gzip, LZMA, etc.). Paginated (default limit 30). |
| `deobfuscate_xor_multi_byte` | Multi-byte XOR deobfuscation with known key. |
| `detect_crypto_constants` | Detect crypto constants (AES S-box, DES, SHA, RC4, etc.). Paginated (default limit 20). |
| `analyze_entropy_by_offset` | Sliding-window entropy analysis to detect packed/encrypted regions. Paginated (default limit 50). |
| `scan_for_api_hashes` | Detect API hashing patterns (ROR13, CRC32, DJB2, FNV). Paginated (default limit 20). |
| `get_import_hash_analysis` | Import hash (imphash) with per-DLL analysis and anomaly detection. |

## Signature & Capability Analysis

| Tool | Description |
|---|---|
| `get_capa_analysis_info` | Capa capability rules overview with filtering. Paginated (default limit 20). |
| `get_capa_rule_match_details` | Detailed match info for a specific Capa rule. |

> **Note:** PEiD matches and YARA matches are now accessed via `get_pe_data(key='peid_matches')` and `get_pe_data(key='yara_matches')`.

## String Analysis (14 tools)

All string tools that return lists support pagination via `limit` (default 20) and `offset` (default 0) parameters.

| Tool | Description |
|---|---|
| `get_floss_analysis_info` | FLOSS results (static, stack, tight, decoded strings). Paginated (default limit 20). |
| `extract_strings_from_binary` | Extract printable ASCII strings, optionally ranked. Requires explicit `limit`. |
| `search_for_specific_strings` | Search for specific strings within the binary. |
| `search_floss_strings` | Regex search across FLOSS strings with score filtering. Paginated (default limit 20). |
| `get_top_sifted_strings` | ML-ranked strings from all sources with granular filtering. Requires explicit `limit`. |
| `get_strings_for_function` | All strings referenced by a specific function. Paginated (default limit 20). |
| `get_string_usage_context` | Disassembly context showing where a string is used. Paginated (default limit 20). |
| `fuzzy_search_strings` | Fuzzy matching to find similar strings. Requires explicit `limit`. |
| `find_and_decode_encoded_strings` | Multi-layer Base64/Hex/XOR decoding with heuristics. |
| `get_strings_summary` | Categorised string intelligence  - groups strings by type (URLs, IPs, file paths, registry keys, mutex names, base64 blobs) with counts and top examples. |
| `search_yara_custom` | Compile and run custom YARA rules (provided as a string) against the loaded binary. Returns matching rules with offsets. Useful for validating hypotheses about byte patterns or structures. Paginated (default limit 20). |
| `get_string_at_va` | Extract a string at a virtual address or file offset. Reads bytes until null terminator with auto-encoding detection (ASCII/UTF-16LE). Supports `address_type='va'` (default, resolves VA to file offset) or `address_type='file_offset'` (reads directly at file offset, also computes VA for cross-reference). Useful when decompilation references a string pointer or when FLOSS gives file offsets. |
| `search_hex_pattern` | Search the loaded binary for hex byte patterns with `??` wildcards. Example: `"4D 5A ?? ?? ?? ?? ?? ?? 50 45"` finds PE headers at any offset. Optional section filter restricts search to a named PE section. Max 200 tokens, 5000 matches. |

## Triage & Forensics

| Tool | Description |
|---|---|
| `get_triage_report` | **Comprehensive automated triage** (25+ dimensions)  - packing assessment, digital signatures, timestamp anomalies, Rich header fingerprint, suspicious imports & delay-load evasion, capa capabilities, network IOCs, section anomalies, overlay/appended data analysis, resource anomalies (nested PE detection), YARA matches, header corruption detection, TLS callback detection, security mitigations (ASLR/DEP/CFG/CET/XFG), version info spoofing, .NET indicators, export anomalies, high-value strings, ELF security features (PIE/NX/RELRO/canaries), Mach-O security (code signing/PIE), cumulative risk score, and format-aware tool suggestions. Paginated (default limit 20). |
| `classify_binary_purpose` | Classify binary type (GUI app, console app, DLL, service, driver, installer, .NET assembly) from headers, imports, and resources. |
| `get_virustotal_report_for_loaded_file` | Query VirusTotal for the file hash. |

## Deobfuscation & Utilities

| Tool | Description |
|---|---|
| `deobfuscate_base64` | Decode hex-encoded Base64 data. Parameter: `data_hex` (hex string of Base64-encoded bytes). Returns a structured dict with `decoded_text`, `input_hex_length`, and `decoded_length`. |
| `deobfuscate_xor_single_byte` | XOR-decrypt hex data with a single byte key. |
| `is_mostly_printable_ascii` | Check if a string is mostly printable. |
| `get_hex_dump` | Hex dump of a file region. |

## Binary Analysis  - Core Angr (20 tools)

All angr tools that return lists support pagination via `limit` and `offset` parameters. The default `limit` is 20 for most tools.

| Tool | Description |
|---|---|
| `list_angr_analyses` | **Discovery tool**  - lists all available angr analysis capabilities grouped by category (decompilation, CFG, symbolic, slicing, forensic, hooks, modification) with parameter descriptions. Call this first to understand available analyses. |
| `get_angr_partial_functions` | List functions discovered in angr's knowledge base, even while CFG is still building or has timed out. Works without full CFG. Paginated (default limit 50). |
| `decompile_function_with_angr` | C-like pseudocode for a function at a given address. Works without full CFG by building a local region CFG. Applies user-assigned renames (function names and variables) to the output. Supports `search` parameter for regex grep within decompiled code (with `context_lines` and `case_sensitive` options). |
| `batch_decompile` | Decompile up to 20 functions in a single call. Per-function timeout of 60s. Results cached per-function via `_ToolResultCache`. Applies rename helpers. Use `summary_mode=True` for signature + first 5 lines only. Supports `search` parameter to grep across all functions and return only those with matches. Self-reporting progress. |
| `get_function_cfg` | Control flow graph (nodes and edges) for a function. |
| `find_path_to_address` | Symbolic execution to find inputs reaching a target address. |
| `emulate_function_execution` | Emulate a function with concrete arguments. |
| `analyze_binary_loops` | Detect and characterise loops in the binary. Paginated (default limit 20). |
| `get_function_xrefs` | Cross-references (callers and callees) for a function. Paginated (default limit 20). |
| `get_backward_slice` | All code blocks that can reach a target address. Paginated (default limit 20). |
| `get_forward_slice` | All code reachable from a source address. Paginated (default limit 20). |
| `get_dominators` | Dominator blocks that must execute to reach a target. Returns diagnostic notes when the result is empty (e.g. target is the function entry, or address doesn't correspond to a block boundary). |
| `get_function_complexity_list` | Functions ranked by complexity (block/edge count). Paginated (default limit 20). |
| `extract_function_constants` | Hardcoded constants and string references in a function. Paginated (default limit 20). |
| `get_global_data_refs` | Global memory addresses read/written by a function. Paginated (default limit 20). |
| `scan_for_indirect_jumps` | Indirect jumps/calls (dynamic control flow) in a function. Filters out constant-target exits and return instructions (`Ijk_Ret`), classifies results by `flow_type` (`indirect_call`, `indirect_jump`). Paginated (default limit 20). |
| `patch_binary_memory` | Patch the loaded binary in memory with new bytes. |
| `get_cross_reference_map` | Multi-dimensional cross-reference  - for one or more functions, returns API calls, string refs, callers, callees, suspicious imports, and complexity in a single response. |
| `solve_constraints_for_path` | Use angr's symbolic execution and constraint solver to find concrete input values (stdin, argv, symbolic registers) that cause execution to reach a target address. Returns detailed constraint solutions. Background task. |
| `explore_symbolic_states` | Explore symbolic execution states across multiple target addresses simultaneously with selectable strategy (DFS, BFS, or directed). Reports all found states with constraint summaries and solved input values. Background task. |

## Binary Analysis  - Extended Angr (24 tools)

| Tool | Description |
|---|---|
| `get_reaching_definitions` | Track how values propagate through registers and memory. Paginated (default limit 20). |
| `get_data_dependencies` | Data dependency analysis (def-use chains) for a function. Paginated (default limit 20). |
| `hook_function` | Replace a function with a custom SimProcedure. |
| `list_hooks` | List all active function hooks. |
| `unhook_function` | Remove a previously set hook. Resolves symbol names by searching angr's internal `_sim_procedures` table (more reliable than `find_symbol`). Falls back to cleaning tracking state if the hook was already cleared. |
| `get_calling_conventions` | Detect calling conventions for functions. Includes diagnostic notes when CC analysis produces no results (e.g. for simprocedures or thunks). Paginated (default limit 20). |
| `get_function_variables` | Recover local variables and parameters. Automatically filters VEX IR temporaries (`ir_N`, `tmp_N`) from results and reports their count separately. Paginated (default limit 80). |
| `disassemble_at_address` | Disassemble N instructions at a given address (default 30 instructions). |
| `identify_library_functions` | Identify standard library functions (libc, etc.). Paginated (default limit 20). |
| `get_control_dependencies` | Control dependency analysis for a function. Paginated (default limit 20). |
| `propagate_constants` | Constant propagation analysis. Paginated (default limit 80). |
| `diff_binaries` | Compare two binaries for added/removed/modified functions. Paginated (default limit 20). |
| `detect_self_modifying_code` | Detect code that writes to executable memory. Paginated (default limit 20). |
| `find_code_caves` | Find unused executable space for patching. Paginated (default limit 20). |
| `get_call_graph` | Generate full or filtered inter-procedural call graph. Paginated (default limit 50). |
| `find_path_with_custom_input` | Symbolic execution with custom constraints. |
| `emulate_with_watchpoints` | Emulate with memory/register watchpoints. |
| `get_annotated_disassembly` | Rich disassembly with resolved names and comments. Paginated (default limit 300). Supports `search` parameter for regex grep within instructions (mnemonics, operands, call targets, labels). For Go binaries, automatically annotates call instructions with Go ABI parameter/return register mappings (register ABI for Go 1.17+ AMD64/ARM64, stack ABI for older versions). |
| `get_value_set_analysis` | Determine possible values at program points. Computationally expensive; consider `get_reaching_definitions` or `propagate_constants` for lighter analysis. Paginated (default limit 80). |
| `detect_packing` | Heuristic packing/encryption detection (not paginated). |
| `save_patched_binary` | Save a patched binary to disk. |
| `identify_cpp_classes` | Recover C++ vtables and class hierarchies. Paginated (default limit 20). |
| `get_function_map` | Smart function ranking  - scores every function by interestingness (complexity, suspicious API calls, string refs, xref count) and groups by purpose. Paginated (default limit 30). |
| `find_anti_debug_comprehensive` | Comprehensive anti-analysis and anti-debug technique detection  - checks specific API patterns (IsDebuggerPresent, NtQueryInformationProcess, timing checks, PEB access), TLS callbacks, known evasion techniques, anti-VM indicators (93 hypervisor strings across VMware/VirtualBox/Hyper-V/QEMU/Xen/Parallels/sandbox/analysis tools), and instruction-level scanning (RDTSC, CPUID, INT 2Dh, SIDT). Returns a detailed inventory with severity ratings, hypervisor breakdown, and instruction findings. |

## PE Forensics & Detection Engineering (7 tools)

| Tool | Description |
|---|---|
| `generate_yara_rule` | Auto-generate a YARA detection rule from the loaded binary's analysis findings: FLOSS decoded/stack strings, ML-ranked high-value strings, network IOCs (URLs, domains, IPs), basic ASCII strings (fallback), import combinations, section names, Rich header hash, PDB path, file size range, and byte patterns. Outputs valid YARA syntax. Use `scan_after_generate=True` to immediately compile and scan the loaded binary with the generated rule, returning match results inline. |
| `generate_sigma_rule` | Generate draft Sigma detection rules from analysis findings: process creation patterns, file paths, registry keys, and network indicators. Supports `rule_type`: `process_creation`, `file_event`, `registry`, or `all`. Includes confidence annotations. |
| `parse_authenticode` | Parse PE authenticode signatures: certificate details (subject, issuer, serial, thumbprint, validity), countersignature timestamps, PE hash validation, and anomaly detection (expired, self-signed, mismatched hashes). |
| `unify_artifact_timeline` | Correlate all temporal artifacts: PE compile timestamp, debug directory timestamps, Rich header build info, resource timestamps, export table timestamp, digital signature timestamps, and .NET metadata. Flags timestomping, future dates, and component mismatches. |
| `analyze_debug_directory` | Deep parsing of the debug directory: PDB paths and GUIDs (CodeView NB10/RSDS), POGO sections, Rich header build tool info, debug info anomalies (mismatched timestamps, suspicious PDB paths, timestamp tampering). |
| `analyze_relocations` | Parse BASE_RELOC directory: relocation blocks, types, and anomalies. Detects ASLR bypass indicators, out-of-section relocations, unusual type distributions, and empty/malformed blocks. |
| `analyze_seh_handlers` | Analyze Structured Exception Handling: x64 RUNTIME_FUNCTION entries, SafeSEH table (x86), SEH-based anti-debug patterns, and suspicious handler addresses (outside image, in writable sections). |

## Threat Intelligence & Attribution (5 tools)

| Tool | Description |
|---|---|
| `detect_dga_indicators` | Scan for Domain Generation Algorithm indicators via API co-occurrence analysis, suspicious string patterns, and import combination scoring. Configurable `confidence_threshold`. |
| `match_c2_indicators` | Match binary content against known C2 framework indicator profiles: Cobalt Strike, Metasploit, Sliver, Havoc, Brute Ratel, Covenant, Mythic, PoshC2. Checks User-Agent strings, URI patterns, named pipes, framework-specific strings, and magic bytes. |
| `analyze_kernel_driver` | Analyze kernel driver characteristics: DriverEntry detection, kernel API categorization, IRP dispatch patterns, IOCTL handler identification, filter driver registration, and DKOM/rootkit indicators. Use when PE subsystem is Native (1). |
| `map_mitre_attack` | Aggregate all MITRE ATT&CK-relevant findings from analysis: capa results, import classification, behavioral indicators, and string matches. Maps to specific techniques with confidence scores. Optionally outputs an ATT&CK Navigator JSON layer. |
| `analyze_batch` | Batch-analyze multiple binary files: compute hashes, PE metadata, import overlaps, timestamp comparison, and optional similarity clustering (ssdeep/TLSH pairwise). Does NOT modify the currently loaded file. Accepts `directory` or `file_paths`. |

## Extended Library Tools (13 tools)

| Tool | Description |
|---|---|
| `parse_binary_with_lief` | Multi-format binary parsing with LIEF (PE/ELF/Mach-O). |
| `modify_pe_section` | Modify PE section properties (name, characteristics). |
| `disassemble_raw_bytes` | Disassemble raw bytes with Capstone (any architecture). Paginated (default limit 20). |
| `assemble_instruction` | Assemble mnemonics to bytes with Keystone. |
| `patch_with_assembly` | Assemble and patch instructions into the binary. |
| `compute_similarity_hashes` | Compute ssdeep and TLSH fuzzy hashes. |
| `compare_file_similarity` | Compare two files using fuzzy hash similarity. |
| `emulate_pe_with_windows_apis` | Full Windows API emulation with Speakeasy. Use `track_allocations=True` to track VirtualAlloc/VirtualProtect/HeapAlloc calls and return a memory allocation timeline with anomaly detection (RWX allocations, large allocations, alloc-then-protect sequences). Paginated (default limit 20). |
| `emulate_shellcode_with_speakeasy` | Emulate shellcode with Windows API hooks. Paginated (default limit 20). |
| `auto_unpack_pe` | Automatically unpack packed PEs (UPX, ASPack, FSG, etc.). |
| `scan_for_embedded_files` | Detect embedded files/firmware with Binwalk. Paginated (default limit 20). |
| `get_extended_capabilities` | List all available tools and library versions. |

## Qiling Cross-Platform Emulation (8 tools)

| Tool | Description |
|---|---|
| `emulate_binary_with_qiling` | Full OS emulation of PE/ELF/Mach-O binaries with behavioural report (API calls, file/registry/network activity). Cross-platform  - unlike Speakeasy (Windows-only), Qiling handles Linux ELF and macOS Mach-O as well. Use `trace_syscalls=True` for syscall-level tracing with optional `syscall_filter`, `track_memory=True` for memory allocation tracking, and `anti_vm_bypass=True` to spoof CPUID/RDTSC/VMware I/O port results (defeats anti-VM detection but NOT code virtualization — see Known Limitations). Paginated (default limit 20). |
| `emulate_shellcode_with_qiling` | Multi-architecture shellcode emulation (x86, x64, ARM, ARM64, MIPS) with API/syscall capture. Paginated (default limit 20). |
| `qiling_trace_execution` | Instruction-level execution tracing with addresses, sizes, and raw bytes for each executed instruction. Paginated (default limit 50). |
| `qiling_hook_api_calls` | Hook specific APIs/syscalls to capture arguments and return values during emulation. Paginated (default limit 20). |
| `qiling_dump_unpacked_binary` | Dynamic unpacking via emulation — handles custom/unknown packers that YARA-based unipacker cannot identify. `smart_unpack` (default True) hooks VirtualAlloc/VirtualAllocEx to track allocations, then scans for PE headers (MZ + PE signature) in tracked regions. Falls back to largest-region heuristic if no PE found. |
| `qiling_resolve_api_hashes` | Resolve API hash values (ROR13, CRC32, DJB2, FNV-1a) against known DLL exports. |
| `qiling_memory_search` | Run a binary then search process memory for decrypted strings, C2 URLs, keys, or byte patterns. Paginated (default limit 20). |
| `qiling_setup_check` | Check Qiling Framework setup status  - venv availability, rootfs directory structure, and essential DLLs for each architecture. Provides specific copy commands for missing DLLs. |

> **Note:** Qiling runs in an isolated venv (`/app/qiling-venv`) with unicorn 1.x, keeping the main environment's unicorn 2.x intact for angr. Linux rootfs is pre-populated at Docker build time. Windows PE emulation requires real DLL files copied from a Windows installation  - see [QILING_ROOTFS.md](QILING_ROOTFS.md) for setup instructions. Registry hive stubs are auto-generated at runtime.

## Interactive Emulation Debugger (29 tools)

Interactive debugger built on Qiling, providing step-by-step emulation control with breakpoints, watchpoints, memory inspection, and snapshot-based state management. Unlike fire-and-forget emulation tools, debug sessions persist across MCP calls via a JSONL protocol over a persistent subprocess.

### Session Lifecycle

| Tool | Description |
|---|---|
| `debug_start` | Start an interactive debug session on the loaded binary. Spawns a persistent Qiling subprocess, pauses at entry point. `stub_crt` (default True) installs ~47 CRT initialization stubs (GetSystemTimeAsFileTime, GetCurrentProcessId, GetProcessHeap, critical sections, TLS/FLS, etc.). `stub_io` (default True) installs Win32 console API stubs to prevent crashes from printf/cout/cin. `anti_vm_bypass` (default False) enables anti-VM detection bypass hooks (CPUID hypervisor bit spoofing, RDTSC timing normalisation, VMware I/O port masking). API tracing is enabled by default. Returns initial PC, registers, architecture, and stub/trace status. Max 3 concurrent sessions. |
| `debug_stop` | Stop and destroy a debug session. Kills the subprocess and frees resources. |
| `debug_status` | Check if a debug session is alive and return its current state (PC, status, instructions executed, architecture). |

### Execution Control

| Tool | Description |
|---|---|
| `debug_step` | Step N instructions (default 1). Returns updated PC, registers, and next 5 disassembled instructions. |
| `debug_step_over` | Step over a CALL instruction (sets temporary breakpoint after the call). If the current instruction is not a CALL, behaves like single step. |
| `debug_continue` | Continue execution until a breakpoint/watchpoint is hit, the program exits, or `max_instructions` (default 10M) is reached. |
| `debug_run_until` | Run until a specific address is reached (temporary breakpoint). Accepts `max_instructions` safety limit. |

### Breakpoints & Watchpoints

| Tool | Description |
|---|---|
| `debug_set_breakpoint` | Set a breakpoint by address, API name, or with conditions (e.g., `{"register": "eax", "equals": "0x0"}`). Max 100 per session. |
| `debug_remove_breakpoint` | Remove a breakpoint by ID. |
| `debug_set_watchpoint` | Set a memory watchpoint (read, write, or both) on an address range. Max 50 per session, max 1MB region. |
| `debug_remove_watchpoint` | Remove a watchpoint by ID. |
| `debug_list_breakpoints` | List all breakpoints and watchpoints in the session. |

### Inspection & Modification

| Tool | Description |
|---|---|
| `debug_read_state` | Read full execution state: all registers, flags, PC, stack top, next 5 disassembled instructions, and memory map summary. |
| `debug_read_memory` | Read N bytes at an address. Returns hex dump and optional capstone disassembly. Max 1MB per read. |
| `debug_write_memory` | Write bytes to memory at a given address. |
| `debug_write_register` | Set a register value. Validates register name against the session's architecture. |

### Snapshots

| Tool | Description |
|---|---|
| `debug_snapshot_save` | Save complete emulation state (CPU, memory, hooks) with an optional name and note. Max 10 per session. |
| `debug_snapshot_restore` | Restore a previously saved snapshot, rewinding execution to that point. |
| `debug_snapshot_list` | List all saved snapshots with metadata (PC, instruction count, timestamp). |
| `debug_snapshot_diff` | Compare two snapshots — shows register differences and changed memory regions. With `attribute_changes=True`, correlates memory changes with API calls that occurred between snapshots (VirtualAlloc, WriteProcessMemory, ReadFile, VirtualProtect categories) and reports unattributed changes. |

### I/O Stubs

| Tool | Description |
|---|---|
| `debug_set_input` | Queue input data for stubbed console input (ReadConsoleA). Supports UTF-8 and hex encoding. Queue input before stepping through stdin/cin/scanf code. |
| `debug_get_output` | Retrieve captured console output from I/O stubs. All text from WriteConsoleA/W (printf, puts, cout) is captured. Paginated with optional clear. |

### API Call Tracing

| Tool | Description |
|---|---|
| `debug_get_api_trace` | Retrieve the API call trace log. All Windows API calls are logged with function name, arguments, and return value. Paginated with optional name filter. Supports structured `query` predicates for filtering by argument values, return values, and sequence numbers (e.g. `api=VirtualAlloc,args.p3=0x40`). Operators: `=`, `!=`, `~` (substring), `>`, `<`, `>=`, `<=`. Also supports ordered `sequence` matching to find API call patterns (e.g. `VirtualAlloc;WriteProcessMemory;CreateRemoteThread`). |
| `debug_clear_api_trace` | Clear the API call trace buffer. |
| `debug_set_trace_filter` | Configure API trace filtering. Set a whitelist of specific API names, or enable/disable tracing entirely. |

### Memory Search

| Tool | Description |
|---|---|
| `debug_search_memory` | Search all mapped memory for string patterns (UTF-8 + UTF-16LE) or hex byte patterns with `??` wildcards. Returns matches with address, region label, and context bytes. Max 100 matches. |

### API Stubs

| Tool | Description |
|---|---|
| `debug_stub_api` | Create a custom API stub at runtime. When the binary calls the specified Windows API, the stub intercepts it, sets the return value, optionally writes data to output pointer parameters, and returns cleanly. `set_last_error` parameter bypasses GetLastError() anti-emulation techniques (e.g. `set_last_error="0x578"` for ERROR_INVALID_WINDOW_HANDLE). Useful for stubbing APIs not covered by builtin CRT/I/O stubs. Max 200 user stubs. |
| `debug_list_stubs` | List all installed API stubs: builtin I/O stubs (8 console APIs), builtin CRT stubs (~47 MSVC init APIs), and user-defined stubs. |
| `debug_remove_stub` | Remove a user-defined API stub. Builtin I/O and CRT stubs cannot be removed — restart the session with `stub_io=False` or `stub_crt=False` to disable them. |

> **Note:** Debug sessions use the same isolated Qiling venv (`/app/qiling-venv`) as the fire-and-forget emulation tools. Sessions time out after 30 minutes of inactivity (`ARKANA_DEBUG_SESSION_TTL`). Each execution command has a 5-minute timeout (`ARKANA_DEBUG_COMMAND_TIMEOUT`). When the timeout fires, the session is **paused, not killed** — the runner calls `emu_stop()` (Unicorn's thread-safe stop) to halt emulation while preserving all CPU state, memory, and hooks. You can inspect the paused session with `debug_read_state`/`debug_read_memory`/`debug_search_memory`, then resume with `debug_continue`. Emulation fidelity limitations apply — complex anti-emulation, threading, and some Windows APIs may not work correctly.

## Post-Emulation Memory Inspection (8 tools)

Persistent emulation sessions that keep the Qiling or Speakeasy subprocess alive after `run()` completes. Unlike fire-and-forget emulation tools, these allow unlimited memory queries on the same emulation state without re-running the binary.

| Tool | Description |
|------|-------------|
| `emulate_and_inspect` | Emulate a binary or shellcode with Qiling or Speakeasy, keep the session alive. Returns behavioral report + `session_id` for subsequent memory queries. |
| `emulation_resume` | Resume emulation from where it left off (Qiling only). Continues from current CPU state with a fresh timeout. Enables staged long-running operations like UPX decompression: run 300s → check memory → resume 300s → check → repeat. |
| `emulation_read_memory` | Read raw bytes at a virtual address (max 1MB). Supports `format="disasm"` for Capstone disassembly. |
| `emulation_write_memory` | Write bytes to memory at a virtual address. Useful for patching code or modifying data. |
| `emulation_search_memory` | Search all mapped memory regions for string (UTF-8 + UTF-16LE) or hex patterns. |
| `emulation_memory_map` | List all mapped memory regions with addresses, sizes, permissions, and labels. |
| `emulation_session_status` | List all active emulation inspect sessions with metadata. |
| `close_emulation_session` | Close an emulation session and release subprocess resources. |

> **Note:** Max 3 concurrent emulation sessions (`ARKANA_MAX_EMULATION_SESSIONS`). Sessions idle for 30 minutes are automatically cleaned up (`ARKANA_EMULATION_SESSION_TTL`). Emulation uses the same isolated venvs as fire-and-forget tools (Qiling venv for Qiling, Speakeasy venv for Speakeasy). Defense-in-depth timeouts: runner hard timer (`os._exit` at timeout+15s), MCP `threading.Timer` backup (kills subprocess at timeout+45s), `asyncio.wait_for` (timeout+30s). User's `timeout_seconds` is propagated to all layers.

## Multi-Format Binary Analysis (9 tools)

All multi-format analysis tools support pagination via `limit` (default 20) and `offset` (default 0) parameters.

| Tool | Description |
|---|---|
| `detect_binary_format` | Auto-detect format (PE/.NET/ELF/Mach-O/Go/Rust) from magic bytes. |
| `dotnet_analyze` | Comprehensive .NET metadata: CLR header, types, methods, assembly refs, user strings. Type/method attribute flags are displayed in compact pipe-separated format (e.g. `Public | Class | AutoLayout`). Paginated (default limit 20). |
| `dotnet_disassemble_method` | Disassemble .NET CIL bytecode to human-readable opcodes. Paginated (default limit 20). |
| `go_analyze` | Go binary analysis: compiler version, packages, functions, type descriptors (works on stripped binaries). Parses typelink/itab sections for struct field layouts, interface method sets, and interface dispatch tables (Go 1.7–1.26+). Falls back through GoReSym→pygore→gopclntab→string-scan. Paginated (default limit 20). |
| `rust_analyze` | Rust binary metadata: compiler version, crate dependencies, toolchain. |
| `rust_demangle_symbols` | Demangle Rust symbol names to human-readable form. Paginated (default limit 20). |
| `elf_analyze` | Comprehensive ELF analysis: headers, sections, segments, symbols, dynamic deps. Paginated (default limit 20). |
| `elf_dwarf_info` | Extract DWARF debug info: compilation units, functions, source files. Paginated (default limit 20). |
| `macho_analyze` | Mach-O analysis: headers, load commands, segments, symbols, dylibs, code signatures. Paginated (default limit 20). |

## Binary Refinery  - Data Transforms (23 tools)

Arkana integrates the full power of [Binary Refinery](https://github.com/binref/refinery)  - a library of **200+ composable binary transformation units**  - through 23 context-efficient MCP tools. Binary Refinery is used extensively by professional malware analysts for tasks like decrypting multi-layer obfuscation, extracting payloads from documents, unpacking installers, and parsing forensic artefacts. Arkana makes these capabilities accessible through natural language, with the AI selecting the right units automatically.

All tools accept data as hex input or operate on the currently loaded file. All Refinery tools support pagination via `limit` (default 20) and `offset` (default 0) parameters. **Only registered when binary-refinery is installed** (lazy registration saves context tokens when absent).

> **Context efficiency:** 56 individual tools were consolidated into 23 using the dispatch pattern (`operation=...` parameter), saving ~33 tool definitions (~15-20K tokens) from the MCP catalogue.

### Core Transforms (11 tools)

| Tool | Description |
|---|---|
| `refinery_codec` | Encode or decode data using 18 encodings (b64, hex, b32, b58, b62, b85, a85, b92, url, esc, u16, uuenc, netbios, cp1252, wshenc, morse, htmlesc, z85). Use `direction='decode'` (default) or `direction='encode'`. Covers the encoding schemes most commonly encountered in malware obfuscation. |
| `refinery_decrypt` | Decrypt data using **35 cipher algorithms**: AES, DES, 3DES, RC4, Blowfish, Camellia, CAST, ChaCha20, Salsa20, Serpent, TEA/XTEA/XXTEA, RC2/RC5/RC6, SM4, Rabbit, SEAL, GOST, Fernet, Speck, HC-128/HC-256, ISAAC, Sosemanuk, Vigenere, ROT, Rijndael, Chaskey, and more. Supports ECB/CBC/CTR/CFB/OFB/GCM block modes. This covers virtually every encryption scheme found in real-world malware. |
| `refinery_xor` | XOR operations  - the single most common obfuscation in malware. `operation='apply'` to XOR with a known key, or `operation='guess_key'` to automatically detect the XOR key using frequency analysis and known-plaintext attacks. The key guessing is effective against single-byte, multi-byte, and rolling XOR schemes. |
| `refinery_decompress` | Decompress data with 23 algorithms including auto-detection. Supports: zlib, bz2, LZMA, LZ4, Brotli, Zstandard, aPLib, LZNT1 (Windows NTFS compression), LZO, BriefLZ, LZF, LZJB, LZW, LZX (CAB), NRV (UPX), QuickLZ, SZDD (old MS), FastLZ, JCALG. The `auto` mode probes all formats. |
| `refinery_extract_iocs` | Extract IOCs from binary data: URLs, IPv4/IPv6 addresses, domain names, email addresses, file paths, hostnames, MD5/SHA1/SHA256 hashes, and GUIDs. Uses Binary Refinery's `xtp` pattern extractor which is more accurate than simple regex matching. |
| `refinery_carve` | Carve embedded data from binaries. `operation='pattern'` carves encoded blobs (Base64, hex, Base32, Base85, URL-encoded, int arrays, strings). `operation='files'` carves embedded file types (PE, ZIP, 7z, RTF, JSON, XML, LNK, DER certificates). Essential for extracting dropped payloads and embedded configs. |
| `refinery_pe_operations` | PE-specific operations: extract overlay data (common payload hiding spot), extract PE metadata, extract resources, strip debug/certificate data, debloat inflated binaries, extract Authenticode signatures. |
| `refinery_deobfuscate_script` | Deobfuscate malicious scripts: PowerShell (ps1), VBA macros (vba), and JavaScript (js). Uses dedicated deobfuscation engines that handle string concatenation, array lookups, arithmetic obfuscation, and encoding layers commonly used by malware droppers. |
| `refinery_hash` | Compute cryptographic hashes: MD5, SHA-1, SHA-256, SHA-384, SHA-512, CRC32, Adler32. |
| `refinery_pipeline` | **Multi-step transformation chains**  - execute an ordered sequence of transforms in a single call. Example: `['b64', 'xor:41', 'zl']` decodes Base64, XORs with key 0x41, then decompresses with zlib. Supports all encoding, compression, and cipher units. This mirrors Binary Refinery's pipe operator (`data \| b64 \| xor[0x41] \| zl`) in a single API call. |
| `refinery_list_units` | Discovery tool  - list all available Binary Refinery unit categories and units installed on the system, with counts per category. |

### Advanced Transforms (8 tools)

| Tool | Description |
|---|---|
| `refinery_regex_extract` | Extract regex matches from binary data with named group support. Useful for extracting structured data (config values, encoded strings) from decompiled code or memory dumps. |
| `refinery_regex_replace` | Find and replace using regex in binary data with backreference support. |
| `refinery_auto_decrypt` | **Automatic decryption**  - uses frequency analysis, known plaintext attacks, and file signature detection to automatically recover XOR/SUB encryption keys and decrypt data. Particularly effective against malware that XOR-encrypts payloads with repeating keys. |
| `refinery_key_derive` | Derive cryptographic keys from passwords using PBKDF2, HKDF, or HMAC with configurable hash algorithms (SHA-256, SHA-1, SHA-512, MD5). Essential for decrypting malware configs protected with password-derived keys. |
| `refinery_string_operations` | Binary string operations: snip (byte slicing), trim, replace, case conversion. Useful for extracting sub-sections of decoded data. |
| `refinery_pretty_print` | Pretty-print structured data (JSON, XML, JavaScript) for readability. Useful after decoding config files or protocol data. |
| `refinery_decompile` | Decompile compiled scripts: Python bytecode (`.pyc` files) to source code, and AutoIt scripts (`.a3x` compiled scripts). Both are common vectors for malware distribution. |
| `autoit_decrypt` | Decrypt and decompile AutoIt3 compiled scripts with dual-PRNG support: standard Mersenne Twister (MT19937) and modified RanRot PRNG (used by DarkGate, StealC, AsgardProtector). Auto-detects algorithm from loaded PE, supports custom keys, EA05/EA06 formats, LZSS decompression, and bytecode deassembly. |
| `refinery_extract_domains` | Extract DNS domain names using wire-format parsing (more accurate than regex for DNS data). |

### .NET Analysis (1 dispatched tool, 10 operations)

The `refinery_dotnet` tool provides deep .NET/CLR analysis  - critical for analysing the large volume of .NET malware (Agent Tesla, AsyncRAT, Quasar RAT, RedLine Stealer, and many more).

| Tool | Operations |
|---|---|
| `refinery_dotnet` | **headers**  - CLR metadata tables, assembly info, type/method definitions. **resources**  - embedded .NET resources (images, configs, encrypted payloads). **managed_resources**  - sub-files from ResourceManager containers. **strings**  - all strings from #Strings and #US metadata streams. **blobs**  - binary data from #Blob stream. **disassemble**  - CIL/MSIL bytecode disassembly per method. **fields**  - constant field values (where RATs store C2 URLs, encryption keys). **arrays**  - byte-array initialisers (shellcode, encrypted payloads). **sfx**  - unpack .NET single-file application bundles. **deserialize**  - deserialise BinaryFormatter data to JSON. |

### Executable Operations (1 dispatched tool, 7 operations)

| Tool | Operations |
|---|---|
| `refinery_executable` | **sections**  - extract sections/segments from PE, ELF, or Mach-O with entropy calculation per section. **virtual_read**  - read bytes at a virtual address. **file_to_virtual**  - convert file offset to virtual address (and back). **disassemble**  - native disassembly (x86/x64/ARM) via Capstone; supports `address` parameter to disassemble at a specific virtual address (reads data via `vsnip`). **disassemble_cil**  - .NET CIL/MSIL bytecode disassembly. **entropy_map**  - visual entropy heatmap of the binary (identifies packed/encrypted regions at a glance). **stego**  - extract hidden data from images via LSB steganography. |

### Archive & Document Extraction (1 dispatched tool, 7 operations)

The `refinery_extract` tool handles every container format commonly encountered in malware delivery chains.

| Tool | Operations |
|---|---|
| `refinery_extract` | **archive**  - extract from ZIP, 7z, TAR, gzip, CAB, ISO, CPIO, CHM, ACE (with password support). **installer**  - unpack NSIS, InnoSetup, PyInstaller, Nuitka, Node.js, ASAR, minidumps. **office**  - extract OLE streams, VBA macros, VBA p-code, strings, text, metadata, Excel cells, RTF objects, OneNote attachments. **office_decrypt**  - decrypt password-protected Office documents. **xlm_deobfuscate**  - deobfuscate Excel 4.0 (XLM) macros. **pdf**  - extract objects and streams from PDFs (with optional decryption). **embedded**  - auto-detect and extract all embedded files (PE, ZIP, ELF, PDF, OLE). |

### Forensic Parsing (1 dispatched tool, 9 operations)

| Tool | Operations |
|---|---|
| `refinery_forensic` | **pcap**  - parse PCAP files and reassemble TCP streams. **pcap_http**  - extract HTTP requests/responses with URLs, methods, and bodies. **evtx**  - parse Windows Event Log files. **registry**  - parse Windows Registry hives (SAM, SYSTEM, NTUSER.DAT). **lnk**  - parse Windows shortcut files (common malware delivery vector). **defang**  - defang IOCs for safe sharing in reports. **url_guards**  - strip URL protection wrappers (Microsoft SafeLinks, ProofPoint, etc.). **protobuf**  - decode Protocol Buffer messages without a schema. **msgpack**  - decode MessagePack binary data to JSON. |

### Binary Refinery Power Combinations

The real power of Arkana's Binary Refinery integration emerges when tools are chained together. Here are patterns the AI uses automatically:

**Decode multi-layer obfuscation:**
`refinery_carve(pattern='b64')` → `refinery_xor(operation='guess_key')` → `refinery_decompress(algorithm='auto')` → `refinery_extract_iocs()`

**Extract and analyse Office malware:**
`refinery_extract(operation='office', sub_operation='vba')` → `refinery_deobfuscate_script(script_type='vba')` → `refinery_carve(pattern='b64')` → `refinery_extract_iocs()`

**Decrypt .NET RAT configuration:**
`refinery_dotnet(operation='fields')` → `refinery_dotnet(operation='arrays')` → `refinery_decrypt(algorithm='aes')` → `refinery_extract_iocs()`

**Parse forensic artefacts:**
`refinery_forensic(operation='pcap_http')` → `refinery_extract(operation='embedded')` → per-file: `open_file()` → `get_triage_report()`

## Cryptographic Analysis (3 tools)

| Tool | Description |
|---|---|
| `identify_crypto_algorithm` | Identify cryptographic algorithms via S-box scanning, key schedule patterns, hash constants, CRC tables, and crypto API imports. Returns confidence-scored detections. Paginated (default limit 20). |
| `auto_extract_crypto_keys` | Search for potential cryptographic keys near identified constants using entropy-based heuristics. Returns key candidates with offset, entropy, and confidence scores. Paginated (default limit 20). |
| `brute_force_simple_crypto` | Brute-force XOR (single/multi-byte), RC4, ADD/SUB/ROL/ROR transforms against the loaded binary. Validates results by checking for PE headers, readable strings, and known patterns. Supports known-plaintext XOR key detection. Paginated (default limit 10). |

## Payload Extraction (3 tools)

| Tool | Description |
|---|---|
| `extract_steganography` | Detect data hidden after image EOF markers (PNG IEND, JPEG FFD9, GIF trailer), BMP size mismatches, and PE overlay data. Returns payload entropy, magic bytes, and extraction hints. Paginated (default limit 10). |
| `parse_custom_container` | Parse binary data following common malware container patterns: `delimiter_size_payload`, `size_payload`, or `fixed_chunks`. Auto-detects delimiters and chunk sizes with entropy analysis. Returns diagnostic hints when 0 chunks are found (e.g. delimiter not found, size field points past data end). Paginated (default limit 20). |
| `extract_config_automated` | Extract potential C2 configuration data using regex patterns  - IPs, URLs, domains, registry keys, file paths, mutexes, and base64-encoded config blobs. Auto-saves significant findings as notes. Paginated (default limit 20). |

## Malware Family Identification (3 tools)

| Tool | Description |
|---|---|
| `identify_malware_family` | Match observed binary indicators (API hash algorithm/seed, config encryption, constants, YARA patterns, compiler, network headers, DLL names, command count) against a 123-family signature knowledge base. Returns ranked candidates with confidence scores, per-category match breakdowns, and extraction guidance. |
| `list_malware_signatures` | Browse the malware signatures knowledge base. Returns a summary of all known families (name, aliases, hash algorithm/seed, config encryption, compiler, source URL) or full fingerprint details for a specific family. |
| `verify_malware_attribution` | Verify a claimed malware attribution by checking each piece of evidence against the knowledge base entry for a specific family. Returns a pass/fail verdict per evidence point and an overall CONFIRMED/PARTIAL_MATCH/UNLIKELY/INCONCLUSIVE verdict. Essential for avoiding misattribution between similar families (e.g. AdaptixC2 vs Havoc). |

## IOC Export (1 tool)

| Tool | Description |
|---|---|
| `get_iocs_structured` | Aggregate IOCs from triage, string analysis, config extraction, and notes into a deduplicated, categorised collection. Supports three export formats: **JSON**, **CSV**, and **STIX 2.1 Bundle**. |

## Unpacking & OEP Detection (3 tools)

| Tool | Description |
|---|---|
| `try_all_unpackers` | Orchestrate multiple unpacking methods (Unipacker, Binary Refinery vstack, PE overlay extraction) and return the best result with method comparison. |
| `reconstruct_pe_from_dump` | Reconstruct a valid PE from a memory dump by fixing headers using LIEF  - realigns sections, fixes SizeOfImage/SizeOfHeaders, and adjusts base address. |
| `find_oep_heuristic` | Detect Original Entry Point of packed binaries using multiple heuristics: tail-jump detection, section-hop analysis, entropy transitions, and known packer patterns. Returns confidence-scored candidates. Paginated (default limit 10). |

## Binary Comparison (1 tool)

| Tool | Description |
|---|---|
| `diff_payloads` | Compare two binary payloads byte-by-byte  - reports identical/different regions, similarity percentage, and XOR relationship detection. For PE files, includes structural comparison (sections, imports). |

## Function Similarity  - BSim-style (5 tools)

Architecture-independent function similarity matching inspired by Ghidra's BSim. Uses 6 feature groups extracted from angr's CFG and VEX IR: CFG structure, API calls, VEX operation profile, string references, constants, and size metrics. Supports pairwise comparison and persistent SQLite signature database for cross-binary search.

| Tool | Description |
|---|---|
| `extract_function_features` | Extract feature vectors from functions in the loaded binary. Features include CFG structure (block/edge count, cyclomatic complexity, loops), API calls with semantic categories, VEX IR operation histogram, string reference hashes, constants, and size metrics. |
| `find_similar_functions` | Compare a function against all functions in another binary. Background task that loads the second binary, extracts features, and scores pairwise similarity. Returns ranked matches above threshold. |
| `build_function_signature_db` | Index all non-trivial functions from the loaded binary into a persistent SQLite database at `~/.arkana/bsim/signatures.db`. Background task with progress reporting. Skips simprocedures, syscalls, and single-block thunks. |
| `query_signature_db` | Search the signature database for functions similar to one in the loaded binary. Two-phase query: SQL pre-filter on structural features eliminates ~80-90% of candidates, then full feature vector scoring on the remainder. |
| `list_signature_dbs` | List all binaries indexed in the function signature database with metadata (SHA256, filename, architecture, function count, indexing date). No angr dependency  - reads only SQLite metadata. |

## Workflow & Reporting (2 tools)

| Tool | Description |
|---|---|
| `generate_analysis_report` | Generate a comprehensive analysis report from accumulated findings in Markdown or plain text  - includes file info, risk assessment, key findings, explored functions, IOCs, analyst notes, and timeline. |
| `auto_name_sample` | Suggest a descriptive filename based on detected capabilities, classification, and C2 indicators (e.g. `service_keylogger_c2_192.168.105.250.dll`). |

## AI-Optimised Analysis  - Streamlined Tools

These tools are designed for progressive, context-efficient analysis by AI clients with limited context windows. They provide summaries first, details on demand, and cross-reference data across multiple analysis dimensions.

| Tool | Description |
|---|---|
| `get_triage_report(compact=True)` | **Compact triage**  - risk level, score, top findings, and next-tool suggestions in ~2KB instead of ~20KB. Use `compact=False` for the full report. Paginated (default limit 20). |
| `get_focused_imports` | **Filtered import view**  - returns only security-relevant imports categorised by threat behaviour (process injection, networking, crypto, anti-analysis, etc.), filtering out thousands of benign imports. Paginated (default limit 20). |
| `get_strings_summary` | **Categorised string intelligence**  - groups strings by type (URLs, IPs, file paths, registry keys, mutex names, base64 blobs) with counts and top examples per category. |
| `get_function_map` | **Smart function ranking**  - scores every function by interestingness (complexity, suspicious API calls, string refs, xref count, entry point status) and groups by purpose. Falls back to import-based categorisation when angr is unavailable. Paginated (default limit 30). |
| `get_cross_reference_map` | **Multi-dimensional cross-reference**  - for one or more functions, returns API calls, string refs, callers, callees, suspicious imports, and complexity in a single response. |
| `auto_note_function` | **Auto-summarise a function**  - generates a one-line behavioural summary from API call patterns and saves it as a persistent note for later aggregation. |
| `get_analysis_digest` | **Running analysis summary**  - aggregates triage findings, function notes, IOCs, coverage stats (including `coverage_detail` with per-category breakdowns of decompiled, annotated, and triaged functions), and unexplored high-priority targets into a context-efficient digest. Call at phase transitions to refresh understanding. |
| `get_function_complexity_list(compact=True)` | **Compact complexity list**  - returns minimal per-function data (addr, name, blocks) instead of the full structure. Paginated (default limit 20). |
| `list_tools_by_phase(phase)` | **Tool discovery**  - browse all tools grouped by analysis phase (triage, explore, deep-dive, context, utility). Helps find the right tool for the current stage. |
| `suggest_next_action()` | **Smart recommendations**  - analyses current session state (loaded file, notes, tool history) and recommends 3-5 specific next steps. |
| `get_analysis_timeline()` | **Investigation narrative**  - merges tool history with notes into a single chronological timeline showing the full analysis story. Paginated (default limit 20). |

### Recommended AI Workflow

1. **`get_config()`**  - discover writable paths, container environment, and available libraries
2. **`open_file(path)`**  - load binary, auto-starts background angr CFG. If `session_context` is present, call `get_analysis_digest()` first to review previous findings. All background tasks (CFG build, symbolic execution, data flow, emulation) have automatic timeouts and stall detection  - use `check_task_status(task_id)` to monitor elapsed time and progress.
3. **`get_triage_report(compact=True)`**  - initial risk assessment in ~2KB. **Key findings are auto-saved as notes.**
4. **`get_focused_imports()`**  - understand what suspicious APIs are imported
5. **`get_strings_summary()`**  - categorised string overview
6. **`get_function_map()`**  - find the most interesting functions to investigate (default limit 30; use `limit` and `offset` to page through results)
7. **`decompile_function_with_angr(address)`**  - deep-dive into each target
8. **`auto_note_function(address)`**  - **ALWAYS call after each decompilation** to record what you learned
9. **`add_note(content, category='tool_result')`**  - record any important manual findings (decoded IOCs, anti-debug tricks, etc.)
10. **`get_analysis_digest()`**  - call at phase transitions to refresh your understanding

> **Pagination tip:** Most tools default to returning 20 items per page. If results indicate `"has_more": true` in the `_pagination` block, call the same tool with an incremented `offset` to fetch the next page.

## Session Persistence & Notes

Notes and tool history are the primary mechanism for preserving analysis context across sessions and managing long-running investigations within limited context windows. All notes and history persist to disk automatically.

**How notes work:**
- **Automatic**: `get_triage_report()` auto-saves risk assessment, critical imports, and IOCs as `tool_result` notes
- **Function summaries**: `auto_note_function(address)` generates and saves one-line behavioural summaries from API patterns  - call this after every decompilation
- **Manual findings**: `add_note(content, category='tool_result')` records specific observations (decoded C2 URLs, crypto keys, evasion techniques)
- **Aggregation**: `get_analysis_digest()` compiles all notes into an actionable summary with coverage stats and unexplored targets
- **Persistence**: Notes survive server restarts. When the same file is reopened, all previous notes and history are restored automatically
- **Export**: `export_project` bundles analysis + notes + history + artifacts + optionally the binary into a `.arkana_project.tar.gz` for sharing

**Note categories:** `general`, `function`, `tool_result`, `ioc`, `hypothesis`, `manual`

**Artifacts:** Tools that extract files (unpacking, payload carving, config extraction) register them via `state.register_artifact()`. Artifacts are tracked with path, SHA256 hash, source tool, and type detection. They persist via cache alongside notes and are included in `export_project` / `import_project` archives. Limits: `MAX_ARTIFACT_FILE_SIZE` (100 MB per file), `MAX_TOTAL_ARTIFACT_EXPORT_SIZE` (50 MB total export).

| Tool | Description |
|---|---|
| `add_note` | Record a finding or observation. Categories: `general`, `function`, `tool_result`, `ioc`, `hypothesis`, `manual`. Persisted to disk cache, survives restarts. |
| `get_notes` | Retrieve notes, filtered by category or address. Paginated (default limit 20). |
| `update_note` / `delete_note` | Modify or remove notes. |
| `auto_note_function` | Auto-generate and save a one-line function summary from API patterns. |
| `get_tool_history` | View the history of tools run during this session. Paginated (default limit 20). |
| `clear_tool_history` | Clear the tool invocation history for the current session. |
| `get_session_summary` | Full session state: file info, notes, tool history, angr status, analysis phase. |
| `get_analysis_digest` | Accumulated findings digest  - what was *learned*, not just what tools ran. Includes `coverage_detail` with per-category breakdowns of analysis completeness. |
| `get_progress_overview` | Lightweight progress snapshot  - analysis phase, note count, tool history count, and coverage percentage. |
| `list_tools_by_phase` | Browse available tools organised by analysis phase (triage, explore, deep-dive, context, utility). Helps discover the right tool for your current workflow stage. |
| `suggest_next_action` | Analyse current session state and recommend 3-5 specific next steps based on what has already been done and what remains unexplored. |
| `get_analysis_timeline` | Merge tool history with notes into a single chronological timeline. Paginated (default limit 20). |
| `export_project` | Export session (analysis + notes + history + optionally the binary) as `.arkana_project.tar.gz`. |
| `import_project` | Import a previously exported project archive. |

## Rename / Annotation Layer (6 tools)

Persistent function renames, variable renames, and address labels. Renames are automatically applied to decompilation and disassembly output. Persisted via cache alongside notes  - restored when the same binary is reopened.

| Tool | Description |
|---|---|
| `rename_function` | Assign a user-defined name to a function at a given address. The name is applied in `decompile_function_with_angr`, `batch_decompile`, and `get_function_map` output. |
| `rename_variable` | Rename a variable within a function scope. Applied in decompilation output for that function. |
| `add_label` | Add a labelled marker at a given address with a category (`general`, `ioc`, `crypto`, `c2`, `function`). Labels appear in `get_annotated_disassembly` output. |
| `list_renames` | List all renames and labels, optionally filtered by type (`functions`, `variables`, `labels`). |
| `delete_rename` | Remove a specific rename or label by address and type. |
| `batch_rename` | Bulk apply up to 50 renames/labels in a single call. Accepts a list of `{type, address, name, ...}` dicts. |

## Custom Types (5 tools)

User-defined structs and enums for parsing binary data. Struct field types reuse `parse_binary_struct` types (uint8-64 LE/BE, cstring, wstring, ipv4, bytes:N, padding:N). Persisted via cache.

**Validation guards:** Field names must match `[a-zA-Z_][a-zA-Z0-9_]*`. Enum values are checked against the declared byte size with duplicate detection. Cycle detection prevents recursive struct references. Padding bounds are 0–10 MB. Cstrings are decoded as UTF-8 with Latin-1 fallback.

| Tool | Description |
|---|---|
| `create_struct` | Define a named struct with typed fields. Validates field types against the `parse_binary_struct` schema. |
| `create_enum` | Define a named enum with name-to-integer mappings and a byte size. |
| `apply_type_at_offset` | Parse binary data at a file offset using a previously defined custom type. Supports parsing multiple consecutive instances via `count` parameter (max 100). |
| `list_custom_types` | List all defined structs and enums with their definitions. |
| `delete_custom_type` | Remove a type definition by name. |

## Context Aggregation (1 tool)

| Tool | Description |
|---|---|
| `get_analysis_context_for_function` | Aggregates comprehensive analysis context for a single function in one call: decompiled code, cross-references (callers/callees), suspicious API usage with risk levels, strings, notes, triage status, enrichment score, and complexity. Avoids calling 5-10 separate tools. |

## Dashboard-Exposed Analysis (3 tools)

Functions previously only accessible via the web dashboard, now available as MCP tools for AI clients.

| Tool | Description |
|---|---|
| `search_decompiled_code` | Full-text regex search across all cached decompiled function code. Finds specific code patterns, strings, or API calls without decompiling each function individually. Returns matching functions with line context. |
| `get_entropy_analysis` | Per-section and overall entropy analysis for the loaded binary. Detects packed/encrypted sections (high entropy >7.0) or empty sections (near-zero entropy). Optionally includes byte-level heatmap data. |
| `generate_report` | Generate a comprehensive markdown analysis report summarising findings, risk assessment, IOCs, function analysis, and timeline. Optionally saves to a file path. |

## Frida Script Generation (4 tools)

Generate ready-to-run Frida JavaScript instrumentation scripts from static analysis findings. No Frida dependency  - generates standalone `.js` code that can be used with `frida -l`.

| Tool | Description |
|---|---|
| `generate_frida_hook_script` | Generate a Frida hook script for specified API functions or hex addresses (up to 50 targets). Produces code that intercepts API calls, logs arguments/return values with type-aware formatting for 50+ common APIs, and captures backtraces. |
| `generate_frida_bypass_script` | Generate a Frida script that bypasses anti-debug techniques. Auto-detects anti-debug APIs from the binary's imports/triage data and generates targeted bypass code (IsDebuggerPresent, NtQueryInformationProcess, timing checks, PEB patches, etc.). |
| `generate_frida_trace_script` | Generate a Frida API tracing script based on the binary's import table. Identifies suspicious/interesting APIs and creates a comprehensive tracing script filterable by category (networking, crypto, injection, file_io, registry, etc.). |
| `generate_frida_stalker_script` | Generate specialised Frida DBI scripts: Stalker-based code coverage collection (drcov/JSON output), anti-VM detection bypass (registry/firmware/process/MAC hooks), process injection sequence detector (VirtualAllocEx→WriteProcessMemory→CreateRemoteThread monitoring), or structured API argument logger with type-aware resolution. |

## Code Coverage Import (2 tools)

Import and analyse code coverage data collected from external DBI tools (DynamoRIO, Frida Stalker, Intel PIN) to identify executed vs. uncovered code regions.

| Tool | Description |
|---|---|
| `import_coverage_data` | Import coverage from DynamoRIO drcov binary format, Frida/Lighthouse JSON, or CSV files. Overlays coverage onto the loaded binary's function map to show which functions were executed during dynamic analysis. |
| `get_coverage_summary` | Summarise imported coverage: coverage percentage, top uncovered functions (potential hidden functionality), and top covered functions. |

## Trace Analysis & MBA Detection (2 tools)

Analyse instruction traces and detect Mixed Boolean-Arithmetic (MBA) obfuscation patterns used by VM protectors like VMProtect and Themida.

| Tool | Description |
|---|---|
| `analyze_instruction_trace` | Import and analyse instruction traces in PIN, CSV, or JSON format. With Triton installed, applies symbolic execution to reconstruct simplified input-output expressions. Without Triton, computes trace statistics (instruction count, mnemonic frequency, unique addresses). |
| `detect_mba_obfuscation` | Scan decompiled pseudocode for MBA obfuscation patterns: XOR-via-NOT-AND-OR, algebraic identities, tautologies, double negation, and other redundant expressions used by VM protectors. Reports detected patterns with simplified forms. |

## Vulnerability Detection & Data Flow (4 tools)

Pattern-based vulnerability scanning, attack surface assessment, and dangerous data flow detection using decompiled code and call-graph analysis.

| Tool | Description |
|---|---|
| `scan_for_vulnerability_patterns` | Scan decompiled functions for 11 common vulnerability patterns: buffer overflows, format strings, command injection, memory corruption, integer overflows, path traversal, insecure crypto, hardcoded credentials, race conditions, DLL hijacking, and double-free. Filterable by severity and function address. |
| `assess_function_attack_surface` | Assess the attack surface of a specific function by analysing input sources, dangerous sinks, source-to-sink connectivity, reachability (caller count), and complexity. Produces a risk score from 0 to 100. |
| `find_dangerous_data_flows` | Trace data flow from input sources (recv, read, scanf, argv, etc.) to dangerous sinks (system, strcpy, sprintf, memcpy, WinExec, etc.) within individual functions. Uses RDA with structural fallback. For inter-procedural flows, use `trace_taint_flows`. |
| `trace_taint_flows` | Inter-procedural taint flow analysis — traces data from untrusted input sources (network, file, environment, registry, user input) to dangerous sinks (buffer copy, command execution, format strings, data exfiltration) across function call-chain boundaries. Three-phase analysis: structural BFS through the call graph, decompile-based argument flow validation, and optional per-function RDA for high-confidence results. Supports source/sink category filtering and automatic reverse tracing when targeting a sink function. |

## .NET Deobfuscation & Decompilation (3 tools)

Automated .NET deobfuscation via de4dot-cex and NETReactorSlayer, plus full C# source recovery via ILSpy. Requires the Docker image (tools are invoked as subprocesses).

| Tool | Description |
|---|---|
| `detect_dotnet_obfuscation` | Pure-Python obfuscation detection via dnfile metadata scanning. Identifies 10+ obfuscators by matching custom attributes, resource patterns, and name entropy: ConfuserEx, .NET Reactor, SmartAssembly, Dotfuscator, Babel .NET, Crypto Obfuscator, Agile.NET, Eazfuscator, Goliath.NET, Phoenix Protector, and generic obfuscation. |
| `dotnet_deobfuscate` | Orchestrate .NET deobfuscation via external tools. Supports four methods: `auto` (detect obfuscator and choose best tool), `de4dot` (handles ~20 obfuscators including ConfuserEx), `reactor_slayer` (.NET Reactor specialist), and `detect_only`. Outputs a cleaned binary registered as an artifact. |
| `dotnet_decompile` | C# source recovery via ILSpy CLI with pagination support. Two modes: stdout mode (returns paginated C# source lines, optionally filtered to a specific type) and project mode (writes `.csproj` + `.cs` files to a directory). |

## Anti-Analysis & Obfuscation Detection (3 tools)

Detect control flow obfuscation techniques commonly used by commercial protectors (OLLVM, Themida, VMProtect, Code Virtualizer) and malware packers.

| Tool | Description |
|---|---|
| `detect_control_flow_flattening` | Analyse a function's CFG for control flow flattening (CFF) hallmarks: single-entry dispatcher block with high in-degree, state variable driving a switch/if-else chain, and real basic blocks routing back to the dispatcher. Returns confidence score, dispatcher address, state variable identification, and affected block count. |
| `detect_opaque_predicates` | Identify always-true or always-false conditional branches using angr's constraint solver. Flags branches with only one feasible path, which are characteristic of dead-code insertions by obfuscators. Returns predicate locations with verdicts and solver confidence. |
| `detect_vm_protection` | Detect VMProtect/Themida/Enigma/Code Virtualizer protection via section names, entropy, imports, and string signatures. Returns protector-specific option detection (Themida: anti_debug/api_wrapping/vm_code/string_encryption; VMProtect: virtualization/mutation/import_protection), import obfuscation score (0.0-1.0), and protector-specific analysis recommendations. Does NOT require angr. |

## Learner Progress Tracking (4 tools)

These tools support the [learning skill](claude-code.md#learning-skill-for-claude-code), tracking learner progress across sessions. They are called automatically by the tutor but can also be invoked directly.

| Tool | Description |
|---|---|
| `get_learner_profile` | Retrieve the learner's progress profile  - current tier, concept mastery counts, module completion percentages, and session statistics. |
| `update_concept_mastery` | Record mastery of a concept at a given level (`introduced`, `practiced`, `understood`, `mastered`). Accepts optional notes. |
| `get_learning_suggestions` | Get personalised learning suggestions based on current mastery and optional focus area. Returns recommended modules, concepts to revisit, and next steps. |
| `reset_learner_profile` | Reset the learner profile to start fresh. Requires `confirm=true` to execute. |

---

## Known Tool Limitations

The following limitations have been identified through comprehensive testing. They are inherent to the underlying analysis frameworks or architectural constraints.

### Data Flow & Slicing

| Tool | Limitation |
|------|-----------|
| `get_data_dependencies` | Returns raw angr internal representations (`SimEngineRDVEX`, `LocalVariableTag` atoms). Output is useful for programmatic analysis but not human-readable summaries. Prefer `get_reaching_definitions` or `propagate_constants` for more interpretable results. |
| `get_backward_slice` / `get_forward_slice` | Returns CFG reachability (all blocks that *can* reach or *be reached from* a target), not true data-flow slices. The `variable` parameter selects the starting point but the slice follows control flow, not data dependencies. |
| `extract_function_constants` | Includes code addresses (call targets, branch destinations) alongside actual data constants. Filter by checking whether values fall within code section ranges. |

### Emulation & Unpacking

| Tool | Limitation |
|------|-----------|
| Qiling tools (`emulate_binary_with_qiling`, etc.) | Requires manual rootfs setup with real Windows DLLs. Use `qiling_setup_check()` to verify. See [QILING_ROOTFS.md](QILING_ROOTFS.md) for setup. |
| `auto_unpack_pe` / `try_all_unpackers` | FSG-packed binaries may fail to unpack with Unipacker. Use Qiling-based unpacking (`qiling_dump_unpacked_binary`) or manual OEP recovery as fallback. |
| Speakeasy / Qiling emulation | Complex packers with anti-emulation checks may cause emulation to stall or produce incomplete results. Timeouts and partial results are captured automatically. |
| Debug sessions (`debug_*` tools) | Emulation fidelity limitations apply  - anti-emulation techniques, threading, and complex Windows APIs may produce incorrect results or cause the session to stall. Watchpoints add per-instruction overhead. Snapshots (`ql.save()`/`ql.restore()`) may not fully capture complex hook or callback state. Max 3 concurrent sessions, 30-minute idle timeout. |
| Anti-VM bypass (`anti_vm_bypass=True`) | Defeats VM *detection* (CPUID hypervisor bit, RDTSC timing, VMware I/O port) but NOT code *virtualization* (custom bytecode interpreters used by VMProtect/Themida/Enigma). VM-protected binaries have 4 layers: (1) anti-VM detection → bypassed, (2) unpacking → partially handled, (3) code virtualization → NOT addressed, (4) original code. For Layer 3, use `generate_frida_stalker_script` to create scripts for real Windows execution, then `import_coverage_data`/`analyze_instruction_trace` to bring results back into Arkana. |

### External Dependencies

| Tool | Limitation |
|------|-----------|
| `get_virustotal_report_for_loaded_file` | Requires a VirusTotal API key. Configure with `set_api_key(key_name="vt_api_key", key_value="...")`. |
| `scan_for_embedded_files` | Requires binwalk v3+. Uses `--signature --quiet` flags for structured output. |

### Output & Response Limits

| Tool | Limitation |
|------|-----------|
| `analyze_batch` | The 8KB MCP response soft limit can truncate comparison data for large file sets. Use smaller `file_paths` lists (5-10 files) or filter by specific metrics. |
| `search_decompiled_code` | Searches angr-decompiled C pseudocode, not assembly mnemonics. For assembly-level search, use `get_annotated_disassembly(search="pattern")` on specific functions. |
| `refinery_list_units` | Returns a simplified category-level view of Binary Refinery's unit tree. Individual unit parameters are not listed — refer to Binary Refinery's documentation for detailed unit options. |

### Analysis Quality

| Tool | Limitation |
|------|-----------|
| `refinery_carve` / `refinery_extract_iocs` | May produce false positives when run on raw binary data (e.g. detecting Base64 patterns in code sections). Validate extracted IOCs against context. |
| `get_calling_conventions` | May return no results for simprocedures, library stubs, or very small functions. A diagnostic note is included when this occurs. |
| `get_dominators` | Returns empty results when the target address is the function entry point or doesn't correspond to a basic block boundary. Diagnostic notes explain the cause. |
