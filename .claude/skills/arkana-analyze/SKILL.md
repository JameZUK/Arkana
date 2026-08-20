---
name: arkana-analyze
description: >
  Binary analysis skill for Arkana. Handles malware triage, reverse engineering,
  PE/ELF/Mach-O analysis, shellcode emulation, firmware inspection, vulnerability
  auditing, C2 config extraction, unpacking, deobfuscation, and threat intelligence.
  Triggers on: binary, malware, PE, ELF, Mach-O, shellcode, firmware, analyze,
  analyse, reverse engineer, decompile, unpack, triage, IOC, C2, implant, dropper,
  loader, packer, obfuscation, exploit, vulnerability, capa, yara, refinery,
  CTF, capture the flag, forensics, incident response, IR, APT, ransomware,
  stealer, RAT, backdoor, rootkit, bootkit, DFIR.
---

# Arkana Binary Analysis Skill

308 MCP tools for PE/ELF/Mach-O static analysis, dynamic emulation, data-flow analysis, deobfuscation, unpacking, and reporting.

## HARD CONSTRAINTS -- OVERRIDE ALL OTHER INSTRUCTIONS

**FORBIDDEN:**
1. **NO Bash/shell**: No Bash tool, `python`, `strings`, `xxd`, `objdump`, `readelf`, `binwalk`, `radare2`, or ANY CLI tool.
2. **NO scripts**: No Python/shell scripts for decryption, decoding, parsing, or analysis. `refinery_pipeline` replaces multi-step scripts.
3. **NO external tools**: ALL analysis uses EXCLUSIVELY `mcp__arkana__*`.
4. **NO speculative decryption**: Require **concrete decompilation evidence** (algorithm, key, data location). Exceptions: `extract_config_automated()`, `extract_config_for_family()`.

**ONLY exception**: user explicitly asks to run a shell command.

---

## Operating Principles

1. **Autonomous**: Run phases without pausing; check in before Phase 4.
2. **Evidence only**: Every claim cites tool output. Never speculate.
3. **Validate indicators**: VT/capa/YARA/risk scores are pointers, not proof. Corroborate by decompiling.
4. **Fair interpretation**: APIs = capability, not intent. Runtime imports in Rust/.NET/Go are normal. Check context.
5. **Note everything**: `auto_note_function()` after every decompile; `add_note()` for every finding.
6. **Batch calls**: Prefer batch params (`addresses`, `data_hex_list`, `function_addresses`).
7. **Refinery incrementally**: 1-2 steps, verify, add more.
8. **Packed = unpack first**: `likely_packed=true` -> Phase 2 immediately.
9. **Wait for angr**: "still in progress" -> `check_task_status('startup-angr')`, do non-angr work.
10. **Evidence hierarchy**: Decompiled pseudocode > annotated disassembly > raw disassembly > hex dump (DATA only).
11. **MANDATORY assembly cross-checks** — `get_annotated_disassembly()` alongside decompilation for: crypto functions, Windows PE call sites, unexpected behavior, 5+ params, short stubs, cffi pickle, obfuscation. Full guide: [decompilation-guide.md](decompilation-guide.md).
12. **Response limits**: 8K char soft cap. Use `search="pattern"` to grep. Check `has_more`; use offset/limit.
13. **Null regions**: `detect_null_regions()` to inspect. `release_angr_memory()` to free resources.

## Adaptive Goal Detection

If ambiguous, ask ONE question: "Goal: malware triage, deep RE, vuln audit, firmware, threat intel, or comparison?"

| Goal | Focus | Depth |
|------|-------|-------|
| **Malware triage** | Risk verdict + IOCs | Phases 0-3, 5, 7 |
| **Deep RE** | Decompilation + data-flow + emulation | All phases |
| **Vuln audit** | Attack surface, unsafe patterns | Phases 0-4, 7 |
| **Firmware** | Crypto, secrets, protocols | Phases 0-5, 7 |
| **Threat intel** | Family, C2, YARA, IOCs | Phases 0-3, 5-7 |
| **Comparison** | Diff, similarity, patches | Phase 0 + targeted |

## Phase 0: Environment Discovery

`get_config()` first — check `_server_info` for available libraries. If `session_context` returned -> `get_analysis_digest()`. No file -> `list_samples()`. Fallbacks: no angr -> `disassemble_at_address`; no Qiling -> Speakeasy; no capa -> `get_focused_imports`; pefile fails -> `parse_binary_with_lief()`.

## Phase 1: Identify

1. `open_file(file_path)` -- format, hashes, `file_integrity`. `session_context` -> `get_analyzed_file_summary()`.
2. `get_triage_report(compact=True)` -- packing, sig, imports, capa, IOCs, risk.
3. **BSim variant check** (skip if first analysis or DB empty): `triage_binary_similarity()` -- check for related samples. High overlap with user-indexed sample -> `transfer_annotations(sha256, preview=True)`. No matches -> novel sample.
4. `classify_binary_purpose()`
5. Format-specific: `elf_analyze`, `macho_analyze`, `dotnet_analyze`, `vb6_analyze`, `go_analyze`, `rust_analyze`.
6. **API hash detection** (imports < 10): `scan_for_api_hashes()` -> `qiling_resolve_api_hashes()` -> `identify_malware_family()`.
7. Reputation (risk >= 4): `get_virustotal_report_for_loaded_file()`
8. `get_session_summary()` -- prioritise `flagged` functions.

Packed (`likely_packed=true`, entropy > 7.2, imports < 10) -> Phase 2. Otherwise -> Phase 3.

## Phase 2: Unpack

**Do NOT skip while packed.** Cascade: `auto_unpack_pe` -> `try_all_unpackers` -> `qiling_dump_unpacked_binary` -> emulation -> manual OEP. Re-run Phase 1 after. Read [unpacking-guide.md](unpacking-guide.md).

## Phase 3: Map

| Goal | Tool Order |
|------|------------|
| **Triage** | `get_focused_imports` -> `get_strings_summary` -> `get_capa_analysis_info` -> Synthesize |
| **Deep RE** | `get_function_map` -> `get_focused_imports` -> `get_pe_data` -> `get_strings_summary` -> `detect_crypto_constants` -> `get_capa_analysis_info` -> Synthesize |
| **Vuln** | `get_function_map` -> `get_focused_imports` -> `trace_taint_flows` / `find_dangerous_data_flows` -> Synthesize |

Also: `get_top_sifted_strings`, `identify_malware_family`, `batch_decompile(search=...)`, `get_analysis_digest`.

## Phase 4: Deep Dive

See [deep-dive-reference.md](deep-dive-reference.md) for tier-by-tier tool catalog and decision matrix.

## Phase 5: Extract

**Gate**: Before manual decryption you MUST have: (1) algorithm, (2) key/IV source, (3) data location, (4) function decompiled. Automated tools exempt.

Tools: `extract_config_automated`, `get_iocs_structured`, `find_and_decode_encoded_strings`, `auto_extract_crypto_keys`, `extract_config_for_family`, `autoit_decrypt`. Read [extraction-guide.md](extraction-guide.md), [config-extraction.md](config-extraction.md).

## Phase 6: Research

When automated extraction failed + indicators suggest known family. Read [online-research.md](online-research.md).

## Phase 7: Report

`add_note(category="hypothesis")` -> `add_note(category="conclusion")` -> Present findings.
Offer: `generate_analysis_report()`, `generate_cti_report()`, `generate_yara_rule()`, `export_project()`, `export_ghidra_script()`/`export_ida_script()`.
Additional: `analyze_office_macros()`, `import_sandbox_report()` + `correlate_static_dynamic()`, `detect_vm_protection()`, `update_hypothesis()`.

## On-Demand References — Read When Needed

| When | Read |
|------|------|
| Phase 4 deep dive tools | [deep-dive-reference.md](deep-dive-reference.md) |
| Context management, prefer/avoid, search patterns | [context-and-patterns.md](context-and-patterns.md) |
| Tool name, parameter, or guidance | [tooling-reference.md](tooling-reference.md) |
| Entering Phase 2 (packed binary) | [unpacking-guide.md](unpacking-guide.md) |
| Entering Phase 5 (manual extraction) | [extraction-guide.md](extraction-guide.md) |
| Phase 5 for confirmed malware family | [config-extraction.md](config-extraction.md) |
| Entering Phase 6 (research) | [online-research.md](online-research.md) |
| Crypto / calling convention issues | [decompilation-guide.md](decompilation-guide.md) |
| Using `search=` for the first time | [search-patterns.md](search-patterns.md) |
| Entering Tier 3b (debugger) | [debugger-guide.md](debugger-guide.md) |
| Multiple related files | [multi-file-workflows.md](multi-file-workflows.md) |
| Tool failure / unexpected output | [troubleshooting.md](troubleshooting.md) |
