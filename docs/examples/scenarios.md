# Real-World Scenarios & Comparisons

These scenarios demonstrate Arkana's combined power across its tool categories. Each represents a common analysis task that traditionally requires multiple disconnected tools.

---

## Scenario 1: Triaging a Suspicious Email Attachment (2 minutes vs 30+)

**The situation:** A SOC analyst receives an alert about a suspicious `.doc` attachment. They need to determine if it's malicious and extract any IOCs.

**Traditional workflow:** Open in a sandbox VM, use `olevba` to extract macros, manually read VBA code, use CyberChef to decode Base64 payloads, use `strings` to find URLs, check hashes on VirusTotal  - switching between 5+ tools.

**With Arkana:**
```
Analyst: "Open this Office document and tell me if it's malicious"
```
Arkana automatically:
1. `open_file("attachment.doc")`  - detects OLE format
2. `get_triage_report(compact=True)`  - instant risk assessment
3. `refinery_extract(operation='office', sub_operation='vba')`  - extracts VBA macros
4. `refinery_deobfuscate_script(script_type='vba')`  - deobfuscates the macro code
5. `refinery_extract_iocs()`  - pulls URLs, IPs, domains from the deobfuscated script
6. `refinery_carve(operation='pattern', pattern='b64')`  - finds and decodes Base64 payloads
7. `get_virustotal_report_for_loaded_file()`  - checks community detection

The AI cross-references all findings: *"This document contains an obfuscated VBA macro that downloads a second-stage payload from hxxps://evil[.]com/payload.exe using PowerShell. The macro uses string concatenation and Chr() calls to evade static detection. Three unique C2 URLs were extracted."*

---

## Scenario 2: Extracting C2 Configuration from a Packed .NET RAT

**The situation:** A malware analyst has a .NET sample suspected to be AsyncRAT. The binary is packed and the C2 configuration is encrypted in string constants.

**Traditional workflow:** Use `de4dot` to deobfuscate, load in `dnSpy` to find the config class, manually identify the decryption routine, write a Python script to replicate the decryption, extract the C2 address  - a process that can take 1-2 hours.

**With Arkana:**
```
Analyst: "Analyse this .NET binary and extract the C2 configuration"
```
Arkana orchestrates:
1. `open_file("sample.exe")`  - detects .NET assembly
2. `dotnet_analyze()`  - extracts CLR metadata, type/method definitions
3. `refinery_dotnet(operation='strings')`  - extracts all .NET metadata strings
4. `refinery_dotnet(operation='fields')`  - extracts constant field values (where RATs store encrypted configs)
5. `refinery_dotnet(operation='arrays')`  - extracts byte array initialisers (AES keys, encrypted blobs)
6. `refinery_dotnet(operation='resources')`  - checks for config stored in resources
7. `refinery_decrypt(algorithm='aes', key_hex='...', iv_hex='...')`  - decrypts the config using extracted key material
8. `refinery_extract_iocs()`  - extracts C2 URLs, ports, and mutex names from decrypted config

The AI correlates field names with known AsyncRAT config patterns: *"This is AsyncRAT v0.5.7B. The C2 server is 192.168.1[.]100:8808, with a backup at evil-c2[.]com:443. The mutex is 'AsyncMutex_6SI8OkPnk'. The AES-256 key was found in the Settings.Key field and the encrypted config was stored in Settings.Host, Settings.Port, and Settings.Pastebin fields."*

---

## Scenario 3: Analysing a Multi-Stage Dropper with Shellcode

**The situation:** A threat intel analyst has a PE dropper that unpacks multiple stages. Stage 1 is a packed PE, Stage 2 is XOR-encrypted shellcode in the overlay, and Stage 3 is a DLL downloaded to memory.

**With Arkana:**
```
Analyst: "This looks like a multi-stage dropper. Help me unpack each stage."
```
Arkana chains operations:
1. `open_file("dropper.exe")`  - parses PE, background CFG starts
2. `get_triage_report()`  - identifies high entropy sections, overlay data, suspicious imports (`VirtualAlloc`, `WriteProcessMemory`)
3. `detect_packing()`  - confirms UPX packing on Stage 1
4. `auto_unpack_pe()`  - unpacks Stage 1 via Un{i}packer
5. `refinery_pe_operations(operation='overlay')`  - extracts Stage 2 from overlay
6. `refinery_xor(operation='guess_key')`  - auto-detects the XOR key used on Stage 2
7. `refinery_xor(operation='apply', key_hex='...')`  - decrypts Stage 2 shellcode
8. `refinery_executable(operation='disassemble')`  - disassembles the decrypted shellcode
9. `emulate_shellcode_with_speakeasy()`  - emulates the shellcode to capture API calls and network activity
10. `refinery_extract_iocs()`  - extracts the Stage 3 download URL from emulation output

Each stage's findings are recorded with `auto_note_function()` and `add_note()`, so `get_analysis_digest()` provides a complete picture at any time.

---

## Scenario 4: Investigating a Go Binary on Linux

**The situation:** An IR team recovers a suspicious ELF binary from a compromised Linux server. It's a stripped Go binary with no symbols.

**With Arkana:**
```
Analyst: "Analyse this Linux binary  - it might be a backdoor"
```
1. `open_file("suspicious_elf")`  - auto-detects ELF format
2. `elf_analyze()`  - ELF headers, sections, segments, dynamic deps
3. `go_analyze()`  - recovers Go compiler version, packages, and function names from `pclntab` (works on stripped binaries)
4. `get_triage_report()`  - ELF-specific security checks (PIE, NX, RELRO, stack canaries)
5. `decompile_function_with_angr(address)`  - decompile suspicious functions identified by package names
6. `refinery_extract_iocs()`  - extract hardcoded IPs, domains, URLs
7. `get_capa_analysis_info()`  - map capabilities to MITRE ATT&CK (file manipulation, process injection, network communication)

The AI recognises Go package names like `net/http`, `os/exec`, `crypto/tls` and correlates them with the decompiled functions: *"This is a Go-based reverse shell (compiled with Go 1.21.4). It establishes a TLS connection to C2 at 10.0.0[.]50:4443, receives commands via HTTP POST, and executes them via os/exec. It also has file exfiltration capabilities via the archive/zip package."*

---

## Scenario 5: Bulk IOC Extraction from a Forensic PCAP

**The situation:** An incident responder has a PCAP capture from a compromised network segment and needs to extract all malicious indicators.

**With Arkana:**
```
Analyst: "Extract all IOCs and embedded files from this PCAP"
```
1. `refinery_forensic(operation='pcap')`  - reassembles TCP streams, identifies protocols
2. `refinery_forensic(operation='pcap_http')`  - extracts HTTP transactions with URLs, methods, and response bodies
3. `refinery_extract(operation='embedded')`  - auto-detects embedded PE files, ZIPs, scripts in the extracted streams
4. `refinery_extract_iocs()`  - extracts all URLs, IPs, domains, email addresses, hashes
5. `refinery_forensic(operation='defang')`  - defangs all IOCs for safe sharing in reports

For each carved PE file, the analyst can immediately:
```
Analyst: "Open this carved PE and analyse it"
```
6. `open_file(carved_pe)` → `get_triage_report()` → `get_focused_imports()` → full analysis chain

---

## Scenario 6: Reversing a Custom Cipher in a Chinese APT RAT (ValleyRAT)

**The situation:** A threat intel analyst has a UPX-packed sample suspected to be ValleyRAT. The payload is hidden behind 5 layers of encryption including a custom block cipher. The C2 configuration is stored with reversed-string obfuscation.

**Traditional workflow:** Unpack UPX in PE-bear, load DLL in IDA/Ghidra, trace the config decryption manually through 4 transforms, identify the custom cipher algorithm by reading assembly, reimplement in Python, decrypt the inner PE, load it in a new IDA session, find the C2 config string, manually reverse the obfuscation — a multi-day effort requiring expert-level reverse engineering.

**With Arkana (multi-session):**

*Session 1 — Unpack and identify the payload:*
```
Analyst: "Analyse this binary and extract any embedded payloads"
```
1. `open_file("valleyrat.exe")` — detects UPX packing
2. `auto_unpack_pe()` — unpacks to PE64 DLL
3. `open_file("unpacked.dll")` — analyses the DLL
4. `get_triage_report()` — identifies suspicious imports, high-entropy sections
5. `decompile_function_with_angr(config_func)` — reveals the 4-step decryption pipeline
6. `refinery_codec(codec='b64')` + `refinery_xor(key='be')` — decodes the config blob

*Session 2 — Reverse the shellcode loader:*
```
Analyst: "The config decrypts to shellcode. Analyse the shellcode and find the inner PE."
```
7. `open_file("shellcode.bin", mode="shellcode")` — loads shellcode for analysis
8. `disassemble_raw_bytes()` — identifies PEB-walking reflective loader
9. `decompile_function_with_angr(decrypt_func)` — reveals custom ARX-CTR cipher
10. Custom Python decryption (non-standard cipher — one of the few cases requiring custom code)
11. `search_hex_pattern(pattern="4D5A")` — locates the inner PE at offset 0x104C

*Session 3 — Extract C2 from the inner PE:*
```
Analyst: "Load the extracted PE and find the C2 configuration"
```
12. `open_file("inner_pe.bin")` — full PE analysis with capa, YARA, FLOSS
13. `get_triage_report()` — CRITICAL risk, process injection, anti-debug
14. `extract_wide_strings()` — discovers reversed C2 config at offset 0x1DE40
15. `get_hex_dump(offset=0x1DE00)` — confirms config structure with key templates
16. `search_for_specific_strings(["tracerpt", "IpDate", "SOFTWARE"])` — finds persistence IOCs

The AI decodes the reversed config: *"C2 server is 8.136.41[.]104:3323 (Alibaba Cloud). Campaign group is 默认 ('default' in Chinese). Build date 2025-12-04. Config keys use pinyin abbreviations confirming Chinese-language development. The shellcode patches AMSI, ETW, and WLDP before loading the implant."*

**Full report:** [ValleyRAT Multi-Stage Loader](example-report-valleyrat.md)

---

## Scenario 7: Unpacking and Extracting C2 Config from Brute Ratel C4

**The situation:** A threat hunter has a suspected Brute Ratel C4 packed loader. The sample resolves all APIs dynamically via hash-based resolution, making automated triage tools report almost no suspicious indicators. The C2 configuration is RC4-encrypted with a key derived from the decrypted payload itself.

**Traditional workflow:** Load in IDA/Ghidra, manually trace the PIC shellcode bootstrap through self-injection, identify the RC4 decryption routine, determine the key (last 8 bytes of encrypted payload), decrypt the 245KB payload, patch the zeroed MZ header, load the unpacked DLL in a new session, trace the config parser, determine the second RC4 key (derived from the decrypted payload's tail), decrypt the config blob — easily a multi-day effort requiring deep x64 shellcode analysis skills.

**With Arkana (multi-session):**

*Session 1 — Analyse the packed loader:*
```
Analyst: "Analyse this binary — it's suspected Brute Ratel C4"
```
1. `open_file("bruteratel.exe")` — PE64 DLL with export name `badger_x64_wait.bin.packed.dll`
2. `get_triage_report()` — CRITICAL risk, only 3 meaningful imports (FreeConsole, GetModuleHandleW, GetProcAddress)
3. `get_pe_data()` — .data section has 0x3D600 bytes of high-entropy data (encrypted payload)
4. `decompile_function_with_angr(DllMain)` — reveals self-injection pattern (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread with handle -1)
5. `get_hex_dump(offset=0x1A00)` — maps .data section layout: PIC shellcode + encrypted config blob + encrypted payload + loader stub

*Session 2 — Unpack the badger payload:*
```
Analyst: "Try dynamic unpacking to extract the payload"
```
6. `emulate_pe_with_windows_apis()` — 0 API calls (PEB walking bypasses hooks)
7. `emulate_shellcode_with_speakeasy()` — 0 API calls (indirect syscalls bypass emulation)
8. `disassemble_raw_bytes()` — traces PIC shellcode: identifies RC4 KSA with `AND EAX, 7` (8-byte key), key = last 8 bytes of encrypted data
9. Custom Python RC4 decryption on host + MZ magic patch → `bruteratel_unpacked.dll`

*Session 3 — Extract C2 configuration from unpacked badger:*
```
Analyst: "Load the unpacked badger and extract the C2 config"
```
10. `open_file("bruteratel_unpacked.dll")` — 936 functions, 14 capa rules (RC4 KSA, HTTP, anti-VM)
11. `decompile_function_with_angr(0x100071b0)` — entry point: FreeConsole, CreateThread to worker
12. `decompile_function_with_angr(0x10007bf0)` — worker: copies 8-byte key from struct, calls config parser
13. `decompile_function_with_angr(0x10007f70)` — config parser: RC4 decrypt then split by pipe delimiter (27 fields)
14. `decompile_function_with_angr(0x10004b10)` — RC4 function: default key `{-l," +r3/#~&;v_`, 8-byte override
15. `disassemble_raw_bytes()` — traces PIC decryptor: `LEA RAX, [R11+RBX-0x10]` saves pointer to last 16 bytes of decrypted payload for config key
16. Custom Python: RC4 decrypt 403-byte config blob with key `7a3e24647a292175` → 5 C2 domains, auth tokens, URI paths, license hash

The AI maps the full execution chain: *"BRc4 badger with 5 C2 domains (2 via Tyk API gateways in US/EU, 3 direct), HTTPS/443 with JSON beacons. Auth tokens 6J1D1M4P9A57JGC2/LDTPTF78OUCCVQ0I, URI paths /api/azure and /content.php. Config RC4 key derived from the last 16 bytes of the decrypted payload — a two-key scheme where the packer appends the config key to the payload."*

**Full report:** [Brute Ratel C4 Badger Implant](example-report-bruteratel.md)

---

## Scenario 8: Cracking a Neural Network Password Lock (Ternary Trap)

**The situation:** A reverse engineer is presented with a CTF crackme (difficulty 4.0/6.0) that encodes its password inside the weights of a neural network. The binary loads a companion `model.nli` file containing a custom-format encrypted model. There is no string comparison, no hash comparison, and no flag string in the binary — the password exists only as the deterministic output of the network.

**Traditional workflow:** Load in Ghidra/IDA, reverse the file format, write a custom parser in Python, implement the neural network forward pass, then brute-force or mathematically solve for the password. Requires deep understanding of both reverse engineering and machine learning. Easily a multi-day effort.

**With Arkana:**
```
Analyst: "Find a new tricky crackme and go ahead and crack it"
```
Arkana autonomously:
1. Searches crackmes.one, downloads "Ternary Trap" (difficulty 4.0)
2. `open_file("PolyMLP.exe")` — identifies as MSVC C++ x64 console app
3. `get_triage_report` + `search_floss_strings` — discovers "Neural Password Lock", NLI2 format, "password is encoded in neural weights"
4. `get_function_map` → identifies model loader, inference engine, main loop
5. `decompile_function_with_angr` (4 pages, 449 lines) — maps the complete validation flow: load model → evaluate probability → generate chars → check sum
6. `get_annotated_disassembly(search="movsx.*byte|cvtsi2")` — discovers the critical `cvtdq2pd` instruction hidden by the decompiler, revealing that byte weights are converted to float64
7. Switches to `model.nli` via `open_file(mode='shellcode')` → `get_hex_dump` reads first bytes `90 E1 F7 DD`
8. Derives XOR key: `0x90⊕0x4E = 0xDE`, `0xE1⊕0x4C = 0xAD`, `0xF7⊕0x49 = 0xBE`, `0xDD⊕0x32 = 0xEF` → key is `0xDEADBEEF`
9. `refinery_xor` decrypts header and footer — extracts V=28, K=5, H=512, ternary weights, character map, checksums
10. Builds a Python solver implementing the 2-layer MLP with DFS search
11. Solver finds password `3ig3nv4lu3` ("eigenvalue" in leet) → generates `VALID` (sum 368 ✓) → flag `NLI{w31ghts_4r3_th3_k3y}` (sum 2184 ✓)

The AI identifies the float32-vs-int32 bias bug mid-solve, recognises `0xBF800000` as IEEE 754 -1.0, and corrects the model parser — a debugging step that would stump many analysts unfamiliar with floating-point representations.

**Full report:** [Ternary Trap Neural Crackme](example-report-ternary-trap.md)

---

## Scenario 9: Reversing a Go-Compiled Stealer with Zero Static IOCs (ACRStealer)

**The situation:** A threat intelligence analyst pulls a fresh ACRStealer sample from Malware Bazaar — uploaded the same day. It's a Go-compiled PE32 with an invalid code signing certificate, tagged as dropped by RenPyLoader. The analyst needs to extract C2 infrastructure and understand the delivery mechanism. The catch: the sample contains **zero plaintext IOCs** — no URLs, no domains, no browser paths, no C2 strings anywhere in 9,071 extracted strings.

**Traditional workflow:** Load in Ghidra/IDA (30+ minutes for Go binary auto-analysis), manually identify the 1,651 Go functions, try to find `main.main` in the sea of runtime functions, reverse the custom encryption, write a Python decryptor, extract and analyse the decrypted payload. Go binaries are notoriously difficult — position-independent code, goroutine prologues, and interleaved runtime functions make manual analysis a multi-day effort.

**With Arkana:**
```
Analyst: "Find a complex malware sample on Malware Bazaar and analyse it"
```
Arkana autonomously:
1. Queries Malware Bazaar API, selects an ACRStealer sample with interesting properties (Go binary, signed, multi-stage)
2. `open_file` → `get_triage_report` — CRITICAL risk (56), 6 capa crypto detections, PEiD packing flags, signed but invalid cert
3. `go_analyze` — parses gopclntab: Go 1.20+, 1,651 functions, 193 packages, discovers obfuscated module names (Certain, Brain, Document, Bind, Bleak, Box, Actual)
4. `parse_authenticode` — certificate from `new-pay.heleket.com`, Let's Encrypt E8, issued 23 days prior
5. `get_strings_summary` + `search_for_specific_strings` — confirms zero IOCs across all 9,071 strings; identifies statically-linked DLLs (ws2_32, dnsapi, crypt32, etc.)
6. `get_capa_rule_match_details` — locates AES-NI and RC4 PRGA match addresses, then **disproves** them as Go runtime internals (AES-NI for map hash randomisation, RC4 pattern matched a varint decoder)
7. `get_entropy_analysis` — reveals 320 KB high-entropy blob (7.4–7.8) in .rdata starting at `0xDB000`
8. `brute_force_simple_crypto(known_plaintext="https://")` — recovers first 8 XOR bytes, confirming the blob starts with "https://" but isn't simple XOR
9. `emulate_pe_with_windows_apis` — captures 0 API calls, confirming PEB-walking evasion
10. `search_hex_pattern("F1 FF FF FF 00 00")` — locates Go pclntab magic at `0x129458`, parses header (1,651 functions, 178 files)
11. `search_hex_pattern("9A F6 00 00")` — finds the funcdata entry for "main.main" via its nameOff, extracts entryOff `0x80930` → **main.main at VA `0x481930`**
12. `decompile_function_with_angr("0x481930")` — reveals the orchestration: copies 80,565 bytes from global `g_4db981`, calls `decrypt_payload(0x482980)` with key `0x115C4`, then VirtualAlloc's RWX memory
13. `decompile_function_with_angr("0x482980")` — **fully reverses the 5-stage custom cipher**:
    - Stage 1: Modular substitution (even bytes: `-= key%53 + i*17`, odd bytes: `^= (i*31) ^ key%97`)
    - Stage 2: Full array reversal
    - Stage 3: Adjacent byte pair swap
    - Stage 4: Subtract `key>>8` from each byte
    - Stage 5: XOR each byte with `key&0xFF ^ index`
14. Identifies compiler magic-number optimisations (`1296593901 * x >> 36` = `x / 53`, `1416896428 * x >> 37` = `x / 97`)
15. `generate_yara_rule` + `generate_cti_report` + `get_iocs_structured` + `map_mitre_attack` — produces detection rule, CTI report, structured IOCs, and ATT&CK Navigator layer

The AI concludes: *"This Go binary is a multi-stage loader, not the stealer itself. The actual ACRStealer capabilities — browser credential theft, Dead Drop Resolver C2 via Steam/Google Docs, data exfiltration — reside in the encrypted payload executed from RWX memory. The C2 IP 77.238.236.29 (from Malware Bazaar intelligence) is in the second-stage payload, not the Go loader."*

**Full report:** [ACRStealer Go Loader](example-report-acrstealer.md)

---

## Scenario 10: Peeling a 3-Layer Stealer — AES + UPX + Go (SalatStealer)

**The situation:** A threat intelligence analyst pulls a fresh SalatStealer sample from Malware Bazaar — uploaded the same day, tagged UNIQ (never seen before). It's a 4.8 MB PE32+ console application with a 4.6 MB `.data` section at entropy 8.0 (maximum). The analyst needs to determine what the binary does and extract IOCs, but all the interesting functionality is buried behind multiple protection layers.

**Traditional workflow:** Load in IDA/Ghidra (minutes to analyse the x64 loader), reverse the AES decryption manually, write a Python script to decrypt, discover UPX packing, install UPX tool to decompress, load the 12.9 MB Go binary in a new IDA session (30+ minutes for Go analysis), manually identify stealer targets across thousands of Go functions. Realistically a **multi-day effort** requiring expertise in x64 RE, cryptography, PE packing, and Go binary analysis.

**With Arkana:**
```
Analyst: "Find a new malware sample on MalwareBazaar and analyse it"
```
Arkana autonomously:
1. Queries Malware Bazaar API, selects a same-day SalatStealer sample (GCleaner dropper, UNIQ tag)
2. `open_file` → `get_triage_report` — CRITICAL risk (70), entropy 8.0, AES S-box + inverse S-box detected, 6x CPUID VM detection
3. `get_function_map` → identifies `sub_140001000` (dropper: VirtualAlloc, CreateProcessA, Sleep) and `sub_140002020` (admin check)
4. `decompile_function_with_angr` on 9 key functions — fully maps the loader: admin check → UAC bypass → dual-method Defender exclusion → AES decrypt → drop → execute → self-clean
5. `get_hex_dump` at `.data` offsets → extracts AES-256 key (`efd1...86f7`), IV (`480e...dc14`), and payload boundaries
6. `refinery_pipeline(steps=["aes:KEY:CBC:IV:padding=pkcs7"])` → **decrypts the 3.6 MB payload in one call** — result starts with `MZ...PE...UPX0, UPX1, UPX2`
7. Opens the decrypted PE → identifies UPX 5.02 with LZMA (method byte 0x0E from pack header)
8. Disassembles UPX stub → extracts LZMA params (lc=3, lp=0, pb=2, dict=2^24, sz_unc=12,911,501)
9. Manually reconstructs LZMA header and decompresses → 12.9 MB Go binary with `Go build ID` at offset 0x72
10. `search_hex_pattern` on the 12.9 MB dump → finds `Login Data`, `cookies.sqlite`, `key4.db`, `DiscordTokens.txt`, `TelegramDesktop`, 23+ wallet names, `salat/screenshot.Capture`, `salat/main.go`, `taskkill /F /PID`, `SELECT a11, a102 FROM nssPrivate`
11. Maps the full Go module structure: `salat/main.go`, `salat/funcs.go`, `salat/sets.go`, `salat/task.go`, `salat/screenshot/`
12. Discovers advanced techniques: LSASS dump attempt, Task Scheduler persistence (capnspacehook/taskmaster), DoH C2 resolution, PBKDF2 Chrome decryption
13. `generate_cti_report` + `generate_yara_rule` — produces shareable report with 15 MITRE ATT&CK techniques and detection rule

The AI concludes: *"This is a 3-layer matryoshka: MSVC x64 loader → UPX 5.02 LZMA → Go stealer (package 'salat/'). The loader disables Defender via dual methods (registry + PowerShell), then AES-256-CBC decrypts and executes the stealer. The Go payload targets 16 browsers, 23+ crypto wallets, Telegram, Discord, Steam, attempts LSASS credential dump, captures screenshots, and uses DNS-over-HTTPS for stealthy C2 resolution."*

**Full report:** [SalatStealer 3-Layer Info Stealer](example-report-salatstealer.md)

---

## Arkana vs Traditional Tools

### Comparison Matrix

| Capability | Arkana | Ghidra | IDA Pro | pestudio | CyberChef | Binary Refinery CLI |
|---|---|---|---|---|---|---|
| **PE/ELF/Mach-O parsing** | 308 tools, auto-detect | Plugin-based | Plugin-based | PE only | No | No |
| **Decompilation** | Angr (auto, all archs) | Ghidra Decompiler | Hex-Rays ($$$) | No | No | No |
| **Symbolic execution** | Angr (automated) | Limited (Ghidra scripts) | No | No | No | No |
| **Data transforms** | 200+ via Binary Refinery | Manual scripting | Manual scripting | No | 300+ (manual) | 200+ (CLI) |
| **String analysis** | FLOSS + StringSifter ML ranking | Built-in (basic) | Built-in (basic) | Basic | No | Basic |
| **Signature scanning** | YARA + Capa + PEiD | YARA (plugin) | FLIRT signatures | Signatures | No | No |
| **Emulation** | Speakeasy + Qiling + Angr | Emulator (limited) | No | No | No | No |
| **AI reasoning** | Native (MCP protocol) | No | No | No | No | No |
| **Session persistence** | Notes + history + cache | Project files | IDB files | No | No | No |
| **Learning curve** | Natural language | Months | Months | Low | Moderate | Moderate |
| **Cost** | Free & open source | Free | $1,800+/year | Free | Free | Free |
| **Tool count** | 308 tools | Plugins | Plugins | 50+ | 300+ | 200+ |

### How Arkana Complements (Not Replaces) Existing Tools

Arkana is not meant to fully replace Ghidra or IDA Pro  - those tools remain essential for deep interactive reverse engineering sessions where you need to manually rename variables, annotate code, and navigate complex control flow graphs in a visual GUI. Instead, Arkana excels in different parts of the analysis lifecycle:

**Where Arkana excels over Ghidra/IDA:**
- **Speed of initial triage**  - Arkana produces a comprehensive risk assessment in seconds. Ghidra takes 30+ seconds just to load and auto-analyse a binary, and IDA's auto-analysis can take minutes on large files.
- **Automated IOC extraction**  - Arkana extracts URLs, IPs, domains, hashes, and file paths automatically. In Ghidra/IDA, this requires custom scripts or manual searching.
- **Data transformation chains**  - Decoding nested Base64 → XOR → zlib payloads is a single `refinery_pipeline` call. In Ghidra, you'd write a Jython script. In IDA, an IDAPython script. In CyberChef, you'd manually build a recipe.
- **Cross-tool correlation**  - Arkana's AI automatically connects findings: "The XOR key found in the .rdata section matches the key used to decrypt the config extracted from the .NET resources." No other tool does this automatically.
- **Multi-format support in one interface**  - Analyse PE, ELF, Mach-O, .NET, Go, and Rust binaries without switching tools or learning different workflows.
- **Accessibility**  - A junior analyst can ask "What does this function do?" and get an explanation. In Ghidra, they'd need to understand the decompiler output themselves.

**Where Ghidra/IDA still excel:**
- **Interactive visual navigation**  - Ghidra's graph view, cross-reference browser, and function call trees are unmatched for manual code exploration.
- **Type reconstruction**  - IDA's Hex-Rays decompiler produces higher-fidelity C pseudocode with better type propagation than Angr's decompiler.
- **Plugin ecosystems**  - Ghidra has GhidraScript/Pyhidra, IDA has IDAPython  - mature scripting for custom analysis workflows.
- **Debugging**  - Both support live debugging. Arkana is static/emulation-only.

**The ideal workflow combines both:**
1. **Arkana for triage and automated analysis**  - Get the risk assessment, extract IOCs, identify interesting functions, decode obfuscated data.
2. **Ghidra/IDA for targeted deep-dives**  - When Arkana identifies a critical function (e.g., "the decryption routine at 0x00401230"), open the binary in Ghidra to manually trace the algorithm and reconstruct data structures.

### Arkana vs CyberChef / Binary Refinery CLI

CyberChef and Binary Refinery's command-line interface are powerful data transformation tools, but they require the analyst to know *which* transforms to apply and in *what order*. Arkana wraps Binary Refinery's 200+ units behind an AI that can reason about the data:

- **CyberChef**  - Browser-based, visual recipe builder. Great for known transform chains but requires manual operation selection. No binary analysis, no PE parsing, no decompilation.
- **Binary Refinery CLI**  - Powerful pipe-based transforms (`data | b64 | xor[0x41] | zl`). Requires command-line expertise and knowledge of unit names. No AI reasoning.
- **Arkana**  - Wraps Binary Refinery into 23 context-efficient MCP tools, adds AI reasoning, and combines with PE parsing, decompilation, emulation, and signature scanning. The AI can look at encrypted data, hypothesise the encryption scheme, try `refinery_xor(operation='guess_key')`, and if that fails, try `refinery_auto_decrypt()`, all without the analyst knowing which specific refinery units to use.
