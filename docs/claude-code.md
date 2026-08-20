# Using Arkana with Claude Code

Arkana integrates seamlessly with [Claude Code](https://docs.anthropic.com/en/docs/claude-code) via stdio transport. This guide covers setup, configuration, the analysis skill, and typical workflows.

---

## Adding Arkana via the CLI

The fastest way to add Arkana to Claude Code is with the `claude mcp add` command.

**Add to the current project (recommended):**

```bash
claude mcp add --scope project arkana -- python /path/to/Arkana/arkana.py --mcp-server --samples-path /path/to/samples
```

**Add with a VirusTotal API key:**

```bash
claude mcp add --scope project -e VT_API_KEY=your-key-here arkana -- python /path/to/Arkana/arkana.py --mcp-server --samples-path /path/to/samples
```

**Add globally for all projects (user scope):**

```bash
claude mcp add --scope user arkana -- python /path/to/Arkana/arkana.py --mcp-server
```

**Add with `--brief-descriptions` to reduce context window usage:**

```bash
claude mcp add --scope project arkana -- python /path/to/Arkana/arkana.py --mcp-server --brief-descriptions --samples-path /path/to/samples
```

`--brief-descriptions` trims tool descriptions to first-paragraph summaries (~60% smaller tool listing). Useful when `ENABLE_TOOL_SEARCH` is disabled.

**Add using Docker (via `run.sh` helper):**

```bash
claude mcp add --scope project arkana -- /path/to/Arkana/run.sh --stdio
```

**Add using Docker with a custom samples directory:**

```bash
claude mcp add --scope project arkana -- /path/to/Arkana/run.sh --samples /path/to/your/samples --stdio
```

The `run.sh` helper auto-detects Docker or Podman, builds the image if needed, and handles volume mounts and environment setup. The `--samples` flag mounts any local directory read-only into the container, mirroring the host folder name (e.g. `--samples ~/Downloads` mounts at `/Downloads`). To pass a VirusTotal API key, set it in your environment or `.env` file:

```bash
claude mcp add --scope project -e VT_API_KEY=your-key-here arkana -- /path/to/Arkana/run.sh --samples ~/malware-zoo --stdio
```

**Add a remote HTTP server:**

```bash
claude mcp add --transport http --scope project arkana http://127.0.0.1:8082/mcp
```

**Verify the server was added:**

```bash
claude mcp list
```

**Remove the server:**

```bash
claude mcp remove arkana
```

---

## Adding Arkana via JSON Configuration

Alternatively, you can configure Arkana by editing JSON files directly.

### Project-Level Configuration (Recommended)

Add a `.mcp.json` file to your project root (an example is included in this repository):

```json
{
  "mcpServers": {
    "arkana": {
      "type": "stdio",
      "command": "python",
      "args": ["arkana.py", "--mcp-server"],
      "env": {
        "VT_API_KEY": ""
      }
    }
  }
}
```

Adjust the `command` path if Arkana is installed elsewhere. Use `--samples-path` to point at your samples directory so the `list_samples` tool can discover files, or set the `ARKANA_SAMPLES` environment variable:

```json
{
  "mcpServers": {
    "arkana": {
      "type": "stdio",
      "command": "python",
      "args": ["/path/to/Arkana/arkana.py", "--mcp-server", "--samples-path", "/path/to/samples"],
      "env": {
        "VT_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### User-Level Configuration

For system-wide availability across all projects, add Arkana to `~/.claude.json`:

```json
{
  "mcpServers": {
    "arkana": {
      "type": "stdio",
      "command": "python",
      "args": ["/absolute/path/to/Arkana/arkana.py", "--mcp-server"]
    }
  }
}
```

### Docker Configuration (via `run.sh`)

To use the Docker image with Claude Code, point the configuration at the `run.sh` helper script. Use `--samples` to specify where your binaries live on the host  - the container path mirrors the host folder name (e.g. `--samples ~/Downloads` → `/Downloads`):

```json
{
  "mcpServers": {
    "arkana": {
      "type": "stdio",
      "command": "/path/to/Arkana/run.sh",
      "args": ["--samples", "/path/to/your/samples", "--stdio"],
      "env": {
        "VT_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

Then in Claude Code, load files using the container path (which mirrors the host folder name):

```
open_file("/samples/malware.exe")
```

If `--samples` is omitted, the `./samples/` directory next to `run.sh` is mounted by default (at `/samples`). You can also set the `ARKANA_SAMPLES` environment variable instead of using the flag.

The `run.sh` helper automatically detects Docker or Podman, builds the image on first run, runs as your host UID (not root), and persists the analysis cache and configuration in `~/.arkana` on the host (bind-mounted into the container). Use `--cache <dir>` or `ARKANA_CACHE` to override the location.

---

## Typical Workflow

Once configured, you can interact with Arkana through Claude Code naturally:

1. **"What samples are available?"**  - Claude calls `list_samples` to discover files in the configured samples directory
2. **"Open this sample for analysis"**  - Claude calls `open_file` with the path (auto-detects PE/ELF/Mach-O). If `session_context` is returned, Claude knows to call `get_analysis_digest()` to review previous findings
3. **"What format is this?"**  - Claude calls `detect_binary_format` to identify format and suggest tools
4. **"What does this binary do?"**  - Claude retrieves the triage report (key findings are auto-saved as notes)
5. **"Decompile the main function"**  - Claude uses Angr tools to decompile, then calls `auto_note_function(address)` to record a summary
6. **"Summarise what we've found"**  - Claude calls `get_analysis_digest()` for an aggregated view of all findings
7. **"Is this a .NET binary?"**  - Claude calls `dotnet_analyze` for CLR metadata and CIL disassembly
8. **"Analyse this Go binary"**  - Claude calls `go_analyze` for packages, functions, compiler version
9. **"Check if it's on VirusTotal"**  - Claude queries the VT API
10. **"Export this analysis"**  - Claude calls `export_project` to save analysis + notes + history as a portable archive
11. **"Close the file"**  - Claude calls `close_file` to free resources (notes and history are persisted to cache)

API keys can be set interactively: *"Set my VirusTotal API key to abc123"*  - Claude calls `set_api_key`, and the key persists across sessions.

---

## Example Natural Language Queries

Arkana understands analytical intent, not just tool commands. Here are examples of what you can ask:

**Triage & Classification:**
- *"Is this file malicious? Give me a quick assessment."*
- *"What kind of binary is this  - is it a service, a DLL, an installer?"*
- *"Show me the most suspicious imports  - skip the boring Windows API stuff."*
- *"What capabilities does MITRE ATT&CK map to this sample?"*

**Data Decoding & Decryption:**
- *"There's a Base64 blob at offset 0x1000  - decode it."*
- *"This data looks XOR encrypted. Can you figure out the key?"*
- *"Decode this: first Base64, then XOR with key 0x41, then decompress."* → uses `refinery_pipeline`
- *"Decrypt this AES-CBC ciphertext. The key is in the .rdata section."*

**Reverse Engineering:**
- *"Decompile the function at 0x00401230 and explain what it does."*
- *"Search the decompiled code for xor operations."* → uses `decompile_function_with_angr(search="xor")`
- *"Which of the top 20 functions contain crypto patterns?"* → uses `batch_decompile(search="xor|aes|rc4")`
- *"What functions call VirtualAlloc? Which ones look suspicious?"*
- *"Find all the string references in the main function."*
- *"Is there shellcode injection happening? Check for VirtualAlloc → WriteProcessMemory patterns."*

**Forensics & IOC Extraction:**
- *"Extract all URLs, IPs, and domain names from this binary."*
- *"Parse this PCAP file and show me the HTTP transactions."*
- *"Extract the VBA macros from this Word document and deobfuscate them."*
- *"What's in this Windows Event Log? Show me the security events."*

**Multi-Stage Analysis:**
- *"This binary has overlay data  - extract and analyse it."*
- *"Unpack this UPX-packed binary and re-analyse."*
- *"The .NET resources contain an encrypted payload  - extract and decrypt it."*
- *"Emulate this shellcode and tell me what APIs it calls."*

---

## Analysis Skill for Claude Code

Arkana ships with an **analysis skill**  - a structured workflow that teaches Claude Code how to use Arkana's 308 tools methodically, rather than relying on the model to figure it out from tool descriptions alone.

Without the skill, Claude Code can still call Arkana tools individually, but it won't follow a structured analysis methodology, may miss important steps, and won't know Arkana-specific patterns like session persistence, note-taking discipline, or unpacking cascades.

### What the Skill Does

The skill provides Claude Code with:

- **Goal-adaptive workflow**  - Detects whether you want malware triage, deep reverse engineering, vulnerability auditing, firmware analysis, threat intel extraction, or binary comparison, and adjusts tool selection and depth accordingly.
- **Phased analysis**  - Structured progression from environment discovery → identification → unpacking → mapping → deep dive → extraction → research → reporting, with clear decision points between phases.
- **Evidence-first methodology**  - All findings must cite specific tool output. Indicators (VirusTotal detections, capa matches, YARA hits) are treated as leads to investigate, not conclusions. Extraction of C2 configs and decoded payloads includes the full chain of evidence (where the data was, what algorithm/key was used, how the key was obtained).
- **Multi-file workflows**  - Guidance for dropper-payload relationships, DLL sideloading investigations, campaign sample comparison, and shellcode extraction from loaders, including cross-file reference discovery (searching strings and imports for companion filenames).
- **Context management**  - Automatic note-taking after every decompilation, periodic digest calls to synthesise findings, and session persistence awareness.
- **Comprehensive tool coverage**  - A complete reference for all 308 tools organised by use case, plus specialised guides for C2 config extraction, unpacking strategies, and safe online research methodology.

### Installing the Skill

The skill files live in `.claude/skills/arkana-analyze/` within the Arkana repository. If you cloned the repo, they're already in place  - no additional installation is needed.

**Verify the skill is present:**

```bash
ls .claude/skills/arkana-analyze/
```

You should see:

```
SKILL.md              # Core workflow  - phases, operating principles, goal detection
tooling-reference.md  # Complete 308-tool catalog by use case
config-extraction.md  # Config decoding patterns by malware family
unpacking-guide.md    # Packer identification and unpacking pipelines
online-research.md    # Safe online research and decoder translation
```

**If you're using Arkana from a different working directory**, the skill won't auto-load since Claude Code skills are project-relative. You have two options:

1. **Run Claude Code from the Arkana directory** (simplest):
   ```bash
   cd /path/to/Arkana
   claude
   ```

2. **Copy the skill into your own project**:
   ```bash
   cp -r /path/to/Arkana/.claude/skills /path/to/your/project/.claude/skills
   ```

### Using the Skill

**Automatic invocation**  - The skill triggers automatically when Claude Code detects binary analysis context (Arkana tools in the conversation, or keywords like "malware", "binary", "analyse", "PE", "ELF", "decompile", etc.). Just start talking about analysis and the skill activates.

**Manual invocation**  - Type `/arkana-analyze` in Claude Code to explicitly activate the skill:

```
/arkana-analyze
```

**Example sessions:**

Quick malware triage:
```
> Open /samples/suspicious.exe and tell me if it's malicious
```

Deep reverse engineering:
```
> I need to fully reverse engineer this binary  - find the crypto routines,
> extract any configs, and document how it works
```

Targeted extraction:
```
> This is AsyncRAT. Extract the C2 config and show me how you got it
```

Multi-file investigation:
```
> I have a dropper (loader.exe) and its payload (data.bin) in /samples  -
> analyse them together
```

The skill runs autonomously through Phases 0-3 (environment discovery, identification, unpacking, mapping). Before entering the deep dive phase, it pauses to present findings so far and asks whether you want to proceed deeper and which areas to focus on. After analysis, it presents a concise evidence-backed summary and offers to generate a detailed report or export the session.

### Skill File Reference

| File | Purpose |
|------|---------|
| [`SKILL.md`](../.claude/skills/arkana-analyze/SKILL.md) | Core workflow orchestration  - operating principles, 8 analysis phases, goal detection, reporting format, multi-file workflows, context management |
| [`tooling-reference.md`](../.claude/skills/arkana-analyze/tooling-reference.md) | Complete catalog of all 308 MCP tools organised by use case with brief descriptions and key parameters |
| [`config-extraction.md`](../.claude/skills/arkana-analyze/config-extraction.md) | Malware config storage patterns, family-specific extraction strategies (Agent Tesla, AsyncRAT, Cobalt Strike, Emotet, Remcos, AdaptixC2, etc.), generic unknown-family approach, validation checklist |
| [`unpacking-guide.md`](../.claude/skills/arkana-analyze/unpacking-guide.md) | Packer identification indicators, 5-method unpacking cascade (auto → orchestrated → emulation-based → emulation analysis → manual OEP), special cases for multi-layer packing, .NET obfuscators, shellcode loaders |
| [`online-research.md`](../.claude/skills/arkana-analyze/online-research.md) | When and how to research online, search query patterns, read-and-understand methodology, decoder operation → Arkana tool translation table, safety rules |

---

## Learning Skill for Claude Code

Arkana ships with a **learning skill**  - an interactive reverse engineering tutor that adapts to all levels, from complete beginners to experienced analysts looking to sharpen specific skills.

Without the skill, you can still ask Claude Code to explain things, but it won't follow a structured pedagogical approach, track your progress across sessions, or draw from a curated curriculum of RE concepts.

### What the Skill Does

The skill provides Claude Code with:

- **Dual-mode teaching**  - Works in two modes: **guided analysis** (learn by doing  - the tutor explains concepts as they arise naturally during hands-on binary analysis) and **structured lessons** (request a specific topic and receive a focused lesson with demonstrations and exercises).
- **Socratic method**  - At key moments, the tutor asks you questions before revealing answers ("Looking at these imports, what behaviour do you think this binary might have?"), building analytical instinct rather than just tool familiarity.
- **Adaptive depth**  - Automatically adjusts vocabulary, explanations, and pacing to your level. A beginner hears "this is a PE header  - think of it as the table of contents for the binary." An expert hears "the reaching definitions show the key originates from the PBKDF2 call at 0x4023A0."
- **Progress tracking**  - Tracks concept mastery across sessions using 4 dedicated MCP tools. The tutor knows what you've learned, what needs reinforcement, and what to teach next.
- **4-tier curriculum**  - 17 concept reference files organised across Foundation, Core Skills, Applied Analysis, and Specialist tiers, covering everything from binary basics to C2 extraction and campaign analysis.

### Installing the Skill

The skill files live in `.claude/skills/arkana-learn/` within the Arkana repository. If you cloned the repo, they're already in place  - no additional installation is needed.

**Verify the skill is present:**

```bash
ls .claude/skills/arkana-learn/
```

You should see:

```
SKILL.md              # Core tutor behaviour  - teaching principles, level adaptation, dual-mode operation
curriculum.md         # 4-tier structured curriculum with modules, prerequisites, and exercises
concepts/             # 17 concept reference files covering RE topics from basics to specialist
```

**If you're using Arkana from a different working directory**, the skill won't auto-load since Claude Code skills are project-relative. You have two options:

1. **Run Claude Code from the Arkana directory** (simplest):
   ```bash
   cd /path/to/Arkana
   claude
   ```

2. **Copy the skill into your own project**:
   ```bash
   cp -r /path/to/Arkana/.claude/skills /path/to/your/project/.claude/skills
   ```

### Using the Skill

**Automatic invocation**  - The skill triggers automatically when Claude Code detects learning context (keywords like "teach", "learn", "tutorial", "explain", "what is", "how does", "walk me through", "help me understand", etc.). Just start asking questions and the skill activates.

**Manual invocation**  - Type `/arkana-learn` (or `/arkana-tutor`) in Claude Code to explicitly activate the skill:

```
/arkana-learn
```

**Example sessions:**

Beginner  - first steps:
```
> I'm new to reverse engineering. Can you teach me the basics using a real binary?
```

Intermediate  - targeted topic:
```
> Teach me about packing and unpacking. I want to understand how to detect
> and unpack a UPX-packed binary
```

Advanced  - deep dive:
```
> Walk me through data flow analysis. I want to understand reaching definitions
> and how to trace where a crypto key comes from
```

Guided analysis with teaching:
```
> Open /samples/suspicious.exe and teach me how to analyse it step by step
```

The skill uses the Socratic method throughout  - expect questions, not just demonstrations. Your answers help the tutor calibrate its teaching and build your analytical instincts.

### Skill File Reference

| File | Purpose |
|------|---------|
| [`SKILL.md`](../.claude/skills/arkana-learn/SKILL.md) | Core tutor behaviour  - teaching principles (explain-then-do, Socratic method, evidence-based), level adaptation rules, dual-mode operation (guided analysis + structured lessons), progress tracking integration |
| [`curriculum.md`](../.claude/skills/arkana-learn/curriculum.md) | 4-tier structured curriculum: Foundation (binary basics, PE structure, strings, imports), Core Skills (control flow, decompilation, packing), Applied Analysis (crypto, anti-analysis, C2 extraction, emulation), Specialist (data flow, YARA authoring, advanced unpacking, campaign analysis) |
| [`concepts/`](../.claude/skills/arkana-learn/concepts/) | 17 concept reference files  - detailed teaching material for each RE topic, including analogies, key points, common misconceptions, and Arkana tool mappings |

### Progress Tracking Tools

The learning skill uses 4 dedicated MCP tools to track learner progress across sessions. These are called automatically by the tutor but can also be used directly:

| Tool | Description |
|------|-------------|
| `get_learner_profile` | Retrieve your progress profile  - current tier, concept mastery counts, module completion percentages, and session statistics. |
| `update_concept_mastery` | Record mastery of a concept at a given level (introduced, practiced, mastered). Called by the tutor after covering a topic. |
| `get_learning_suggestions` | Get personalised suggestions for what to learn next, based on current mastery and optional focus area. |
| `reset_learner_profile` | Reset your learner profile to start fresh. Requires explicit confirmation. |
