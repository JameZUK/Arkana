# Installation & Setup

This guide covers every way to install and run Arkana, from the recommended Docker approach to minimal local installations.

---

## Option A: Docker (Recommended)

Docker handles all complex dependencies (Angr, Unicorn, Vivisect) automatically.

### Quick Start with `run.sh`

The included `run.sh` helper auto-detects Docker or Podman and handles image building, volume mounts, and environment setup:

```bash
# Start HTTP MCP server (builds image if needed)
./run.sh

# Start stdio MCP server (for Claude Code)
./run.sh --stdio

# Mount a custom samples directory (read-only, mirrors host folder name)
./run.sh --samples ~/malware-zoo --stdio

# Analyse a file in CLI mode
./run.sh --analyze samples/suspicious.exe

# Open a shell in the container
./run.sh --shell

# Build/rebuild the image
./run.sh --build
```

Set environment variables as needed:

```bash
VT_API_KEY=abc123 ARKANA_PORT=9000 ./run.sh
ARKANA_SAMPLES=~/malware-zoo ./run.sh --stdio
```

Or copy `.env.example` to `.env` and fill in your values  - `run.sh` loads it automatically.

### Docker Compose

For more control, use Docker Compose directly:

```bash
# Start HTTP MCP server
docker compose up arkana-http

# Start stdio MCP server
docker compose run --rm -i arkana-stdio

# Build only
docker compose build
```

The `docker-compose.yml` defines two services:
- **`arkana-http`**  - Network-accessible MCP server with healthcheck and restart policy
- **`arkana-stdio`**  - For Claude Code / MCP client integration (behind the `stdio` profile)

Both services bind-mount `~/.arkana` from the host for persistent cache and configuration (override with `ARKANA_CACHE`).

### Manual Docker Commands

For most use cases, the `run.sh` helper is recommended. If you need to run Docker directly (e.g. for custom volume mounts or networking):

```bash
# Build the image
docker build -t arkana-toolkit .

# Run as MCP server (streamable-http)
docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  -e HOME=/app/home \
  -p 8082:8082 \
  -v "$(pwd)/samples:/samples:ro" \
  -v "$HOME/.arkana:/app/home/.arkana:rw" \
  -e VT_API_KEY="your_key" \
  arkana-toolkit \
  --mcp-server \
  --mcp-transport streamable-http \
  --mcp-host 0.0.0.0 \
  --samples-path /samples

# Run as MCP server (stdio, for Claude Code)
docker run --rm -i \
  --user "$(id -u):$(id -g)" \
  -e HOME=/app/home \
  -v "$(pwd)/samples:/samples:ro" \
  -v "$HOME/.arkana:/app/home/.arkana:rw" \
  arkana-toolkit \
  --mcp-server \
  --samples-path /samples
```

> **Note:** The `-v $HOME/.arkana:/app/home/.arkana:rw` mount persists the analysis cache, notes, and API key configuration in your home directory. Without it, cached results and stored keys are lost when the container is removed. The `run.sh` helper configures this bind mount automatically (creating `~/.arkana` if needed).

---

## Option B: Local Installation

Requires Python 3.10+ and cmake (for building Unicorn/Angr bindings).

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get install build-essential libssl-dev cmake

# Install Python packages
pip install -r requirements.txt
```

---

## Option C: Minimal Installation

For basic PE analysis without heavy dependencies:

```bash
pip install pefile networkx "mcp[cli]>=2.0,<3.0"
```

Optional packages can be added individually:
- `pip install cryptography signify`  - Digital signature analysis
- `pip install yara-python`  - YARA scanning (bundled rules from ReversingLabs and Yara-Rules Community are auto-downloaded on first run)
- `pip install requests`  - VirusTotal integration
- `pip install rapidfuzz`  - Fuzzy string search
- `pip install flare-capa`  - Capability detection
- `pip install flare-floss vivisect`  - Advanced string extraction
- `pip install stringsifter joblib numpy`  - ML-based string ranking
- `pip install "angr[unicorn]"`  - Decompilation, CFG, symbolic execution
- `pip install lief`  - Multi-format binary parsing (PE/ELF/Mach-O)
- `pip install capstone`  - Multi-architecture disassembly
- `pip install keystone-engine`  - Multi-architecture assembly
- `pip install speakeasy-emulator`  - Windows API emulation
- `pip install ppdeep py-tlsh`  - Fuzzy hashing (ssdeep/TLSH)
- `pip install dnfile dncil`  - .NET assembly analysis
- `pip install pygore`  - Go binary analysis
- `pip install autoit-ripper`  - AutoIt3 LZSS decompression and bytecode deassembly (core MT/RanRot decryption is built-in)
- `pip install rustbininfo rust-demangler`  - Rust binary analysis
- `pip install pyelftools`  - ELF/DWARF analysis
- `pip install binwalk`  - Embedded file detection
- `pip install unipacker`  - Automatic PE unpacking
- `pip install qiling`  - Cross-platform binary emulation (requires isolated venv with unicorn 1.x)
- `pip install dotnetfile`  - .NET PE metadata
- `pip install binary-refinery`  - Composable binary data transforms (encoding, crypto, compression, IOC extraction)

---

## Modes of Operation

### CLI Mode (One-Shot Report)

Generates a comprehensive, human-readable report. Requires `--input-file`.

```bash
python arkana.py --input-file malware.exe --verbose > report.txt
```

### MCP Server Mode (Interactive)

Starts the MCP server. The `--input-file` is optional  - files can be loaded dynamically using the `open_file` tool.

```bash
# Start without a file (recommended for Claude Code)
python arkana.py --mcp-server

# Start with a samples directory (enables the list_samples tool)
python arkana.py --mcp-server --samples-path ./samples

# Start with a pre-loaded file
python arkana.py --mcp-server --input-file malware.exe

# Start with streamable-http transport (for network access)
python arkana.py --mcp-server --mcp-transport streamable-http --mcp-host 0.0.0.0 --mcp-port 8082 --samples-path ./samples
```

**Reducing context window usage:**

```bash
# Trim tool descriptions to first-paragraph summaries (~60% smaller listing)
python arkana.py --mcp-server --brief-descriptions

# Or via environment variable
ARKANA_BRIEF_DESCRIPTIONS=1 python arkana.py --mcp-server
```

`--brief-descriptions` trims tool descriptions to the first paragraph only (phase label + summary sentence), dropping "When to use", "Next steps", Args, and Returns sections. Useful when `ENABLE_TOOL_SEARCH` is disabled in Claude Code.

### Transport Options

| Transport | Flag | Use Case |
|---|---|---|
| **stdio** (default) | `--mcp-transport stdio` | Claude Code, local MCP clients |
| **streamable-http** | `--mcp-transport streamable-http` | Network access, Docker, remote clients |
| **sse** (deprecated) | `--mcp-transport sse` | Legacy support only; use streamable-http instead |

---

## Multi-Format Binary Support

### Auto-Detection (Recommended)

Arkana automatically detects the binary format from magic bytes:

```
open_file("/path/to/binary")  # Auto-detects PE, ELF, or Mach-O
```

### ELF Binaries (Linux)

```bash
# CLI mode
python arkana.py --input-file binary.elf --mode elf

# MCP mode  - use elf_analyze, elf_dwarf_info, plus all angr tools
open_file("/path/to/binary", mode="elf")
```

### Mach-O Binaries (macOS)

```bash
# CLI mode
python arkana.py --input-file binary.macho --mode macho

# MCP mode  - use macho_analyze, plus all angr tools
open_file("/path/to/binary", mode="macho")
```

### .NET, Go, and Rust Binaries

These format-specific tools work on any loaded binary:

```
dotnet_analyze("/path/to/assembly.exe")     # .NET CLR metadata
go_analyze("/path/to/go-binary")            # Go packages and functions
rust_analyze("/path/to/rust-binary")        # Rust crate dependencies
```

### Shellcode Analysis

Arkana supports raw shellcode analysis:

```bash
# CLI mode
python arkana.py --input-file shellcode.bin --mode shellcode

# MCP server mode with architecture hint
python arkana.py --mcp-server --input-file shellcode.bin --mode shellcode --floss-format sc64
```

In MCP mode, you can also open shellcode dynamically:

```
open_file("/path/to/shellcode.bin", mode="shellcode")
```

Use `--floss-format sc64` (64-bit) or `--floss-format sc32` (32-bit) to provide architecture hints to FLOSS and Angr.
