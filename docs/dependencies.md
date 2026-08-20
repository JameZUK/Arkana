# Arkana Dependency Notes

This document records known dependency conflicts, version constraints,
and workarounds used in the Docker build.  If the container build breaks
after a `--no-cache` rebuild, start here.

---

## Quick reference  - build-time assertions

The Dockerfile includes a build-time check that will **fail the build**
if the unicorn module is broken:

```
assert hasattr(unicorn, 'UC_ARCH_RISCV'), 'UC_ARCH_RISCV missing!'
```

If you see `UC_ARCH_RISCV missing!` during `podman build`, the unicorn
namespace collision (described below) has resurfaced.

---

## 1. The unicorn quartet: angr, speakeasy, unipacker, qiling

Four packages each need the `unicorn` CPU emulator, but they need
**incompatible versions** and some of them silently clobber each other's
files.

| Package            | Needs unicorn | Why                                                         |
|--------------------|---------------|-------------------------------------------------------------|
| **angr\[unicorn\]**   | 2.x           | `archinfo` references `UC_ARCH_RISCV` (added in unicorn 2.0) |
| **speakeasy-emulator** | 1.x (==1.0.2) | Uses the internal `_uc` C API removed in unicorn 2.x        |
| **unipacker**      | 1.x (via `unicorn-unipacker`) | Fork of unicorn 1.x with the same Python namespace |
| **qiling**         | 1.x           | Uses unicorn 1.x internal APIs for CPU emulation            |

### The namespace collision (unicorn vs unicorn-unipacker)

`unicorn-unipacker` is a **separate pip package** but installs its files
into the same `site-packages/unicorn/` directory as the real `unicorn`
package.  When pip installs `unicorn-unipacker` *after* `unicorn`, the
1.x module files silently overwrite the 2.x files.  Critically, **pip's
package registry still records `unicorn==2.1.x`** so commands like
`pip install --upgrade "unicorn>=2.0.0"` see "Requirement already
satisfied" and do nothing.

Even `--force-reinstall` can be confused by the stale metadata.

### Current fix: venv isolation for speakeasy, unipacker, and qiling

All three unicorn-1.x packages are installed in **separate virtualenvs**
so their dependencies never touch the main environment:

- **speakeasy-emulator** → `/app/speakeasy-venv` (unicorn 1.x via
  `unicorn==1.0.2`).  Invoked via `scripts/speakeasy_runner.py`.
- **unipacker** → `/app/unipacker-venv` (unicorn 1.x via
  `unicorn-unipacker`).  Invoked via `scripts/unipacker_runner.py`.
- **qiling** → `/app/qiling-venv` (unicorn 1.x).  Invoked via
  `scripts/qiling_runner.py`.

The main environment keeps unicorn 2.x for angr.  No nuke-and-reinstall
step is needed because no conflicting package is installed in the
main env.

All three runners use the same subprocess pattern: the tool function
sends a JSON command via stdin, the runner script (executed with the
venv's Python) does the work, and returns a JSON result via stdout.

#### Stdout pollution guard

Emulator libraries (unipacker's `engine.emu()`, Qiling's emulation
core) print log and debug messages directly to stdout during execution.
Since the runners use stdout for JSON IPC with the parent process,
these log lines corrupt the JSON output and cause `json.loads()` to
fail in the parent.

**Fix:** Each runner redirects `sys.stdout` to `sys.stderr` before
dispatching the action, then restores it in a `finally` block before
writing the JSON result.  This sends emulator log output to stderr
(which the parent captures separately) while keeping stdout clean for
the JSON response.

#### Qiling Windows rootfs and registry hive stubs

Qiling requires OS-specific rootfs directories containing DLLs,
registry hives, and system files to initialise emulation.  Rootfs
content is downloaded from the dedicated **qilingframework/rootfs**
GitHub repository (not the main qiling repo, where `examples/rootfs/`
is a git submodule that GitHub archive zips do not include).

For Windows targets, Qiling's `RegistryManager` requires five registry
hive files (`NTUSER.DAT`, `SAM`, `SECURITY`, `SOFTWARE`, `SYSTEM`)
that cannot be legally distributed.  Arkana generates minimal valid
stubs  - structurally correct regf-format files with an empty root key
node  - at both Docker build time and at runtime (on first use).
These stubs satisfy Qiling's format parser so emulation can proceed.

The rootfs directory (`/app/qiling-rootfs`) is pre-populated at Docker
build time with Linux rootfs files.  Windows PE emulation additionally
requires real DLL files (ntdll.dll, kernel32.dll, etc.) copied from a
Windows installation  - see `docs/QILING_ROOTFS.md` for instructions.

### Runtime safety net (arkana/config.py)

The angr import block catches both `ImportError` and `AttributeError`:

```python
try:
    import angr
    import angr.analyses.decompiler
    ANGR_AVAILABLE = True
except (ImportError, AttributeError):
    ANGR_AVAILABLE = False
```

If unicorn is still broken at runtime, the server starts with angr
disabled instead of crashing.

---

## 2. setuptools < 81

The `unicorn` package calls `import pkg_resources` at import time.
setuptools 81+ removed `pkg_resources` entirely, causing an
`ImportError` on `import unicorn`.

**Fix:** Pin `setuptools<81` in the Dockerfile pip upgrade step.

A deprecation warning is also suppressed in application code
(`arkana/__init__.py`).

---

## 3. oscrypto + OpenSSL 3.x

The PyPI release of `oscrypto` (1.3.0) does not support OpenSSL 3.x,
which is the default in Debian Bookworm.  Importing `signify` (which
depends on `oscrypto`) fails with an `OpenSSL` error.

**Fix:** Force-reinstall from a specific commit that adds OpenSSL 3
support:

```dockerfile
RUN pip install --no-cache-dir --force-reinstall \
    git+https://github.com/wbond/oscrypto.git@d5f3437ed24257895ae1edd9e503cfb352e635a8
```

`--force-reinstall` is required because pip sees the same version number
(1.3.0) and skips the install otherwise.

---

## 4. Best-effort packages (dotnetfile, binwalk, pygore)

These are installed with `|| true` so a failure in one does not block
the others or the entire build.  They may have fragile or conflicting
dependencies.

If any of these break the build, the simplest fix is to comment them
out  - Arkana will detect their absence at runtime and disable the
corresponding tools.

Note: unipacker was previously in this group but is now installed in
its own isolated venv (see section 1).

### Optional analysis libraries

| Package | Used by | Purpose |
|---------|---------|---------|
| **Triton** | `analyze_instruction_trace` | Symbolic trace analysis, expression simplification. Without Triton, the tool falls back to pure-Python trace statistics (instruction count, mnemonic frequency, unique addresses). Install: `pip install triton-library` |
| **oletools** | `analyze_office_macros`, `detect_xlm_macros`, `analyze_ole_streams` | VBA/XLM macro extraction and OLE stream analysis for Office documents. Install: `pip install oletools` |

---

## 4b. ilspycmd version pin (.NET decompiler)

`dotnet tool install ilspycmd` with no version resolves to the newest
release, which targets a framework newer than the image's .NET 8 SDK. That
fails the build step with:

```
The settings file in the tool's NuGet package is invalid:
Settings file 'DotnetToolSettings.xml' was not found in the package.
```

The step is non-fatal, so builds succeeded with `dotnet_decompile()`
silently unavailable. Testing candidates inside the image gives three
distinct outcomes:

| Version | Installs | Runs |
|---------|----------|------|
| 10.1.1.8388 | no  - SDK 8 cannot resolve the target framework | — |
| **9.1.0.7988** | yes | yes  - targets net8.0, which the image ships |
| 8.2.0.7535 | yes | **no**  - "You must install or update .NET to run this application" |

The 8.x outcome is the dangerous one: `_check_ilspycmd_available()` only
tests that the file exists, so an unrunnable binary would be advertised as
available and every call would fail at runtime.

The Dockerfile therefore pins `ARG ILSPYCMD_VERSION=9.1.0.7988` and follows
the install with an `ilspycmd --version` check that removes the directory on
failure, so detection can never report a tool that cannot execute. Revisit
the pin when the dotnet base image is upgraded.

---

## 5. stringsifter pins

`stringsifter` pins `numpy<1.25`, `scikit-learn<1.4`, and
`joblib==1.3.x`.  These older versions are pulled in automatically by
pip's resolver.  If a future package requires newer numpy/scikit-learn,
stringsifter will need to be updated or isolated.

**Important:** The PyPI package name is **`stringsifter`**, not
`flare-stringsifter` (which does not exist on PyPI).

---

## 6. capa-rules version alignment

The bundled capa-rules must match the capa major version.  If you bump
`flare-capa` to a new major version, update the rules download URL in
**both** places:

- `arkana/config.py` → `CAPA_RULES_ZIP_URL`
- `Dockerfile` → the `urllib.request.urlretrieve(...)` URL

Current alignment: **flare-capa >=9.3,<9.4** with **capa-rules v9.3.0**.
The minor version must match  - rules use syntax from their matching capa release.

### Capa rule cache (`XDG_CACHE_HOME`)

Capa writes a compiled-rules cache file to `$XDG_CACHE_HOME/capa-*.cache`
(via `platformdirs`).  In Docker the container runs as an arbitrary UID
(via `--user "$(id -u):$(id -g)"`), so the default `~/.cache/` may not
be writable.

**Fix:** The Dockerfile sets `ENV XDG_CACHE_HOME=/tmp` so the cache
always lands in a world-writable directory.  If the Dockerfile ENV is
ever removed, add `-e XDG_CACHE_HOME=/tmp` to the `docker run` command
or the `run.sh` helper.

---

## 7. Bundled YARA rules store

Arkana bundles YARA rules from two legitimate open-source projects so
that YARA scanning works out-of-the-box without the user needing to
supply their own rules via `--yara-rules`.

| Source | Licence | Description |
|--------|---------|-------------|
| [ReversingLabs YARA Rules](https://github.com/reversinglabs/reversinglabs-yara-rules) | MIT | General-purpose malware detection rules. Uses YARA `import "pe"` etc. |
| [Yara-Rules Community](https://github.com/Yara-Rules/rules) | GPL-2.0 | Crowd-sourced rules: packers, crypto, anti-debug/VM, capabilities, malware families. |

### Store layout

```
yara_rules_store/
  reversinglabs/     ← ReversingLabs archive (develop branch)
  community/         ← Yara-Rules project archive (master branch)
```

### How rules are obtained

- **Docker (build-time):** Both ZIP archives are downloaded and extracted
  during `docker build` (see the `PYEOF` block in the Dockerfile).  No
  network access is needed at runtime.
- **Local / non-Docker (first run):** When `--yara-rules` is not
  specified and no `yara_rules_store/` directory exists, Arkana calls
  `ensure_yara_rules_exist()` which downloads both archives to
  `DATA_DIR/yara_rules_store/`.  Subsequent runs reuse the local copy.

### Compilation strategy

YARA rules are compiled **per top-level subdirectory** (i.e. one batch
for `reversinglabs/`, one for `community/`).  This preserves YARA
`import` statements (`import "pe"`, `import "math"`, etc.) which many
ReversingLabs rules require.  If batch compilation fails for a group
(e.g. a rule references an unsupported module), Arkana falls back to
per-file compilation for that group, logging a warning for each file
that fails.

Matches are **deduplicated by rule name** after scanning  - if both
sources define a rule with the same name (e.g. `IsPE64`), only the
first match is kept.  String instances per rule match are capped at 25
to prevent noisy rules (e.g. `contains_base64`) from inflating MCP
response sizes.

### Updating the URLs

If you need to pin to a specific tag or update the sources:

- `arkana/config.py` → `YARA_REVERSINGLABS_ZIP_URL`,
  `YARA_COMMUNITY_ZIP_URL`
- `Dockerfile` → the corresponding `urllib.request.urlretrieve(...)` URLs

---

## 8. Library API renames (runtime compatibility)

Several libraries renamed classes or APIs in newer versions, breaking
Arkana's imports.  These are handled with compatibility shims:

| Library | Old API | New API (current) | Affected Arkana files | Shim |
|---------|---------|-------------------|---------------------|------|
| **dncil** >=1.0.2 | `dncil.cil.error.CilError` | `dncil.cil.error.MethodBodyFormatError` | `config.py`, `tools_dotnet.py` | `import MethodBodyFormatError as CilError` |
| **angr** >=9.2.199 | `analyses.FlirtAnalysis()` | `analyses.Flirt()` | `tools_angr_disasm.py` | Direct rename + auto-load FLIRT sigs |
| **unipacker** >=1.0.8 | `UnpackerEngine(filepath, ...)` | `UnpackerEngine(Sample(filepath), ...)` | `scripts/unipacker_runner.py` | Wrap path in `Sample()` object (in venv runner) |
| **angr** >=9.2.199 | `ProcedureEngine()` (no args) | `ProcedureEngine(project)` | `tools_angr_dataflow.py` | Monkey-patch `VFG._get_simsuccessors` |
| **mcp** >=2.0 | `mcp.server.fastmcp.FastMCP` | `mcp.server.mcpserver.MCPServer` | `imports.py`, `main.py`, `state.py` | Try v2, fall back to v1; alias kept as `FastMCP` |

### dncil: CilError → MethodBodyFormatError

dncil v1.0.2 renamed the exception class.  Arkana imports the new name
with an alias (`as CilError`) so all downstream `except CilError`
handlers continue to work.  Without this, `DNCIL_AVAILABLE` is set to
`False` at startup, silently disabling all .NET CIL tools.

### angr: FlirtAnalysis → Flirt

angr v9.2.199 renamed the FLIRT analysis plugin.  Additionally, the new
`Flirt()` API requires signatures to be pre-loaded via
`angr.flirt.load_signatures(path)`, unlike the old `FlirtAnalysis()`
which handled this internally.  Arkana auto-discovers FLIRT signature
files from FLOSS's bundled sigs directory.

### mcp: FastMCP to MCPServer (SDK v2)

MCP SDK v2.0 removed `mcp.server.fastmcp` outright  - `FastMCP` became
`mcp.server.mcpserver.MCPServer`, with no deprecation shim. Because the
dependency was pinned as an unbounded `mcp[cli]>=1.0`, fresh builds
resolved 2.0.0 on release day and stopped working.

`arkana/imports.py` tries v2 first and falls back to v1, keeping the
internal alias `FastMCP` so the rest of the codebase is version-agnostic.
The pin is now `mcp[cli]>=2.0,<3.0`  - the upper bound is deliberate,
since a major bump moved the server class once already.

Three behavioural differences needed handling beyond the import:

**`settings` lost `host`/`port`.** v1 carried the bind address on
`mcp_server.settings`; v2 moved it to app-factory and runner keyword
arguments, and its pydantic settings model raises `ValueError` on
assignment to an undeclared field. `main._apply_mcp_settings()` assigns
only fields the model declares, and `main._mcp_run_kwargs()` passes
host/port to `run()` on v2 only  - v1's `run()` signature would raise
`TypeError`.

**`ServerSession` is rebuilt per request.** v1 kept one session object per
connected client, so Arkana keyed its per-session `AnalyzerState` by
stamping a UUID onto it. Under v2 the object differs on every call, so
each tool call landed in a fresh state  - `open_file()` reported success
and the next call answered "No file is currently loaded". Session identity
now resolves in three tiers (see
[Architecture → MCP session identity](architecture.md#mcp-session-identity)).

**Client-side renames.** v2 renamed `isError` → `is_error` and
`structuredContent` → `structured_content`, and the streamable-http
transport yields a 2-tuple instead of a 3-tuple.
`tests/integration/mcp_test_client.py` handles both shapes.

### unipacker: Sample object required

unipacker v1.0.8 changed `UnpackerEngine.__init__()` to expect a
`Sample` instance (from `unipacker.core`) instead of a raw file path
string.  `Sample()` wraps the path and performs YARA-based packer
detection.

### angr: VFG ProcedureEngine missing project argument

angr v9.2.199 refactored the engine class hierarchy so that
`SimEngine.__init__()` requires a `project` argument (it uses
`self.project.arch` internally).  The inheritance chain is:

```
SimEngine.__init__(self, project)        ← requires project
  └── SuccessorsEngine.__init__(self, project)
        └── ProcedureEngine (ProcedureMixin + SuccessorsEngine)
```

The bug is in `VFG._get_simsuccessors()` (in
`angr/analyses/vfg.py`), which has 3 error-handling fallback paths
that still call `ProcedureEngine()` **without** passing `project`:

```python
# angr/analyses/vfg.py, lines ~1432/1438/1445 (the buggy code)
except SimIRSBError as ex:
    inst = SIM_PROCEDURES["stubs"]["PathTerminator"]()
    sim_successors = ProcedureEngine().process(state, procedure=inst)
    #                              ^^^ missing self.project
```

The **main** execution path (`self.project.factory.successors()`) works
fine.  The crash only triggers when VFG encounters unsupported VEX
instructions (`SimIRSBError`), Claripy solver errors (`ClaripyError`),
or generic simulation errors (`SimError`)  - all of which fall through
to the broken `ProcedureEngine()` calls.

**Fix:** Arkana monkey-patches `VFG._get_simsuccessors` at import time
(in `arkana/mcp/tools_angr_dataflow.py`).  The patched version is a
faithful copy of the original method with one change on each of the 3
error paths: `ProcedureEngine()` → `ProcedureEngine(self.project)`.
The `self.project` attribute is always available because `VFG` inherits
from `Analysis`, and the `AnalysisFactory` sets `self.project` before
`__init__` is called (see `angr/analyses/analysis.py` line ~246).

```python
# The patch (applied at module load time)
from angr.analyses.vfg import VFG

def _patched_get_simsuccessors(self, state, addr):
    # ... same as original, except:
    sim_successors = ProcedureEngine(self.project).process(state, procedure=inst)
    #                                ^^^^^^^^^^^^^ fix

VFG._get_simsuccessors = _patched_get_simsuccessors
```

The entire patch is wrapped in `try/except (ImportError, AttributeError)`
so it silently skips if a future angr version removes `VFG`, renames
`_get_simsuccessors`, or restructures the class hierarchy.

**Upstream status:** Bug present in angr 9.2.199 (latest on PyPI).
Not fixed upstream.  These are the only 3 call sites in the angr
codebase that call `ProcedureEngine()` without arguments.

**To remove this patch:** If a future angr release fixes the bug,
delete the monkey-patch block in `tools_angr_dataflow.py` (the
`try` block between the `import networkx` and the
`# ---- Reaching Definitions Analysis` comment).  No other code
changes are needed  - the tool will use angr's native `VFG` method
automatically.

---

## 9. PyPI version ceilings for optional packages

Several optional packages have low version ceilings on PyPI  - the latest
available version is *below* the minimum you might naively expect:

| Package | Latest on PyPI | Notes |
|---------|---------------|-------|
| **nampa** | 0.1.1 | Last release 2017  - unmaintained but functional |
| **dotnetfile** | 0.2.10 | Active; still pre-1.0 |
| **binwalk** | 2.1.0 | PyPI release is from 2015; 2.3.x+ only via GitHub |
| **pygore** | 0.5.0 | Last release Oct 2021; cannot parse modern Go binaries. `go_analyze` has a string-scan fallback |
| **keystone-engine** | 0.9.2 | Last release 2020 |

The `requirements.txt` minimum constraints are set to values that can
actually be satisfied from PyPI.  If a package needs a newer version
only available from GitHub, install it in the Dockerfile via
`pip install git+https://...`.

---

## 10. Binary Refinery sub-dependencies

Binary Refinery is a large framework with 200+ units.  Many units are
self-contained, but some require optional packages that are **not** pulled
in automatically by `pip install binary-refinery`.  These are installed
best-effort in the Dockerfile:

| Package | Required by | Purpose |
|---------|-------------|---------|
| **pypcapkit[scapy]** | `pcap` unit | PCAP network capture parsing |
| **python-registry** | `winreg` unit | Windows registry hive parsing |
| **LnkParse3** | `lnk` unit | Windows .lnk shortcut parsing |
| **olefile** | OLE units | OLE/CFB document extraction |
| **msoffcrypto-tool** | `officecrypt` unit | Office document decryption |
| **Pillow** | `stego` unit | Image steganography extraction |
| **xdis** | `pyc` unit | Python bytecode decompilation |
| **xlrd2** | `xlmdeobf` unit | Excel 4.0 XLM macro deobfuscation |
| **python-evtx** | `evtx` unit | Windows Event Log (.evtx) parsing |
| **XLMMacroDeobfuscator** | `xlmdeobf` unit | XLM macro emulation engine |
| **pikepdf** (<=9.5) | `xtpdf` unit | PDF object/stream extraction |

If any of these are missing at runtime, the corresponding refinery unit
returns a `MissingModule` stub instead of functioning normally.  Arkana's
tool wrappers detect this and return a clear error message.

---

## Debugging a broken build

1. **Read the build log carefully.** Look for packages that install into
   the `unicorn` namespace or downgrade existing packages.
2. **Check the diagnostic step output.** The build prints the main env,
   speakeasy venv, and unipacker venv unicorn versions.  Main env must
   be 2.x.
3. **Run an interactive shell** in a partial build to inspect:
   ```bash
   podman run --rm -it --entrypoint bash arkana-toolkit
   python -c "import unicorn; print(unicorn.__version__, dir(unicorn))"
   pip list | grep -i unicorn
   ```
4. **If the assert fails**, the unicorn namespace has been clobbered
   again.  Check whether a new package installed in the main env pulls
   in `unicorn-unipacker` or another unicorn fork.

---

## Dockerfile install order (and why it matters)

```
 1. angr[unicorn], nampa  → installs unicorn 2.x + archinfo, pyvex, cle, FLIRT parser
 2. flare-floss, capa, vivisect
 3. Core deps (pefile, requests, mcp, etc.)
 4. Extended libs (lief, capstone, dnfile, dncil, binary-refinery, etc.)
 5. speakeasy-emulator    → isolated in /app/speakeasy-venv (unicorn 1.x)
 6. unipacker             → isolated in /app/unipacker-venv (unicorn 1.x)
 7. qiling                → isolated in /app/qiling-venv (unicorn 1.x)
 8. Qiling rootfs download + Windows registry hive stubs
 9. Binary Refinery sub-deps (best-effort): pypcapkit, python-registry,
    LnkParse3, olefile, msoffcrypto-tool, Pillow, xdis, xlrd2,
    python-evtx, XLMMacroDeobfuscator, pikepdf
10. dotnetfile, binwalk, pygore (best-effort, main env)
11. oscrypto patch
12. Assert UC_ARCH_RISCV exists                      ← build-time guard
13. Pre-populate capa rules (v9.3.0)                 ← avoids runtime download
14. Pre-populate YARA rules store (ReversingLabs + Yara-Rules Community)
15. Copy application files
```

Since speakeasy, unipacker, and qiling are all in isolated venvs,
there is no longer a nuke-and-reinstall step.  The main env's
unicorn 2.x is never touched after step 1.
