# --- Base Image ---
# Pinned by digest for reproducible builds.  To update:
#   docker pull python:3.11-bookworm
#   docker inspect python:3.11-bookworm --format='{{index .RepoDigests 0}}'
# Then replace the digest below with the new one.
FROM python:3.11-bookworm@sha256:94c2dca43c9c127e42dfd021039cc83d8399752097612b49bdc7b00716b6d826

# --- Pinned GitHub download references ---
# Update these periodically to pick up new rules/rootfs content.
# To find the latest commit SHA for a branch:
#   git ls-remote https://github.com/<owner>/<repo>.git <branch> | cut -f1
ARG QILING_ROOTFS_REF=refs/heads/master
ARG REVERSINGLABS_YARA_REF=refs/heads/develop
ARG YARA_RULES_COMMUNITY_REF=refs/heads/master

# --- Set Working Directory ---
WORKDIR /app

# Suppress "Running pip as root" warnings — we're in a container,
# there is no system package manager to conflict with.
ENV PIP_ROOT_USER_ACTION=ignore
# Redirect XDG cache to /tmp so that libraries like capa (which writes
# compiled-rules caches to $XDG_CACHE_HOME/) work regardless of the
# runtime UID.  /tmp is always world-writable — no permission issues.
ENV XDG_CACHE_HOME=/tmp

# --- Install System Dependencies ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    cmake \
    libffi-dev \
    libmagic-dev \
    binwalk \
    && rm -rf /var/lib/apt/lists/*

# --- Upgrade Pip ---
# setuptools<81 is required: the unicorn package does `import pkg_resources`
# at import time, and setuptools 81+ removed pkg_resources entirely.
# The resulting deprecation *warning* is suppressed in application code
# (arkana/__init__.py).
RUN pip install --no-cache-dir --upgrade pip "setuptools<81" wheel

# --- Install Heavy Dependencies (Cached Layer) ---
RUN pip install --no-cache-dir \
    "angr[unicorn]" \
    nampa \
    flare-floss \
    "flare-capa>=9.3,<9.4" \
    vivisect

# --- Install Core Dependencies ---
RUN pip install --no-cache-dir \
    pefile \
    requests \
    cryptography \
    signify \
    yara-python \
    stringsifter \
    joblib \
    numpy \
    "mcp[cli]" \
    Jinja2 \
    rapidfuzz \
    networkx \
    PyYAML \
    psutil

# --- Install Extended Analysis Libraries (Optional but included in Docker) ---
RUN pip install --no-cache-dir \
    lief \
    capstone \
    keystone-engine \
    ppdeep \
    py-tlsh \
    pyelftools \
    dnfile \
    dncil \
    rustbininfo \
    rust-demangler \
    binary-refinery \
    oletools

# --- Install speakeasy in an isolated venv (requires unicorn 1.x) ---
# speakeasy-emulator requires unicorn 1.x (uses internal _uc API removed
# in 2.x).  Instead of downgrading the main env's unicorn (which breaks
# angr's native unicorn bridge), we install speakeasy into its own venv
# and invoke it via subprocess at runtime.  This keeps angr fast (native
# unicorn 2.x) while speakeasy still works (unicorn 1.x in its venv).
RUN python -m venv /app/speakeasy-venv && \
    /app/speakeasy-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /app/speakeasy-venv/bin/pip install --no-cache-dir speakeasy-emulator

# --- Install unipacker in an isolated venv (requires unicorn 1.x) ---
# unipacker pulls in unicorn-unipacker, a fork of unicorn 1.x that
# installs into the same site-packages/unicorn/ namespace as the real
# unicorn package, silently overwriting 2.x module files with 1.x code.
# By isolating unipacker in its own venv we avoid the namespace collision
# entirely -- no more nuke-and-reinstall of unicorn after the build.
RUN python -m venv /app/unipacker-venv && \
    /app/unipacker-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /app/unipacker-venv/bin/pip install --no-cache-dir unipacker

# --- Install Qiling Framework in an isolated venv (requires unicorn 1.x) ---
# Qiling is built on the Unicorn engine and requires unicorn 1.x, which
# conflicts with the main env's unicorn 2.x (used by angr).  By isolating
# Qiling in its own venv we keep angr's native unicorn bridge intact while
# gaining Qiling's cross-platform binary emulation capabilities.
RUN python -m venv /app/qiling-venv && \
    /app/qiling-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /app/qiling-venv/bin/pip install --no-cache-dir qiling

# --- Pre-populate Qiling rootfs (OS-specific files needed for emulation) ---
# Qiling requires rootfs directories containing DLLs, registry hives, and
# other OS-specific files to emulate binaries.  We download these at build
# time from the official Qiling repository to avoid runtime downloads.
#
# IMPORTANT: Rootfs content lives in the dedicated qilingframework/rootfs
# repository, NOT in the main qiling repo (where examples/rootfs/ is a git
# submodule that GitHub archive zips do not include).

# Copy the registry hive script early so the rootfs setup can use it.
# (Full scripts/ COPY happens later to preserve Docker layer caching.)
COPY scripts/create_registry_hives.py /app/scripts/create_registry_hives.py

RUN python <<PYEOF
import urllib.request, zipfile, os, sys, shutil, pathlib
rootfs_dir = pathlib.Path("/app/qiling-rootfs")
rootfs_dir.mkdir(exist_ok=True)
# Pinned via QILING_ROOTFS_REF build arg (update periodically)
url = "https://github.com/qilingframework/rootfs/archive/${QILING_ROOTFS_REF}.zip"
zip_path = "/tmp/qiling-rootfs.zip"
urllib.request.urlretrieve(url, zip_path)
# Auto-detect the top-level directory name in the zip (varies by ref type:
# "rootfs-master/" for branch, "rootfs-<sha>/" for commit SHA)
with zipfile.ZipFile(zip_path, 'r') as zf:
    prefix = zf.namelist()[0].split('/')[0] + '/'
    for member in zf.namelist():
        if not member.startswith(prefix):
            continue
        rel = member[len(prefix):]
        if not rel:
            continue
        dest = rootfs_dir / rel
        if member.endswith('/'):
            dest.mkdir(parents=True, exist_ok=True)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, open(dest, 'wb') as dst:
                dst.write(src.read())
os.remove(zip_path)

# Create registry hive stubs using the shared script
# (canonical implementation lives in scripts/create_registry_hives.py)
sys.path.insert(0, "/app/scripts")
from create_registry_hives import ensure_registry_hives
ensure_registry_hives(str(rootfs_dir))

# Verify key rootfs directories exist and have content.
# NOTE: Windows DLLs are NOT included — users must provide them from a real
# Windows installation.  See docs/QILING_ROOTFS.md for setup instructions.
for d in ["x86_windows", "x8664_windows", "x8664_linux"]:
    p = rootfs_dir / d
    count = sum(1 for _ in p.rglob('*') if _.is_file()) if p.is_dir() else 0
    if count > 0:
        print(f"  rootfs OK: {d} ({count} files)")
    else:
        print(f"  rootfs MISSING or EMPTY: {d}")
PYEOF

# Make rootfs group-writable so the runtime registry-stub generator and
# user-mounted rootfs volumes work when the container runs as a non-root UID.
# A dedicated group (gid 1500) is used so the container user can write without
# full world-writable (777) permissions.  run.sh passes --group-add 1500.
RUN groupadd -g 1500 arkana && \
    chown -R root:arkana /app/qiling-rootfs && \
    chmod -R 775 /app/qiling-rootfs

# --- .NET Runtime & Deobfuscation Tools ---
# de4dot-cex (GPLv3): .NET Framework app — needs mono to run on Linux.
# NETReactorSlayer (GPLv3): self-contained .NET 6 linux-x64 binary — no runtime needed.
# ilspycmd (MIT): .NET global tool — needs dotnet SDK.
# All three run as external subprocesses — no Python dependency or venv needed.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wget apt-transport-https unzip \
        mono-runtime libmono-system-core4.0-cil \
    && wget -q https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb \
         -O /tmp/ms-prod.deb \
    && dpkg -i /tmp/ms-prod.deb && rm /tmp/ms-prod.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends dotnet-sdk-8.0 \
    && rm -rf /var/lib/apt/lists/*

# de4dot-cex v4.0.0 — .NET Framework build, runs via mono
# Zip contains de4dot.exe at root + bin/ with support DLLs
# Optional: download failure is non-fatal (tool reports clear error at runtime)
RUN mkdir -p /app/dotnet-tools/de4dot && { \
    wget -q "https://github.com/ViRb3/de4dot-cex/releases/download/v4.0.0/de4dot-cex.zip" \
         -O /tmp/de4dot.zip && \
    unzip -q /tmp/de4dot.zip -d /app/dotnet-tools/de4dot/ && \
    chmod +x /app/dotnet-tools/de4dot/de4dot.exe && \
    rm /tmp/de4dot.zip; \
    exit_code=$?; \
    if [ $exit_code -ne 0 ]; then \
        echo "WARNING: de4dot-cex download failed (exit $exit_code) — dotnet_deobfuscate(method='de4dot') will be unavailable"; \
    fi; \
    }

# NETReactorSlayer v6.4.0.0 — self-contained linux-x64 binary (no runtime needed)
# Optional: download failure is non-fatal (tool reports clear error at runtime)
RUN mkdir -p /app/dotnet-tools/netreactorslayer && { \
    wget -q "https://github.com/SychicBoy/NETReactorSlayer/releases/download/v6.4.0.0/NETReactorSlayer.CLI-net6.0-linux64.zip" \
         -O /tmp/nrs.zip && \
    unzip -q /tmp/nrs.zip -d /app/dotnet-tools/netreactorslayer/ && \
    chmod +x /app/dotnet-tools/netreactorslayer/NETReactorSlayer.CLI && \
    rm /tmp/nrs.zip; \
    exit_code=$?; \
    if [ $exit_code -ne 0 ]; then \
        echo "WARNING: NETReactorSlayer download failed (exit $exit_code) — dotnet_deobfuscate(method='reactor_slayer') will be unavailable"; \
    fi; \
    }

# ilspycmd — install as .NET global tool
# Optional: install failure is non-fatal (tool reports clear error at runtime)
RUN dotnet tool install --tool-path /app/dotnet-tools/ilspy ilspycmd; \
    exit_code=$?; \
    if [ $exit_code -ne 0 ]; then \
        echo "WARNING: ilspycmd install failed (exit $exit_code) — dotnet_decompile() will be unavailable"; \
    fi
ENV PATH="${PATH}:/app/dotnet-tools/ilspy"

# --- Install GoReSym (Go binary analysis tool from Mandiant) ---
# GoReSym extracts Go compiler version, packages, types, and build info from
# Go binaries.  It is the preferred tier-1 method in go_analyze()'s fallback
# chain (GoReSym → pygore → gopclntab → string-scan).
# Only available for linux/amd64 — on ARM64 the fallback chain handles it
# gracefully (pygore runs in a subprocess, then pure-Python gopclntab parser).
ARG TARGETARCH
RUN if [ "${TARGETARCH:-$(dpkg --print-architecture)}" = "amd64" ]; then \
        wget -q "https://github.com/mandiant/GoReSym/releases/download/v3.3/GoReSym-linux.zip" \
             -O /tmp/GoReSym.zip && \
        unzip -q /tmp/GoReSym.zip -d /usr/local/bin/ && \
        chmod +x /usr/local/bin/GoReSym && \
        rm /tmp/GoReSym.zip && \
        echo "  GoReSym v3.3 installed at /usr/local/bin/GoReSym"; \
    else \
        echo "  GoReSym skipped (no linux/${TARGETARCH:-$(dpkg --print-architecture)} build available — using pygore/gopclntab fallback)"; \
    fi

# --- Install Binary Refinery optional sub-dependencies ---
# These are optional packages that specific refinery units need at runtime.
# Installed best-effort so a single failure doesn't block the build.
# Each package is optional — the corresponding refinery unit reports a clear
# error at runtime if its dependency is missing.
RUN pip install --no-cache-dir \
    "pypcapkit[scapy]" \
    python-registry \
    "LnkParse3>=1.4.0" \
    olefile \
    msoffcrypto-tool \
    Pillow \
    xdis \
    xlrd2 \
    python-evtx \
    XLMMacroDeobfuscator \
    "pikepdf<=9.5"; \
    exit_code=$?; \
    if [ $exit_code -ne 0 ]; then \
        echo "WARNING: Some Binary Refinery sub-dependencies failed to install (exit $exit_code) — affected refinery units will report errors at runtime"; \
    fi

# --- Install libraries that may have complex deps ---
# Each installed separately so a failure in one doesn't block the others,
# but combined into a single layer to reduce image layer count.
# Both are optional — guarded by *_AVAILABLE flags in imports.py.
RUN pip install --no-cache-dir dotnetfile; \
    if [ $? -ne 0 ]; then echo "WARNING: dotnetfile install failed — dotnet_analyze() will use dnfile only"; fi && \
    pip install --no-cache-dir pygore; \
    if [ $? -ne 0 ]; then echo "WARNING: pygore install failed — go_analyze() will use fallback string scan"; fi && \
    pip install --no-cache-dir autoit-ripper; \
    if [ $? -ne 0 ]; then echo "WARNING: autoit-ripper install failed — autoit_decrypt() LZSS decompression and bytecode deassembly will be unavailable (core RanRot/MT decryption still works)"; fi

# --- Patch oscrypto for OpenSSL 3.x compatibility (bookworm ships OpenSSL 3) ---
RUN pip install --no-cache-dir --force-reinstall \
    git+https://github.com/wbond/oscrypto.git@d5f3437ed24257895ae1edd9e503cfb352e635a8

# Show the final unicorn versions for build-log diagnostics.
# Main env: unicorn 2.x → angr native unicorn bridge works.
# Speakeasy venv: unicorn 1.x → speakeasy emulation works.
# Unipacker venv: unicorn 1.x (via unicorn-unipacker) → unipacker works.
# Qiling venv: unicorn 1.x → Qiling Framework emulation works.
RUN python -c "import unicorn; print('main env unicorn', unicorn.__version__); assert hasattr(unicorn, 'UC_ARCH_RISCV'), 'UC_ARCH_RISCV missing!'" && \
    /app/speakeasy-venv/bin/python -c "import unicorn; print('speakeasy venv unicorn', unicorn.__version__)" && \
    /app/unipacker-venv/bin/python -c "import unicorn; print('unipacker venv unicorn', unicorn.__version__)" && \
    /app/qiling-venv/bin/python -c "import unicorn; print('qiling venv unicorn', unicorn.__version__); from qiling import Qiling; print('qiling import OK')"

# --- Pre-populate capa rules (avoids runtime download + write permission issues) ---
# Downloaded at build time so the container never needs write access to /app.
# KEEP THIS URL IN SYNC WITH arkana/constants.py:CAPA_RULES_ZIP_URL so the
# marker file we write here matches what runtime code expects to find.
RUN python <<'PYEOF' && rm -f /tmp/capa-rules.zip
import urllib.request, zipfile, shutil, os, pathlib
RULES_URL = "https://github.com/mandiant/capa-rules/archive/refs/tags/v9.4.0.zip"
urllib.request.urlretrieve(RULES_URL, "/tmp/capa-rules.zip")
zipfile.ZipFile("/tmp/capa-rules.zip").extractall("/tmp")
top = next(p for p in pathlib.Path("/tmp").iterdir() if p.name.startswith("capa-rules") and p.is_dir())
# The archive may have rules at top level or in a rules/ subdir — handle both
source = top / "rules" if (top / "rules").is_dir() else top
os.makedirs("/app/capa_rules_store", exist_ok=True)
shutil.move(str(source), "/app/capa_rules_store/rules")
# Write the marker file so ``ensure_capa_rules_exist`` sees these rules as
# the current version and skips the "no marker → adopt" fallback path.
with open("/app/capa_rules_store/.capa_rules_url", "w") as _f:
    _f.write(RULES_URL)
if top.exists():
    shutil.rmtree(str(top))
PYEOF

# --- Pre-populate capa FLIRT library signatures ---
# Without these, capa analyses ALL functions (including library code),
# causing timeouts on large binaries.
RUN python <<'PYEOF' && rm -f /tmp/capa-src.zip
import urllib.request, zipfile, shutil, os, pathlib
urllib.request.urlretrieve(
    "https://github.com/mandiant/capa/archive/refs/tags/v9.3.0.zip",
    "/tmp/capa-src.zip")
with zipfile.ZipFile("/tmp/capa-src.zip") as zf:
    sigs_prefix = None
    for name in zf.namelist():
        if "/sigs/" in name and name.endswith(".sig"):
            if sigs_prefix is None:
                sigs_prefix = name[:name.index("/sigs/") + len("/sigs/")]
            zf.extract(name, "/tmp")
    if sigs_prefix:
        src = pathlib.Path("/tmp") / sigs_prefix.rstrip("/")
        dest = pathlib.Path("/app/capa_rules_store/sigs")
        if dest.exists(): shutil.rmtree(str(dest))
        shutil.copytree(str(src), str(dest))
        print(f"  Capa FLIRT sigs: {sum(1 for f in dest.iterdir() if f.suffix == '.sig')} files in {dest}")
for d in pathlib.Path("/tmp").iterdir():
    if d.name.startswith("capa-") and d.is_dir(): shutil.rmtree(str(d))
PYEOF

# --- Pre-populate YARA rules store (avoids runtime download) ---
# Two sources are bundled:
#   1. ReversingLabs YARA Rules (MIT licence)  — general malware detection
#   2. Yara-Rules Community (GPL-2.0)          — packers, crypto, anti-debug, capabilities
RUN python <<PYEOF && rm -f /tmp/rl-yara.zip /tmp/community-yara.zip
import urllib.request, zipfile, shutil, os, pathlib

store = pathlib.Path("/app/yara_rules_store")
store.mkdir(exist_ok=True)

# --- ReversingLabs ---
# Pinned via REVERSINGLABS_YARA_REF build arg (update periodically)
rl_url = "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/${REVERSINGLABS_YARA_REF}.zip"
rl_zip = "/tmp/rl-yara.zip"
urllib.request.urlretrieve(rl_url, rl_zip)
with zipfile.ZipFile(rl_zip) as zf:
    zf.extractall("/tmp")
rl_src = next(p for p in pathlib.Path("/tmp").iterdir() if p.name.startswith("reversinglabs-yara-rules") and p.is_dir())
target_rl = store / "reversinglabs"
if target_rl.exists():
    shutil.rmtree(str(target_rl))
shutil.copytree(str(rl_src), str(target_rl))
shutil.rmtree(str(rl_src))
rl_count = sum(1 for _ in target_rl.rglob("*.yar"))
print(f"  ReversingLabs YARA rules installed: {rl_count} files")

# --- Yara-Rules Community ---
# Pinned via YARA_RULES_COMMUNITY_REF build arg (update periodically)
community_url = "https://github.com/Yara-Rules/rules/archive/${YARA_RULES_COMMUNITY_REF}.zip"
community_zip = "/tmp/community-yara.zip"
urllib.request.urlretrieve(community_url, community_zip)
with zipfile.ZipFile(community_zip) as zf:
    zf.extractall("/tmp")
community_src = next(p for p in pathlib.Path("/tmp").iterdir() if p.name.startswith("rules-") and p.is_dir())
target_community = store / "community"
if target_community.exists():
    shutil.rmtree(str(target_community))
shutil.copytree(str(community_src), str(target_community))
shutil.rmtree(str(community_src))
community_count = sum(1 for _ in target_community.rglob("*.yar")) + sum(1 for _ in target_community.rglob("*.yara"))
print(f"  Yara-Rules Community rules installed: {community_count} files")
PYEOF

# --- Copy Application Files ---
COPY arkana.py .
COPY arkana/ ./arkana/
COPY scripts/ ./scripts/
COPY userdb.txt .

# --- Create writable home directory for runtime data ---
# run.sh passes --user "$(id -u):$(id -g)" --group-add 1500 so the
# container runs as the host user with membership in the arkana group.
# Group-writable (775) so any UID in the arkana group can create
# ~/.arkana/cache and config.json inside it.
RUN mkdir -p /app/home/.arkana/cache /app/home/.cache && \
    chown -R root:arkana /app/home && \
    chmod -R 775 /app/home

# --- Create writable output directory ---
# Default export/output directory for project archives, patched binaries, and reports.
# run.sh mounts a host directory here; without a mount this provides a writable fallback.
RUN mkdir -p /output && chown root:arkana /output && chmod 775 /output

# --- Declare volumes ---
# Persistent cache and configuration
VOLUME ["/app/home/.arkana"]
# Qiling rootfs — users can mount their own Windows DLLs, Linux libs, etc.
# See docs/QILING_ROOTFS.md for setup instructions.
VOLUME ["/app/qiling-rootfs"]

# --- Expose Port ---
EXPOSE 8082

# --- Non-root user ---
# Create an unprivileged user in the arkana group (gid 1500, created earlier
# for rootfs permissions).  All writable directories are owned by this user.
# run.sh can still override with --user "$(id -u):$(id -g)" --group-add 1500
# for host-UID mapping; the default (no --user) now runs as arkana:arkana.
RUN useradd -m -s /bin/bash -g arkana arkana && \
    chown -R arkana:arkana /app/home && \
    chown -R arkana:arkana /output && \
    chown -R arkana:arkana /home/arkana

# --- Healthcheck for HTTP mode ---
# Only meaningful when running with --mcp-transport streamable-http.
# In stdio mode the port isn't open, so the check will fail (container
# still runs, Docker just marks it "unhealthy" — harmless).
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8082/mcp')"]

USER arkana

# --- Set Entrypoint ---
ENTRYPOINT ["python", "./arkana.py"]
