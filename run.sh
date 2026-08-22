#!/usr/bin/env bash
#
# Arkana Helper Script
#
# Detects Docker or Podman and runs Arkana with sensible defaults.
# Handles volume mounts, environment variables, and common modes.
#
# Usage:
#   ./run.sh                              Start HTTP MCP server
#   ./run.sh --stdio                      Start stdio MCP server
#   ./run.sh --analyze samples/mal.exe    Analyze a file (CLI mode)
#   ./run.sh --samples /path/to/files     Mount a custom samples directory
#   ./run.sh --build                      Build the container image
#   ./run.sh --shell                      Open a shell in the container
#   ./run.sh --help                       Show this help

set -euo pipefail

IMAGE_NAME="arkana-toolkit"
CONTAINER_PORT="${ARKANA_PORT:-${PEMCP_PORT:-8082}}"
DASHBOARD_PORT_SCAN="${ARKANA_DASHBOARD_PORT_SCAN:-10}"
SAMPLES_DIR="${ARKANA_SAMPLES:-${PEMCP_SAMPLES:-$(cd "$(dirname "$0")" && pwd)/samples}}"
CONTAINER_SAMPLES="/$(basename "$SAMPLES_DIR")"
ROOTFS_DIR="${ARKANA_ROOTFS:-${PEMCP_ROOTFS:-$(cd "$(dirname "$0")" && pwd)/qiling-rootfs}}"
OUTPUT_DIR="${ARKANA_OUTPUT:-${PEMCP_OUTPUT:-$(cd "$(dirname "$0")" && pwd)/output}}"
CACHE_DIR="${ARKANA_CACHE:-${PEMCP_CACHE:-$HOME/.arkana}}"

# --- Detect container runtime ---
detect_runtime() {
    if command -v docker &>/dev/null; then
        # Check if docker is actually working (not just installed alias)
        if docker info &>/dev/null 2>&1; then
            echo "docker"
            return
        fi
    fi
    if command -v podman &>/dev/null; then
        echo "podman"
        return
    fi
    echo ""
}

RUNTIME=$(detect_runtime)

if [[ -z "$RUNTIME" ]]; then
    echo "Error: Neither Docker nor Podman found (or Docker daemon not running)." >&2
    echo "" >&2
    echo "Install one of:" >&2
    echo "  Docker:  https://docs.docker.com/get-docker/" >&2
    echo "  Podman:  https://podman.io/getting-started/installation" >&2
    exit 1
fi

echo "[*] Using container runtime: $RUNTIME" >&2

# --- SELinux: add :z to bind mounts so the container can read/write files ---
SELINUX_SUFFIX=""
if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
    SELINUX_SUFFIX=",z"
fi

# --- Build image if it doesn't exist ---
ensure_image() {
    if ! $RUNTIME image inspect "$IMAGE_NAME" &>/dev/null; then
        echo "[*] Image '$IMAGE_NAME' not found. Building..." >&2
        build_image
    fi
}

build_image() {
    echo "[*] Building $IMAGE_NAME..." >&2
    $RUNTIME build -t "$IMAGE_NAME" "$(dirname "$0")" >&2
    echo "[*] Build complete." >&2
}

# --- Common run arguments ---
# Populates the global COMMON_ARGS array.  Using an array (instead of
# echoing a string and capturing via $(...)) preserves arguments that
# contain spaces — e.g. paths like "/home/user/My Samples".
COMMON_ARGS=()
build_common_args() {
    # Ensure cache directory exists on host
    mkdir -p "$CACHE_DIR" 2>/dev/null || true

    COMMON_ARGS=(
        --rm
        -e "HOME=/app/home"
        -e "USER=${USER:-arkana}"
    )

    # Podman rootless needs --userns=keep-id to map host UID into the container
    # so bind-mounted directories are writable. Docker doesn't need this.
    if [[ "$RUNTIME" == "podman" ]]; then
        COMMON_ARGS+=(--userns=keep-id)
    else
        COMMON_ARGS+=(--user "$(id -u):$(id -g)")
        COMMON_ARGS+=(--group-add 1500)
    fi

    COMMON_ARGS+=(
        -e "ARKANA_HOST_SAMPLES=$SAMPLES_DIR"
        -v "$SAMPLES_DIR:$CONTAINER_SAMPLES:ro${SELINUX_SUFFIX}"
        -v "$CACHE_DIR:/app/home/.arkana:rw${SELINUX_SUFFIX}"
    )

    # Mount output directory if it exists (create it on first use)
    if [[ -n "${OUTPUT_DIR:-}" ]]; then
        mkdir -p "$OUTPUT_DIR" 2>/dev/null || true
        if [[ -d "$OUTPUT_DIR" ]]; then
            COMMON_ARGS+=(-v "$OUTPUT_DIR:/output:rw${SELINUX_SUFFIX}")
            COMMON_ARGS+=(-e "ARKANA_HOST_EXPORT=$OUTPUT_DIR")
            COMMON_ARGS+=(-e "ARKANA_EXPORT_DIR=/output")
        fi
    fi

    # Mount Qiling rootfs if the directory exists on the host.
    # Users place Windows DLLs, Linux libs, etc. here for Qiling emulation.
    # See docs/QILING_ROOTFS.md for setup instructions.
    if [[ -d "$ROOTFS_DIR" ]]; then
        COMMON_ARGS+=(-v "$ROOTFS_DIR:/app/qiling-rootfs:rw${SELINUX_SUFFIX}")
    fi

    # Pass VT_API_KEY if set
    if [[ -n "${VT_API_KEY:-}" ]]; then
        COMMON_ARGS+=(-e "VT_API_KEY=$VT_API_KEY")
    fi

    # Load .env file if present
    local env_file="$(dirname "$0")/.env"
    if [[ -f "$env_file" ]]; then
        COMMON_ARGS+=(--env-file "$env_file")
    fi

    # Build ARKANA_PATH_MAP: semicolon-separated internal=external path pairs
    # so MCP clients can translate container paths to host paths.
    local path_map="$CONTAINER_SAMPLES=$SAMPLES_DIR"
    if [[ -n "${OUTPUT_DIR:-}" && -d "$OUTPUT_DIR" ]]; then
        path_map="$path_map;/output=$OUTPUT_DIR"
    fi
    COMMON_ARGS+=(-e "ARKANA_PATH_MAP=$path_map")
}

# --- Commands ---
cmd_http() {
    ensure_image
    build_common_args
    echo "[*] Starting Arkana HTTP server on port $CONTAINER_PORT..."
    echo "[*] Samples mounted at: $CONTAINER_SAMPLES (from $SAMPLES_DIR)"
    echo "[*] Config/cache (.arkana): $CACHE_DIR"
    echo "[*] MCP endpoint: http://127.0.0.1:$CONTAINER_PORT/mcp"
    echo "[*] Press Ctrl+C to stop."
    echo ""
    $RUNTIME run -it \
        "${COMMON_ARGS[@]}" \
        -e ARKANA_DASHBOARD_HOST=0.0.0.0 \
        -p "$CONTAINER_PORT:8082" \
        "$IMAGE_NAME" \
        --mcp-server --mcp-transport streamable-http --mcp-host 0.0.0.0 \
        --samples-path "$CONTAINER_SAMPLES" \
        --allowed-paths "$CONTAINER_SAMPLES" "/output" \
        "$@"
}

cmd_stdio() {
    ensure_image
    build_common_args
    echo "[*] Starting Arkana in stdio MCP mode..." >&2
    echo "[*] Samples mounted at: $CONTAINER_SAMPLES (from $SAMPLES_DIR)" >&2
    echo "[*] Config/cache (.arkana): $CACHE_DIR" >&2

    # Publish the dashboard on the first free host port. Publishing
    # $CONTAINER_PORT unconditionally makes a second instance die with "address
    # already in use" (docker exit 125), which an MCP client surfaces as
    # CONNECTION_CLOSED. But simply skipping the publish when the port is busy
    # is worse in practice: the check is a single sample taken at spawn time,
    # and the busy window is usually the previous instance shutting down. The
    # dashboard would then stay unreachable for the entire life of the session
    # (hours), with the only notice on stderr where MCP clients bury it.
    # Walking to the next free port keeps every instance reachable.
    local port_args=()
    local host_port=""
    local candidate
    for candidate in $(seq "$CONTAINER_PORT" $((CONTAINER_PORT + DASHBOARD_PORT_SCAN - 1))); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$candidate") 2>/dev/null; then
            continue  # connect succeeded => something is listening
        fi
        host_port="$candidate"
        break
    done

    if [[ -n "$host_port" ]]; then
        port_args=(-p "$host_port:8082")
        if [[ "$host_port" != "$CONTAINER_PORT" ]]; then
            echo "[*] Port $CONTAINER_PORT is in use - using $host_port for the dashboard." >&2
        fi
        echo "[*] Dashboard will be available at: http://127.0.0.1:$host_port/dashboard/" >&2
        echo "[*] (the server logs the ?token=... URL to stderr on startup)" >&2
    else
        echo "[*] Ports $CONTAINER_PORT-$((CONTAINER_PORT + DASHBOARD_PORT_SCAN - 1)) all in use -" \
             "starting without the dashboard port." >&2
    fi

    # In stdio mode stdout IS the JSON-RPC channel. Third-party libraries print
    # banners to stdout at import time (e.g. XLMMacroDeobfuscator, pulled in by
    # oletools), which corrupts the stream for a strict MCP client. MCP stdio is
    # newline-delimited JSON, so pass through only lines that are JSON objects.
    $RUNTIME run -i \
        "${COMMON_ARGS[@]}" \
        -e ARKANA_DASHBOARD_HOST=0.0.0.0 \
        "${port_args[@]}" \
        "$IMAGE_NAME" \
        --mcp-server \
        --samples-path "$CONTAINER_SAMPLES" \
        "$@" | grep --line-buffered '^{'
}

cmd_analyze() {
    ensure_image
    local file="$1"
    shift

    if [[ ! -f "$file" ]]; then
        echo "Error: File not found: $file"
        exit 1
    fi

    local abs_file
    abs_file="$(cd "$(dirname "$file")" && pwd)/$(basename "$file")"
    local dir
    dir="$(dirname "$abs_file")"
    local base
    base="$(basename "$abs_file")"

    echo "[*] Analyzing: $abs_file"
    build_common_args
    $RUNTIME run -it \
        "${COMMON_ARGS[@]}" \
        -v "$dir:/app/input:ro${SELINUX_SUFFIX}" \
        -e "ARKANA_PATH_MAP=$CONTAINER_SAMPLES=$SAMPLES_DIR;/app/input=$dir" \
        "$IMAGE_NAME" \
        --input-file "/app/input/$base" --verbose \
        "$@"
}

cmd_shell() {
    ensure_image
    build_common_args
    echo "[*] Opening shell in Arkana container..."
    $RUNTIME run -it \
        "${COMMON_ARGS[@]}" \
        --entrypoint /bin/bash \
        "$IMAGE_NAME"
}

show_help() {
    cat <<'EOF'
Arkana Container Helper

Usage:
  ./run.sh [--samples <dir>] <command>

Commands:
  (default)                              Start HTTP MCP server
  --stdio                                Start stdio MCP server
  --analyze <file> [opts]                Analyze a file in CLI mode
  --build                                Build/rebuild the container image
  --shell                                Open a shell in the container
  --help                                 Show this help

Options:
  --samples <dir>   Mount a custom directory read-only into the container.
                    The container path mirrors the host folder name
                    (e.g. --samples ~/Downloads → /Downloads inside).
                    Default: ./samples/ next to this script (→ /samples).
  --output <dir>    Mount a writable output directory into the container at /output.
                    Used for project exports, patched binaries, and reports.
                    Default: ./output/ next to this script.
  --cache <dir>     Mount a cache/config directory into the container at /app/home/.arkana.
                    Persists analysis cache, notes, and tool history across sessions.
                    Default: ~/.arkana (auto-created if missing).
  --rootfs <dir>    Mount a Qiling rootfs directory into the container.
                    Place Windows DLLs, Linux libs, etc. here for emulation.
                    Default: ./qiling-rootfs/ next to this script.
                    See docs/QILING_ROOTFS.md for setup instructions.

Environment variables:
  VT_API_KEY        VirusTotal API key (passed into container)
  ARKANA_PORT       Host port for HTTP mode / first dashboard port in stdio mode (default: 8082)
  ARKANA_DASHBOARD_PORT_SCAN
                    How many consecutive ports stdio mode tries for the dashboard
                    when ARKANA_PORT is busy (default: 10)
  ARKANA_SAMPLES    Default samples directory (overridden by --samples)
  ARKANA_OUTPUT     Default output directory (overridden by --output)
  ARKANA_CACHE      Default cache/config directory (overridden by --cache)
  ARKANA_ROOTFS     Default Qiling rootfs directory (overridden by --rootfs)

Examples:
  ./run.sh                                         # HTTP server, default samples/
  ./run.sh --stdio                                 # stdio server for Claude Code
  ./run.sh --samples ~/malware-zoo --stdio         # Mounted at /malware-zoo
  ./run.sh --analyze samples/suspicious.exe        # Analyze a single file
  ./run.sh --rootfs ~/qiling-rootfs                # Custom rootfs for Qiling
  VT_API_KEY=abc123 ARKANA_PORT=9000 ./run.sh      # Custom port + API key
  ARKANA_SAMPLES=~/samples ./run.sh --stdio        # Via environment variable

Notes:
  - Sample files are mounted read-only; the output directory is writable
  - The container path mirrors the host folder name
    (e.g. --samples ~/Downloads → /Downloads/yourfile.exe inside the container)
  - Default samples: ./samples/ → /samples/yourfile.exe
  - Default output: ./output/ → /output/ (writable, for exports and patched binaries)
  - Analysis cache persists in ~/.arkana (bind-mounted into the container)
  - Auto-detects Docker or Podman
EOF
}

# --- Parse all arguments, separating global flags from command + extras ---
COMMAND=""
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --samples)
            if [[ $# -lt 2 ]]; then
                echo "Error: --samples requires a directory path."
                exit 1
            fi
            SAMPLES_DIR="$(cd "$2" 2>/dev/null && pwd)" || {
                echo "Error: Samples directory not found: $2"
                exit 1
            }
            CONTAINER_SAMPLES="/$(basename "$SAMPLES_DIR")"
            shift 2
            ;;
        --rootfs)
            if [[ $# -lt 2 ]]; then
                echo "Error: --rootfs requires a directory path."
                exit 1
            fi
            ROOTFS_DIR="$(cd "$2" 2>/dev/null && pwd)" || {
                echo "Error: Rootfs directory not found: $2"
                exit 1
            }
            shift 2
            ;;
        --output)
            if [[ $# -lt 2 ]]; then
                echo "Error: --output requires a directory path."
                exit 1
            fi
            OUTPUT_DIR="$(mkdir -p "$2" 2>/dev/null; cd "$2" 2>/dev/null && pwd)" || {
                echo "Error: Cannot create/access output directory: $2"
                exit 1
            }
            shift 2
            ;;
        --cache)
            if [[ $# -lt 2 ]]; then
                echo "Error: --cache requires a directory path."
                exit 1
            fi
            CACHE_DIR="$(mkdir -p "$2" 2>/dev/null; cd "$2" 2>/dev/null && pwd)" || {
                echo "Error: Cannot create/access cache directory: $2"
                exit 1
            }
            shift 2
            ;;
        --help|-h|--build|--stdio|--analyze|--shell)
            COMMAND="$1"
            shift
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

# --- Main ---
case "${COMMAND:-}" in
    --help|-h)
        show_help
        ;;
    --build)
        build_image
        ;;
    --stdio)
        cmd_stdio "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
        ;;
    --analyze)
        if [[ ${#EXTRA_ARGS[@]} -lt 1 ]]; then
            echo "Error: --analyze requires a file path."
            echo "Usage: ./run.sh --analyze <file>"
            exit 1
        fi
        cmd_analyze "${EXTRA_ARGS[@]}"
        ;;
    --shell)
        cmd_shell
        ;;
    *)
        cmd_http "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
        ;;
esac
