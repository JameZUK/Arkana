"""Centralized state management for analyzed files.

Supports per-session state isolation via ``StateProxy`` and ``contextvars``.
In stdio mode (single client) the default state is used transparently.
In HTTP mode each MCP session gets its own ``AnalyzerState`` instance so
concurrent clients cannot interfere with each other.
"""
import contextvars
import copy
import datetime
import logging
import os
import sys
import time
import threading
import uuid
import weakref
from collections import deque
from typing import Dict, Any, Optional, List

logger = logging.getLogger("Arkana")


class ResettableLock:
    """A ``threading.Lock`` replacement that supports ``force_reset()``.

    When a file switch occurs while a background thread holds this lock
    (e.g. stuck inside angr's Decompiler C extension), ``force_reset()``
    releases the underlying lock and increments a generation counter.
    The stale thread's later ``release()`` becomes a no-op because its
    generation no longer matches.

    API-compatible with ``threading.Lock`` — callers use ``acquire()``
    (returns *bool*) and ``release()`` (no arguments) unchanged.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._generation: int = 0
        self._holder_gen: dict = {}        # thread_id → generation at acquisition
        self._meta_lock = threading.Lock()  # serializes gen check + release
        self._last_force_reset: float = 0.0

    def acquire(self, timeout=-1, blocking=True) -> bool:
        """Acquire the lock.  Same API as ``threading.Lock.acquire``."""
        # Capture generation BEFORE acquiring to close the race window:
        # if force_reset fires between _lock.acquire and _holder_gen write,
        # we record the pre-reset generation, so our release() becomes a
        # no-op (correct behaviour — we acquired under the old generation).
        gen_at_acquire = self._generation
        if timeout == -1 and blocking:
            result = self._lock.acquire()
        elif not blocking:
            result = self._lock.acquire(blocking=False)
        else:
            result = self._lock.acquire(timeout=timeout)
        if result:
            with self._meta_lock:
                self._holder_gen[threading.get_ident()] = gen_at_acquire
        return result

    def release(self):
        """Release the lock.  Silently ignored if generation changed (stale)."""
        tid = threading.get_ident()
        with self._meta_lock:
            holder_gen = self._holder_gen.pop(tid, -1)
            if holder_gen == self._generation:
                try:
                    self._lock.release()
                except RuntimeError:
                    pass  # Already force-released
            # Periodic cleanup: if holder_gen has grown (dead threads), prune
            if len(self._holder_gen) > 10:
                alive = {t.ident for t in threading.enumerate()}
                self._holder_gen = {k: v for k, v in self._holder_gen.items() if k in alive}

    def force_reset(self):
        """Force-release and invalidate all current holders.

        Called on file switch so new threads can acquire the lock
        immediately, without waiting for a stale C-extension call.
        """
        with self._meta_lock:
            self._generation += 1
            self._holder_gen.clear()
            self._last_force_reset = time.time()
            try:
                self._lock.release()
            except RuntimeError:
                pass  # Lock was not held


    def __repr__(self):
        return f"<ResettableLock gen={self._generation} holders={len(self._holder_gen)}>"


# Stable session ID map — avoids id() reuse after GC.
_session_id_map: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_session_id_map_lock = threading.Lock()

# Maximum number of completed/failed background tasks to retain per session.
MAX_COMPLETED_TASKS = 50

# Maximum number of tool history entries to retain per session.
MAX_TOOL_HISTORY = 500
MAX_NOTES = 10_000
MAX_ARTIFACTS = 1_000
MAX_RENAMES = 10_000
MAX_TRIAGE_STATUS = 100_000
MAX_HYPOTHESIS_EVIDENCE = 50

# Stale session TTL in seconds (1 hour).
SESSION_TTL_SECONDS = 3600

# Maximum number of concurrent active sessions in the registry (HTTP mode).
# Prevents unbounded memory growth from session flooding.
try:
    MAX_ACTIVE_SESSIONS = max(1, int(os.environ.get("ARKANA_MAX_SESSIONS", "100")))
except (TypeError, ValueError):
    MAX_ACTIVE_SESSIONS = 100

# Task status constants — use these instead of raw strings to prevent typo bugs.
TASK_RUNNING = "running"
TASK_OVERTIME = "overtime"  # Soft timeout exceeded, task still running
TASK_COMPLETED = "completed"
TASK_FAILED = "failed"


class AnalyzerState:
    """Per-session state for a single analyzed file."""
    def __init__(self):
        self._state_uuid: str = str(uuid.uuid4())
        self.filepath: Optional[str] = None
        self.pe_data: Optional[Dict[str, Any]] = None
        self._pe_data_shared: bool = False  # True when pe_data is a shared reference from _default_state
        self.pe_object: Optional[Any] = None  # pefile.PE or MockPE
        self._inherited_pe_object: bool = False  # True if pe_object was inherited from _default_state
        # Cache-hit fast-load deferred-promote flag. When True, ``pe_object``
        # was constructed with ``fast_load=True`` (headers + sections only)
        # and tools that need directory parsing should call
        # ``state.pe_object.full_load()`` first. ``_check_pe_object`` does
        # this lazily on the first call with ``require_headers=True``.
        self._pe_object_needs_full_load: bool = False
        self.pefile_version: Optional[str] = None
        self.loaded_from_cache: bool = False

        # Path sandboxing for network-exposed MCP servers
        self.allowed_paths: Optional[List[str]] = None  # None = no restriction

        # Samples directory path (configured via --samples-path or ARKANA_SAMPLES env var)
        self.samples_path: Optional[str] = None

        # API key for HTTP bearer token authentication (None = no auth required)
        self.api_key: Optional[str] = None

        # Dashboard token (set by dashboard app on startup)
        self.dashboard_token: Optional[str] = None

        # PE close guard
        self._pe_lock = threading.Lock()

        # Angr State
        self._angr_lock = threading.Lock()
        self.angr_project = None
        self.angr_cfg = None
        self.angr_loop_cache = None
        self.angr_loop_cache_config = None
        self.angr_hooks: Dict[str, Dict[str, Any]] = {}  # addr_hex -> hook info
        self._cfg_null_artifact_count: int = 0  # null-byte disassembly artifacts filtered out
        self._cfg_quality: Optional[Dict[str, Any]] = None  # CFG build quality metadata

        # Background Tasks
        self._task_lock = threading.Lock()
        self.background_tasks: Dict[str, Dict[str, Any]] = {}
        self._task_cancel_events: Dict[str, threading.Event] = {}   # task_id -> cancel flag
        self._background_threads: Dict[str, threading.Thread] = {}  # task_id -> thread ref
        self._analysis_generation: int = 0  # Incremented on open_file/close_file

        # Notes (persisted per-binary via the active project's overlay)
        self._notes_lock = threading.Lock()
        self._notes_counter: int = 0
        self.notes: List[Dict[str, Any]] = []

        # Tool History (per-session, flushed to project overlay on close_file
        # and by the background _overlay_flush_loop daemon every 30s)
        self._history_lock = threading.Lock()
        self.tool_history: deque = deque(maxlen=MAX_TOOL_HISTORY)

        # Artifacts (extracted files, persisted per-binary via project overlay)
        self._artifacts_lock = threading.Lock()
        self._artifacts_counter: int = 0
        self.artifacts: List[Dict[str, Any]] = []

        # Renames (persisted per-binary via project overlay; also mirrored
        # into the BSim signature DB by _sync_renames_to_bsim for cross-
        # variant transfer_annotations)
        self._renames_lock = threading.Lock()
        self.renames: Dict[str, Any] = {
            "functions": {},   # addr_hex -> new_name
            "variables": {},   # func_addr_hex -> {old_name: new_name}
            "labels": {},      # addr_hex -> {"name": str, "category": str}
        }

        # Triage status (persisted per-binary via project overlay)
        self._triage_lock = threading.Lock()
        self.triage_status: Dict[str, str] = {}  # addr_hex -> "unreviewed"|"suspicious"|"clean"|"flagged"

        # Custom types (persisted per-binary via project overlay)
        self._types_lock = threading.Lock()
        self.custom_types: Dict[str, Any] = {
            "structs": {},   # name -> {"fields": [...], "size": int, "created_at": str}
            "enums": {},     # name -> {"values": {name: int}, "size": int, "created_at": str}
        }

        # Previous session context (populated from the project overlay's
        # tool_history field on open_file → apply_overlay)
        self.previous_session_history: List[Dict[str, Any]] = []

        # Cached analysis results for progressive disclosure tools.
        # M-13: These _cached_* fields rely on CPython's GIL for atomic
        # reference assignment (single STORE_NAME bytecode).  Readers see
        # either the old or new dict reference — never a half-written one.
        # This is safe because each field is only ever replaced wholesale
        # (state._cached_X = new_dict), never mutated in place after
        # assignment.  Compound read-modify-write operations on these
        # fields would NOT be safe without an explicit lock.
        self._cached_triage: Optional[Dict[str, Any]] = None
        self._cached_function_scores: Optional[List[Dict[str, Any]]] = None
        self.last_digest_timestamp: float = 0.0

        # Enrichment cached results (populated by background auto-enrichment)
        self._cached_classification: Optional[Dict[str, Any]] = None
        self._cached_similarity_hashes: Optional[Dict[str, Any]] = None
        self._cached_mitre_mapping: Optional[Dict[str, Any]] = None
        self._cached_iocs: Optional[Dict[str, Any]] = None

        # Extended enrichment cached results (populated by background auto-enrichment)
        self._cached_malware_family: Optional[Dict[str, Any]] = None
        self._cached_api_hashes: Optional[Dict[str, Any]] = None
        self._cached_c2_indicators: Optional[Dict[str, Any]] = None
        self._cached_dga_indicators: Optional[Dict[str, Any]] = None
        self._cached_crypto_constants: Optional[Dict[str, Any]] = None

        # Sandbox report (imported via tools_sandbox.import_sandbox_report)
        self._sandbox_report: Optional[Dict[str, Any]] = None

        # Go binary metadata (populated by go_analyze, used by ABI annotations)
        self._cached_go_version: str = ""
        self._cached_go_abi_detected: Optional[bool] = None

        # Coverage data (populated by import_coverage_data)
        self._cached_coverage: Optional[Dict[str, Any]] = None

        # Decompilation priority control (background vs on-demand)
        self._decompile_lock = ResettableLock()
        self._decompile_on_demand_count: int = 0  # Atomic counter for on-demand decompile requests

        # Enrichment cancellation and generation tracking
        self._enrichment_cancel = threading.Event()
        self._enrichment_generation: int = 0
        self._enrichment_gen_lock = threading.Lock()

        # Newly-decompiled notification queue (SSE push to dashboard)
        self._newly_decompiled: deque = deque(maxlen=200)

        # Active tool tracking (for dashboard live status)
        self._active_tool_lock = threading.Lock()
        self.active_tool: Optional[str] = None
        self._active_tools: List[str] = []
        self.active_tool_progress: int = 0
        self.active_tool_total: int = 100

        # Paginated result cache (LRU per-tool, 5 slots each)
        from arkana.mcp._input_helpers import _ToolResultCache
        self.result_cache = _ToolResultCache()

        # Analysis warnings (captured from library loggers, session-scoped)
        from arkana.constants import MAX_ANALYSIS_WARNINGS
        self._warnings_lock = threading.Lock()
        self.analysis_warnings: deque = deque(maxlen=MAX_ANALYSIS_WARNINGS)
        self._warning_dedup: Dict[tuple, Dict[str, Any]] = {}  # (logger, level, msg[:100]) -> entry

        # Timestamp of last activity (for session TTL cleanup)
        self.last_active: float = time.time()
        self._closing: bool = False  # True when session is being cleaned up

        # Per-state throttle and lock for async decompile cache saves (enrichment.py)
        self._last_decompile_save_time: float = 0.0
        self._async_save_lock: threading.Lock = threading.Lock()

        # Debug Sessions (managed by tools_debug._DebugSessionManager)
        self._debug_manager = None  # Lazily created _DebugSessionManager

        # Emulation Inspect Sessions (managed by tools_emulate_inspect._EmulationSessionManager)
        self._emulation_manager = None  # Lazily created _EmulationSessionManager

        # Active project binding. ``Project`` (real, on-disk) or
        # ``ScratchProject`` (in-memory, promoted on first state mutation).
        # None when no file has been opened yet. See ``arkana/projects.py``.
        self.active_project: Optional[Any] = None
        self._project_lock = threading.RLock()
        self._overlay_dirty: bool = False

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Thread-safe read of a background task."""
        with self._task_lock:
            task = self.background_tasks.get(task_id)
            return dict(task) if task else None

    def set_task(self, task_id: str, task_data: Dict[str, Any]):
        """Thread-safe creation/replacement of a background task."""
        with self._task_lock:
            self.background_tasks[task_id] = task_data
            self._evict_old_tasks()

    def update_task(self, task_id: str, **kwargs):
        """Thread-safe partial update of a background task's fields."""
        with self._task_lock:
            if task_id in self.background_tasks:
                self.background_tasks[task_id].update(kwargs)

    def get_all_task_ids(self) -> List[str]:
        """Thread-safe snapshot of current task IDs."""
        with self._task_lock:
            return list(self.background_tasks.keys())

    # ------------------------------------------------------------------
    # Thread-safe accessors for _task_cancel_events / _background_threads
    # ------------------------------------------------------------------
    # These dicts accompany ``background_tasks`` but were historically
    # accessed without ``_task_lock``.  The helpers below ensure all
    # mutations go through a single lock, closing race windows with
    # ``cancel_all_background_tasks``, the session reaper, and worker
    # finally-blocks — especially important for future free-threaded
    # Python builds (PEP 703).

    def register_task_infra(
        self,
        task_id: str,
        cancel_event: "threading.Event",
        thread: "Optional[threading.Thread]" = None,
    ) -> None:
        """Register a cancel event (and optional thread) for *task_id*.

        Must be called **before** ``set_task(task_id, ...)`` so that
        ``cancel_all_background_tasks()`` can always find the event once
        the task is visible as RUNNING.
        """
        with self._task_lock:
            self._task_cancel_events[task_id] = cancel_event
            if thread is not None:
                self._background_threads[task_id] = thread

    def set_task_thread(self, task_id: str, thread: "threading.Thread") -> None:
        """Register (or update) the thread reference for *task_id*."""
        with self._task_lock:
            self._background_threads[task_id] = thread

    def unregister_task_infra(self, task_id: str) -> None:
        """Remove cancel event and thread ref for a completed/failed task."""
        with self._task_lock:
            self._task_cancel_events.pop(task_id, None)
            self._background_threads.pop(task_id, None)

    def get_cancel_event(self, task_id: str) -> "Optional[threading.Event]":
        """Return the cancel event for *task_id*, or ``None``."""
        with self._task_lock:
            return self._task_cancel_events.get(task_id)

    def check_path_allowed(self, file_path: str) -> None:
        """Raise RuntimeError if the path is outside all allowed directories."""
        import os
        from pathlib import Path
        if self.allowed_paths is None:
            return  # No restriction configured
        resolved = Path(os.path.realpath(file_path))
        for allowed in self.allowed_paths:
            allowed_resolved = Path(os.path.realpath(allowed))
            # Allow if the file is exactly the allowed path or inside it
            if resolved == allowed_resolved or resolved.is_relative_to(allowed_resolved):
                return
        # M-S6: Don't disclose the attempted path — it confirms path existence
        raise RuntimeError(
            "Access denied: the requested path is outside the allowed directories. "
            "Configure with --allowed-paths at server startup."
        )

    def touch(self):
        """Update the last-active timestamp (called by the tool decorator)."""
        if self._closing:
            return
        self.last_active = time.time()

    def push_active_tool(self, name: str):
        """Register a tool as actively running (thread-safe)."""
        with self._active_tool_lock:
            self._active_tools.append(name)
            self.active_tool = name

    def pop_active_tool(self, name: str):
        """Unregister a tool as actively running (thread-safe)."""
        with self._active_tool_lock:
            try:
                self._active_tools.remove(name)
            except ValueError:
                pass
            self.active_tool = self._active_tools[-1] if self._active_tools else None

    def get_active_tools(self) -> list:
        """Return a snapshot of all currently active tools (thread-safe)."""
        with self._active_tool_lock:
            return list(self._active_tools)

    def increment_generation(self) -> int:
        """Increment analysis generation counter.

        Called by ``reset_angr()`` during file switches.  Safe because callers
        are serialized by the tool decorator's session activation (or, in the
        session reaper, operate on evicted sessions with no concurrent writers).
        Returns new value.
        """
        self._analysis_generation += 1
        return self._analysis_generation

    def cancel_all_background_tasks(self):
        """Cancel all running/overtime background tasks and mark them FAILED.

        Called during force file switch to ensure no stale tasks persist.
        """
        with self._task_lock:
            for _tid, task in list(self.background_tasks.items()):
                if task.get("status") in (TASK_RUNNING, TASK_OVERTIME):
                    task["status"] = TASK_FAILED
                    task["error"] = "File was switched during analysis."
                    task["progress_message"] = "Discarded — file switched"
                    task["aborted"] = True
            # Snapshot cancel events under the same lock for a consistent read
            cancel_snapshot = list(self._task_cancel_events.values())
        # Set events outside _task_lock — workers' finally blocks acquire it
        for cancel in cancel_snapshot:
            cancel.set()

        # Force-release the decompile lock so new enrichment isn't blocked
        # by a stale thread stuck in an uninterruptible C extension call.
        self._decompile_lock.force_reset()
        self._decompile_on_demand_count = 0

    def _evict_old_tasks(self):
        """Remove oldest completed/failed tasks when the count exceeds the limit.

        Must be called while ``_task_lock`` is held.
        """
        finished = [
            (tid, t) for tid, t in self.background_tasks.items()
            if t.get("status") in (TASK_COMPLETED, TASK_FAILED)
        ]
        if len(finished) <= MAX_COMPLETED_TASKS:
            return
        # Sort by numeric epoch (oldest first) and remove excess
        finished.sort(key=lambda item: item[1].get("created_at_epoch", 0))
        to_remove = len(finished) - MAX_COMPLETED_TASKS
        for tid, _ in finished[:to_remove]:
            del self.background_tasks[tid]

    # ------------------------------------------------------------------
    #  Notes accessors
    # ------------------------------------------------------------------

    def add_note(self, content: str, category: str = "general",
                 address: Optional[str] = None, tool_name: Optional[str] = None,
                 confidence: Optional[float] = None, status: Optional[str] = None,
                 evidence: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Thread-safe note creation. Returns the new note dict.

        For hypothesis notes, extra fields are attached:
        - confidence (float 0.0-1.0, default 0.5)
        - hypothesis_status (proposed/investigating/supported/refuted/confirmed)
        - evidence (list of evidence dicts)
        - superseded_by (note ID or None)
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        epoch = time.time()
        with self._notes_lock:
            if len(self.notes) >= MAX_NOTES:
                raise RuntimeError(f"Notes limit reached ({MAX_NOTES}). Delete old notes before adding new ones.")
            self._notes_counter += 1
            note: Dict[str, Any] = {
                "id": f"n_{int(now.timestamp() * 1000000)}_{self._notes_counter}",
                "category": category,
                "address": address,
                "tool_name": tool_name,
                "content": content,
                "created_at": now.isoformat(),
                "created_at_epoch": epoch,
                "updated_at": now.isoformat(),
            }
            if category == "hypothesis":
                note["confidence"] = max(0.0, min(1.0, confidence)) if confidence is not None else 0.5
                _valid_statuses = ("proposed", "investigating", "supported", "refuted", "confirmed")
                note["hypothesis_status"] = status if status in _valid_statuses else "proposed"
                note["evidence"] = list(evidence)[:MAX_HYPOTHESIS_EVIDENCE] if evidence else []
                note["superseded_by"] = None
            self.notes.append(note)
            result = dict(note)
        self._maybe_promote_scratch()
        return result

    def get_notes(self, category: Optional[str] = None,
                  address: Optional[str] = None) -> List[Dict[str, Any]]:
        """Thread-safe filtered read of notes. Returns copies."""
        with self._notes_lock:
            result = [dict(n) for n in self.notes]
        if category:
            result = [n for n in result if n.get("category") == category]
        if address:
            result = [n for n in result if n.get("address") == address]
        return result

    def update_note(self, note_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Thread-safe partial update. Returns updated note or None.

        For hypothesis notes, also accepts: confidence, hypothesis_status,
        evidence (appended, not replaced), superseded_by.
        """
        with self._notes_lock:
            for note in self.notes:
                if note["id"] == note_id:
                    for k, v in kwargs.items():
                        if k in ("content", "category", "address", "tool_name") and v is not None:
                            note[k] = v
                    # Hypothesis-specific fields
                    if note.get("category") == "hypothesis":
                        if "confidence" in kwargs and kwargs["confidence"] is not None:
                            note["confidence"] = max(0.0, min(1.0, kwargs["confidence"]))
                        if "hypothesis_status" in kwargs and kwargs["hypothesis_status"] is not None:
                            _valid_statuses = ("proposed", "investigating", "supported", "refuted", "confirmed")
                            if kwargs["hypothesis_status"] in _valid_statuses:
                                note["hypothesis_status"] = kwargs["hypothesis_status"]
                        if "evidence" in kwargs and kwargs["evidence"] is not None:
                            existing = note.get("evidence", [])
                            new_item = kwargs["evidence"]
                            if isinstance(new_item, dict):
                                if len(existing) < MAX_HYPOTHESIS_EVIDENCE:
                                    existing.append(new_item)
                                    note["evidence"] = existing
                            elif isinstance(new_item, list):
                                remaining = MAX_HYPOTHESIS_EVIDENCE - len(existing)
                                existing.extend(new_item[:remaining])
                                note["evidence"] = existing
                        if "superseded_by" in kwargs:
                            note["superseded_by"] = kwargs["superseded_by"]
                    note["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    return dict(note)
        return None

    def delete_note(self, note_id: str) -> bool:
        """Thread-safe note removal. Returns True if found and deleted."""
        with self._notes_lock:
            for i, note in enumerate(self.notes):
                if note["id"] == note_id:
                    self.notes.pop(i)
                    return True
        return False

    def clear_notes(self) -> int:
        """Thread-safe clear of all notes. Returns count of notes removed."""
        with self._notes_lock:
            count = len(self.notes)
            self.notes = []
            self._notes_counter = 0
            return count

    def get_all_notes_snapshot(self) -> List[Dict[str, Any]]:
        """Thread-safe snapshot of all notes for cache persistence."""
        with self._notes_lock:
            return [dict(n) for n in self.notes]

    # ------------------------------------------------------------------
    #  Tool history accessors
    # ------------------------------------------------------------------

    def record_tool_call(self, tool_name: str, parameters: Dict[str, Any],
                         result_summary: str, duration_ms: int) -> None:
        """Thread-safe recording of a tool invocation."""
        # M2-v14: Snapshot pe_data under lock to avoid racing with open_file
        with self._pe_lock:
            _pd = self.pe_data
        entry: Dict[str, Any] = {
            "tool_name": tool_name,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "timestamp_epoch": time.time(),
            "parameters": parameters,
            "result_summary": result_summary,
            "duration_ms": duration_ms,
            "sha256": (_pd or {}).get("file_hashes", {}).get("sha256"),
        }
        with self._history_lock:
            self.tool_history.append(entry)

    def get_tool_history(self, tool_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Thread-safe filtered read of tool history."""
        with self._history_lock:
            result = list(self.tool_history)
        if tool_name:
            result = [h for h in result if h.get("tool_name") == tool_name]
        return result

    def clear_tool_history(self) -> int:
        """Thread-safe clear. Returns count of entries removed."""
        with self._history_lock:
            count = len(self.tool_history)
            self.tool_history.clear()
            return count

    def get_tool_history_snapshot(self) -> List[Dict[str, Any]]:
        """Thread-safe snapshot of history for cache persistence."""
        with self._history_lock:
            return list(self.tool_history)

    def get_tool_history_count(self) -> int:
        """L2-v8: Thread-safe count without copying the full deque."""
        with self._history_lock:
            return len(self.tool_history)

    def get_ran_tool_names(self) -> set:
        """L2-v8: Thread-safe set of tool names without copying the full deque."""
        with self._history_lock:
            return {h.get("tool_name") for h in self.tool_history}

    # ------------------------------------------------------------------
    #  Artifact accessors
    # ------------------------------------------------------------------

    def register_artifact(self, path: str, sha256: str, md5: str,
                          size: int, source_tool: str, description: str,
                          detected_type: Optional[str] = None,
                          *,
                          kind: str = "file",
                          original_path: Optional[str] = None,
                          project_relative: Optional[str] = None,
                          members: Optional[List[Dict[str, Any]]] = None,
                          tags: Optional[List[str]] = None,
                          notes: str = "") -> Dict[str, Any]:
        """Thread-safe artifact registration. Returns the new artifact dict.

        Schema fields:
            id, path, sha256, md5, size, source_tool, description, detected_type,
            kind ('file'|'directory'), original_path, project_relative,
            tags, notes, created_at, modified_at.
            For kind='directory': members[] (list of {relative, size, sha256}),
            member_count, total_size.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        now_iso = now.isoformat()
        with self._artifacts_lock:
            if len(self.artifacts) >= MAX_ARTIFACTS:
                raise RuntimeError(f"Artifacts limit reached ({MAX_ARTIFACTS}). Clear old artifacts before registering new ones.")
            self._artifacts_counter += 1
            artifact: Dict[str, Any] = {
                "id": f"art_{int(now.timestamp() * 1000000)}_{self._artifacts_counter}",
                "kind": kind,
                "path": path,
                "original_path": original_path or path,
                "project_relative": project_relative,
                "sha256": sha256,
                "md5": md5,
                "size": size,
                "source_tool": source_tool,
                "description": description,
                "detected_type": detected_type,
                "tags": list(tags or []),
                "notes": notes or "",
                "created_at": now_iso,
                "modified_at": now_iso,
            }
            if kind == "directory":
                mlist = list(members or [])
                artifact["members"] = mlist
                artifact["member_count"] = len(mlist)
                artifact["total_size"] = sum(int(m.get("size", 0)) for m in mlist)
            self.artifacts.append(artifact)
            result = dict(artifact)
        self._maybe_promote_scratch()
        return result

    def update_artifact_metadata(self, artifact_id: str, *,
                                 description: Optional[str] = None,
                                 tags: Optional[List[str]] = None,
                                 notes: Optional[str] = None,
                                 replace_tags: bool = False) -> Optional[Dict[str, Any]]:
        """Thread-safe partial update of artifact metadata.

        - description: replaces if not None
        - tags: appended (deduped) unless replace_tags=True, in which case replaces
        - notes: replaces if not None
        Updates modified_at timestamp on any change. Returns the updated dict
        or None if not found.
        """
        if description is None and tags is None and notes is None:
            return None
        with self._artifacts_lock:
            for art in self.artifacts:
                if art.get("id") == artifact_id:
                    if description is not None:
                        art["description"] = description
                    if notes is not None:
                        art["notes"] = notes
                    if tags is not None:
                        if replace_tags:
                            art["tags"] = list(dict.fromkeys(tags))
                        else:
                            existing = list(art.get("tags") or [])
                            seen = set(existing)
                            for t in tags:
                                if t not in seen:
                                    existing.append(t)
                                    seen.add(t)
                            art["tags"] = existing
                    art["modified_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    updated = dict(art)
                    self._maybe_promote_scratch()
                    return updated
        return None

    def delete_artifact(self, artifact_id: str) -> bool:
        """Thread-safe artifact removal by ID. Returns True if found and removed."""
        with self._artifacts_lock:
            for i, art in enumerate(self.artifacts):
                if art.get("id") == artifact_id:
                    self.artifacts.pop(i)
                    self._maybe_promote_scratch()
                    return True
        return False

    def delete_artifacts_batch(self, artifact_ids: List[str]) -> Dict[str, bool]:
        """Delete many artifacts in one locked pass — replaces N×O(L) scans
        with one O(L+N) sweep where L = total artifact count.

        Returns ``{artifact_id: True/False}`` for every input id, where
        True means the id was found and removed. Used by the dashboard's
        bulk delete endpoint to avoid an O(L*N) lock-acquire-and-scan
        pattern that pinned the artifact lock under heavy bulk operations.
        """
        wanted = set(artifact_ids)
        if not wanted:
            return {}
        result: Dict[str, bool] = {aid: False for aid in artifact_ids}
        with self._artifacts_lock:
            kept: List[Dict[str, Any]] = []
            removed_any = False
            for art in self.artifacts:
                aid = art.get("id")
                if aid in wanted:
                    result[aid] = True
                    wanted.discard(aid)
                    removed_any = True
                    continue
                kept.append(art)
            if removed_any:
                self.artifacts = kept
                self._maybe_promote_scratch()
        return result

    def update_artifacts_metadata_batch(self, artifact_ids: List[str], *,
                                        description: Optional[str] = None,
                                        tags: Optional[List[str]] = None,
                                        notes: Optional[str] = None,
                                        replace_tags: bool = False
                                        ) -> Dict[str, Optional[Dict[str, Any]]]:
        """Apply the same metadata patch to many artifacts in one locked pass.

        Returns ``{artifact_id: updated_dict_or_None}``. Patch semantics
        mirror ``update_artifact_metadata`` (per-id description/tags/notes).
        Uses an id-indexed dict built once under the lock so total cost
        is O(L + N) instead of O(L*N).
        """
        if description is None and tags is None and notes is None:
            return {aid: None for aid in artifact_ids}
        wanted = set(artifact_ids)
        if not wanted:
            return {}
        result: Dict[str, Optional[Dict[str, Any]]] = {aid: None for aid in artifact_ids}
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._artifacts_lock:
            # Build a single id→artifact index, then patch each requested
            # id once. The artifacts list itself isn't reordered.
            index = {a.get("id"): a for a in self.artifacts}
            updated_any = False
            for aid in artifact_ids:
                art = index.get(aid)
                if art is None:
                    continue
                if description is not None:
                    art["description"] = description
                if notes is not None:
                    art["notes"] = notes
                if tags is not None:
                    if replace_tags:
                        art["tags"] = list(dict.fromkeys(tags))
                    else:
                        existing = list(art.get("tags") or [])
                        seen = set(existing)
                        for t in tags:
                            if t not in seen:
                                existing.append(t)
                                seen.add(t)
                        art["tags"] = existing
                art["modified_at"] = now_iso
                result[aid] = dict(art)
                updated_any = True
            if updated_any:
                self._maybe_promote_scratch()
        return result

    def get_artifacts(self, source_tool: Optional[str] = None) -> List[Dict[str, Any]]:
        """Thread-safe filtered read of artifacts. Returns copies."""
        with self._artifacts_lock:
            result = [dict(a) for a in self.artifacts]
        if source_tool:
            result = [a for a in result if a.get("source_tool") == source_tool]
        return result

    def get_all_artifacts_snapshot(self) -> List[Dict[str, Any]]:
        """Thread-safe snapshot of all artifacts for cache persistence."""
        with self._artifacts_lock:
            return [dict(a) for a in self.artifacts]

    def clear_artifacts(self) -> int:
        """Thread-safe clear of all artifacts. Returns count removed."""
        with self._artifacts_lock:
            count = len(self.artifacts)
            self.artifacts = []
            self._artifacts_counter = 0
            return count

    # ------------------------------------------------------------------
    #  Rename accessors
    # ------------------------------------------------------------------

    def rename_function(self, address: str, new_name: str) -> Dict[str, Any]:
        """Thread-safe function rename. Returns the rename entry."""
        addr = address.lower()
        with self._renames_lock:
            if addr not in self.renames["functions"] and len(self.renames["functions"]) >= MAX_RENAMES:
                raise ValueError(f"Maximum rename limit ({MAX_RENAMES}) reached for functions")
            self.renames["functions"][addr] = new_name
            entry = {"address": addr, "new_name": new_name, "type": "function"}
        self._maybe_promote_scratch()
        return entry

    def rename_variable(self, func_addr: str, old_name: str, new_name: str) -> Dict[str, Any]:
        """Thread-safe variable rename within function scope."""
        faddr = func_addr.lower()
        with self._renames_lock:
            total_vars = sum(len(v) for v in self.renames["variables"].values())
            if total_vars >= MAX_RENAMES:
                # Allow update of existing entry, block new ones
                existing = self.renames["variables"].get(faddr, {})
                if old_name not in existing:
                    raise ValueError(f"Maximum rename limit ({MAX_RENAMES}) reached for variables")
            if faddr not in self.renames["variables"]:
                self.renames["variables"][faddr] = {}
            self.renames["variables"][faddr][old_name] = new_name
            entry = {"function_address": faddr, "old_name": old_name, "new_name": new_name, "type": "variable"}
        self._maybe_promote_scratch()
        return entry

    def add_label(self, address: str, name: str, category: str = "general") -> Dict[str, Any]:
        """Thread-safe label creation at an address."""
        addr = address.lower()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._renames_lock:
            if addr not in self.renames["labels"] and len(self.renames["labels"]) >= MAX_RENAMES:
                raise ValueError(f"Maximum rename limit ({MAX_RENAMES}) reached for labels")
            self.renames["labels"][addr] = {"name": name, "category": category, "created_at": now}
            entry = {"address": addr, "name": name, "category": category, "type": "label"}
        self._maybe_promote_scratch()
        return entry

    def get_renames(self, rename_type: Optional[str] = None) -> Dict[str, Any]:
        """Thread-safe deep read of renames, optionally filtered by type."""
        with self._renames_lock:
            if rename_type and rename_type in self.renames:
                v = self.renames[rename_type]
                # Deep-copy dict-of-dicts (variables, labels)
                if v and isinstance(next(iter(v.values()), None), dict):
                    return {rename_type: {k2: dict(v2) for k2, v2 in v.items()}}
                return {rename_type: dict(v)}
            return {
                "functions": dict(self.renames["functions"]),
                "variables": {k: dict(v) for k, v in self.renames["variables"].items()},
                "labels": {k: dict(v) for k, v in self.renames["labels"].items()},
            }

    def delete_rename(self, address: str, rename_type: str) -> bool:
        """Thread-safe removal of a rename/label. Returns True if found."""
        addr = address.lower()
        with self._renames_lock:
            if rename_type == "function":
                removed = self.renames["functions"].pop(addr, None) is not None
            elif rename_type == "variable":
                removed = self.renames["variables"].pop(addr, None) is not None
            elif rename_type == "label":
                removed = self.renames["labels"].pop(addr, None) is not None
            else:
                removed = False
        if removed:
            self._maybe_promote_scratch()
        return removed

    def get_all_renames_snapshot(self) -> Dict[str, Any]:
        """Thread-safe snapshot for cache persistence."""
        with self._renames_lock:
            return {
                "functions": dict(self.renames["functions"]),
                "variables": {k: dict(v) for k, v in self.renames["variables"].items()},
                "labels": {k: dict(v) for k, v in self.renames["labels"].items()},
            }

    def clear_renames(self) -> int:
        """Thread-safe clear. Returns total count removed."""
        with self._renames_lock:
            count = (len(self.renames["functions"])
                     + len(self.renames["variables"])
                     + len(self.renames["labels"]))
            self.renames = {"functions": {}, "variables": {}, "labels": {}}
            return count

    def get_function_display_name(self, address: str) -> Optional[str]:
        """Return user-assigned name for a function address, or None."""
        addr = address.lower()
        with self._renames_lock:
            return self.renames["functions"].get(addr)

    # ------------------------------------------------------------------
    #  Custom type accessors
    # ------------------------------------------------------------------

    def create_struct(self, name: str, fields: list, size: int) -> Dict[str, Any]:
        """Thread-safe struct creation. Returns the struct definition."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._types_lock:
            self.custom_types["structs"][name] = {
                "fields": list(fields),
                "size": size,
                "created_at": now,
            }
            entry = {"name": name, "fields": fields, "size": size, "type": "struct", "created_at": now}
        self._maybe_promote_scratch()
        return entry

    def create_enum(self, name: str, values: dict, size: int = 4) -> Dict[str, Any]:
        """Thread-safe enum creation. Returns the enum definition."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._types_lock:
            self.custom_types["enums"][name] = {
                "values": dict(values),
                "size": size,
                "created_at": now,
            }
            entry = {"name": name, "values": values, "size": size, "type": "enum", "created_at": now}
        self._maybe_promote_scratch()
        return entry

    def get_custom_type(self, name: str) -> Optional[Dict[str, Any]]:
        """Thread-safe lookup of a custom type by name."""
        with self._types_lock:
            if name in self.custom_types["structs"]:
                result = dict(self.custom_types["structs"][name])
                result["type"] = "struct"
                result["name"] = name
                # Deep copy mutable fields list to prevent callers mutating internal state
                if "fields" in result:
                    result["fields"] = [dict(f) for f in result["fields"]]
                return result
            if name in self.custom_types["enums"]:
                result = dict(self.custom_types["enums"][name])
                result["type"] = "enum"
                result["name"] = name
                # Deep copy mutable values dict to prevent callers mutating internal state
                if "values" in result:
                    result["values"] = dict(result["values"])
                return result
        return None

    def get_all_custom_types(self) -> Dict[str, Any]:
        """Thread-safe read of all custom types (deep copies mutable nested data)."""
        with self._types_lock:
            structs = {}
            for k, v in self.custom_types["structs"].items():
                s = dict(v)
                if "fields" in s:
                    s["fields"] = [dict(f) for f in s["fields"]]
                structs[k] = s
            enums = {}
            for k, v in self.custom_types["enums"].items():
                e = dict(v)
                if "values" in e:
                    e["values"] = dict(e["values"])
                enums[k] = e
            return {"structs": structs, "enums": enums}

    def delete_custom_type(self, name: str) -> bool:
        """Thread-safe removal. Returns True if found."""
        with self._types_lock:
            if name in self.custom_types["structs"]:
                del self.custom_types["structs"][name]
                removed = True
            elif name in self.custom_types["enums"]:
                del self.custom_types["enums"][name]
                removed = True
            else:
                removed = False
        if removed:
            self._maybe_promote_scratch()
        return removed

    def get_all_types_snapshot(self) -> Dict[str, Any]:
        """Thread-safe snapshot for cache persistence (deep copies mutable nested data)."""
        with self._types_lock:
            structs = {}
            for k, v in self.custom_types["structs"].items():
                s = dict(v)
                if "fields" in s:
                    s["fields"] = [dict(f) for f in s["fields"]]
                structs[k] = s
            enums = {}
            for k, v in self.custom_types["enums"].items():
                e = dict(v)
                if "values" in e:
                    e["values"] = dict(e["values"])
                enums[k] = e
            return {"structs": structs, "enums": enums}

    def clear_custom_types(self) -> int:
        """Thread-safe clear. Returns total count removed."""
        with self._types_lock:
            count = len(self.custom_types["structs"]) + len(self.custom_types["enums"])
            self.custom_types = {"structs": {}, "enums": {}}
            return count

    # ------------------------------------------------------------------
    #  Triage status accessors
    # ------------------------------------------------------------------

    def set_triage_status(self, address: str, status: str) -> Dict[str, str]:
        """Thread-safe triage status update. Returns the entry."""
        addr = address.lower()
        if status not in ("unreviewed", "suspicious", "clean", "flagged"):
            raise ValueError(f"Invalid triage status: {status}")
        with self._triage_lock:
            if len(self.triage_status) >= MAX_TRIAGE_STATUS and addr not in self.triage_status:
                raise ValueError(f"Maximum triage status limit ({MAX_TRIAGE_STATUS}) reached")
            self.triage_status[addr] = status
            entry = {"address": addr, "status": status}
        self._maybe_promote_scratch()
        return entry

    def get_triage_status(self, address: Optional[str] = None) -> Any:
        """Thread-safe read of triage status."""
        with self._triage_lock:
            if address:
                return self.triage_status.get(address.lower(), "unreviewed")
            return dict(self.triage_status)

    def get_all_triage_snapshot(self) -> Dict[str, str]:
        """Thread-safe snapshot for cache persistence."""
        with self._triage_lock:
            return dict(self.triage_status)

    def clear_triage(self) -> int:
        """Thread-safe clear. Returns count removed."""
        with self._triage_lock:
            count = len(self.triage_status)
            self.triage_status = {}
            return count

    # ------------------------------------------------------------------
    #  Analysis warning accessors
    # ------------------------------------------------------------------

    def add_warning(self, logger_name: str, level: str, message: str,
                    tool_name: Optional[str] = None,
                    task_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Thread-safe warning capture with deduplication.

        Returns the new entry dict, or None if deduplicated (count incremented).
        Uses a deque(maxlen=MAX_ANALYSIS_WARNINGS) for O(1) eviction.
        """
        # Truncate message to prevent unbounded growth
        msg = message[:500] if len(message) > 500 else message
        dedup_key = (logger_name, level, msg[:100])
        now = time.time()

        with self._warnings_lock:
            existing = self._warning_dedup.get(dedup_key)
            if existing is not None:
                existing["count"] += 1
                existing["last_seen"] = now
                return None

            # If at capacity, deque will auto-evict the oldest on append.
            # Clean up the dedup dict for the entry that will be evicted.
            if len(self.analysis_warnings) == self.analysis_warnings.maxlen:
                oldest = self.analysis_warnings[0]
                oldest_key = (oldest["logger"], oldest["level"], oldest["message"][:100])
                self._warning_dedup.pop(oldest_key, None)

            entry: Dict[str, Any] = {
                "logger": logger_name,
                "level": level,
                "message": msg,
                "tool_name": tool_name,
                "task_id": task_id,
                "count": 1,
                "first_seen": now,
                "last_seen": now,
            }
            self.analysis_warnings.append(entry)
            self._warning_dedup[dedup_key] = entry

            # M-12: Periodic reconciliation — if _warning_dedup has grown
            # much larger than the deque (due to evicted entries whose dedup
            # keys were not cleaned up), rebuild it from current deque entries.
            max_dedup = self.analysis_warnings.maxlen * 2
            if len(self._warning_dedup) > max_dedup:
                self._warning_dedup = {
                    (w["logger"], w["level"], w["message"][:100]): w
                    for w in self.analysis_warnings
                }

            return dict(entry)

    def get_warnings(self, logger_name: Optional[str] = None,
                     level: Optional[str] = None,
                     tool_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Thread-safe filtered read of warnings. Returns copies."""
        with self._warnings_lock:
            result = [dict(w) for w in self.analysis_warnings]
        if logger_name:
            result = [w for w in result if w["logger"] == logger_name]
        if level:
            result = [w for w in result if w["level"] == level]
        if tool_name:
            result = [w for w in result if w.get("tool_name") == tool_name]
        return result

    def get_warning_count(self) -> int:
        """Quick count of unique warnings."""
        with self._warnings_lock:
            return len(self.analysis_warnings)

    def get_error_warning_count(self) -> int:
        """M10-v10: Count warnings with ERROR or CRITICAL level without copying the list."""
        with self._warnings_lock:
            return sum(1 for w in self.analysis_warnings
                       if w.get("level") in ("ERROR", "CRITICAL"))

    def clear_warnings(self) -> int:
        """Clear all warnings. Returns count removed."""
        with self._warnings_lock:
            count = len(self.analysis_warnings)
            self.analysis_warnings.clear()
            self._warning_dedup = {}
            return count

    # ------------------------------------------------------------------
    #  Angr state
    # ------------------------------------------------------------------

    def set_angr_results(self, project, cfg, loop_cache, loop_cache_config):
        """Atomically set all angr analysis results."""
        with self._angr_lock:
            self.angr_project = project
            self.angr_cfg = cfg
            self.angr_loop_cache = loop_cache
            self.angr_loop_cache_config = loop_cache_config

    def _ensure_pe_data_owned(self):
        """Deep-copy pe_data if shared, making it safe to mutate in-place.

        Called before any in-place mutation of ``pe_data`` (key assignment,
        pop, etc.) to implement copy-on-write semantics.  Read-only access
        (``get()``, ``[key]`` reads) does NOT require this call.
        """
        if self._pe_data_shared and self.pe_data is not None:
            self.pe_data = copy.deepcopy(self.pe_data)
            self._pe_data_shared = False

    def get_file_snapshot(self):
        """Return (pe_data, filepath) atomically under _pe_lock."""
        with self._pe_lock:
            return self.pe_data, self.filepath

    def get_angr_snapshot(self):
        """Return a consistent snapshot of (project, cfg)."""
        with self._angr_lock:
            return self.angr_project, self.angr_cfg

    def reset_angr(self):
        with self._angr_lock:
            self.angr_project = None
            self.angr_cfg = None
            self.angr_loop_cache = None
            self.angr_loop_cache_config = None
            self.angr_hooks = {}
        self._cfg_quality = None
        # Increment generation so stale background threads discard their results
        self.increment_generation()
        _angr_task_ids = {"startup-angr", "angr-cfg", "angr-analysis"}
        # Collect cancel events, delete tasks, and clean up thread/event refs
        # under a single lock acquisition for consistency.
        with self._task_lock:
            cancel_events = [
                self._task_cancel_events[tid]
                for tid in _angr_task_ids
                if tid in self._task_cancel_events
            ]
            for tid in list(self.background_tasks):
                if tid in _angr_task_ids:
                    del self.background_tasks[tid]
            for tid in _angr_task_ids:
                self._background_threads.pop(tid, None)
                self._task_cancel_events.pop(tid, None)
        # Set cancel events outside the lock — worker finally blocks acquire it
        for cancel in cancel_events:
            cancel.set()

    # ------------------------------------------------------------------
    #  Project binding & overlay
    # ------------------------------------------------------------------

    def bind_project(self, project: Any) -> None:
        """Bind *project* to this state. Replaces any existing binding."""
        with self._project_lock:
            self.active_project = project
            self._overlay_dirty = False

    def unbind_project(self) -> None:
        """Clear the active project binding without flushing."""
        with self._project_lock:
            self.active_project = None
            self._overlay_dirty = False

    def get_active_project(self) -> Optional[Any]:
        """Thread-safe read of the active project."""
        with self._project_lock:
            return self.active_project

    def mark_overlay_dirty(self) -> None:
        """Mark the user-mutable overlay as having unsaved changes."""
        with self._project_lock:
            self._overlay_dirty = True

    def is_overlay_dirty(self) -> bool:
        with self._project_lock:
            return self._overlay_dirty

    def snapshot_overlay(self) -> Dict[str, Any]:
        """Return a snapshot of all user-mutable state for persistence to a project overlay.

        Includes notes, tool history, artifacts, renames, custom types, triage
        flags, coverage data, and any imported sandbox report. Excludes derived
        analysis (cached enrichment, PE headers, CFG) — that lives in the
        SHA256 cache.
        """
        return {
            "notes": self.get_all_notes_snapshot(),
            "tool_history": self.get_tool_history_snapshot(),
            "artifacts": self.get_all_artifacts_snapshot(),
            "renames": self.get_all_renames_snapshot(),
            "custom_types": self.get_all_types_snapshot(),
            "triage_status": self.get_all_triage_snapshot(),
            "_cached_coverage": self._cached_coverage,
            "_sandbox_report": self._sandbox_report,
        }

    def apply_overlay(self, overlay: Dict[str, Any]) -> None:
        """Restore user-mutable state from an overlay dict.

        Acquires per-field locks to prevent concurrent readers from seeing
        partial state during restoration. Counter values are recomputed from
        the highest existing ID suffix to prevent collisions on subsequent
        creates. The ``_overlay_meta`` key (if present) is ignored.
        """
        if not overlay:
            return

        # Notes
        notes = overlay.get("notes") or []
        with self._notes_lock:
            self.notes = list(notes)
            max_suffix = 0
            for n in self.notes:
                nid = n.get("id", "")
                if isinstance(nid, str) and "_" in nid:
                    try:
                        max_suffix = max(max_suffix, int(nid.rsplit("_", 1)[-1]))
                    except (ValueError, IndexError):
                        pass
            self._notes_counter = max_suffix

        # Tool history → previous_session_history (per existing convention
        # in tools_pe.open_file: restored history isn't appended to the
        # current session deque, it's surfaced separately).
        history = overlay.get("tool_history") or []
        if history:
            self.previous_session_history = list(history)[:MAX_TOOL_HISTORY]

        # Artifacts
        artifacts = overlay.get("artifacts") or []
        with self._artifacts_lock:
            self.artifacts = list(artifacts)
            max_art_suffix = 0
            for a in self.artifacts:
                aid = a.get("id", "")
                if isinstance(aid, str) and "_" in aid:
                    try:
                        max_art_suffix = max(max_art_suffix, int(aid.rsplit("_", 1)[-1]))
                    except (ValueError, IndexError):
                        pass
            self._artifacts_counter = max_art_suffix

        # Renames
        renames = overlay.get("renames")
        if isinstance(renames, dict):
            with self._renames_lock:
                self.renames = {
                    "functions": dict(renames.get("functions") or {}),
                    "variables": {k: dict(v) for k, v in (renames.get("variables") or {}).items()},
                    "labels": {k: dict(v) for k, v in (renames.get("labels") or {}).items()},
                }

        # Custom types
        types = overlay.get("custom_types")
        if isinstance(types, dict):
            with self._types_lock:
                self.custom_types = {
                    "structs": dict(types.get("structs") or {}),
                    "enums": dict(types.get("enums") or {}),
                }

        # Triage flags
        triage = overlay.get("triage_status")
        if isinstance(triage, dict):
            with self._triage_lock:
                self.triage_status = dict(triage)

        # Coverage / sandbox
        if overlay.get("_cached_coverage") is not None:
            self._cached_coverage = overlay["_cached_coverage"]
        if overlay.get("_sandbox_report") is not None:
            self._sandbox_report = overlay["_sandbox_report"]

        with self._project_lock:
            self._overlay_dirty = False

    def _maybe_promote_scratch(self) -> None:
        """Promote ``self.active_project`` if it is currently a ScratchProject.

        Called from mutation methods (add_note, register_artifact, rename_*,
        set_triage_status, create_struct, create_enum) immediately *after* the
        mutation succeeds. Marks the overlay dirty regardless of whether
        promotion fired (real projects also need their dirty flag set).

        Promotion failures degrade gracefully: the mutation has already
        succeeded in memory and a warning is logged. The next mutation will
        retry promotion. The state's data is never lost.
        """
        with self._project_lock:
            self._overlay_dirty = True
            project = self.active_project
            if project is None:
                return
            # Real projects: nothing more to do — flush is handled by the
            # background save loop or close_file.
            if not getattr(project, "is_scratch", False):
                return

        # Lazy import to avoid circular dependencies at module load time.
        try:
            from arkana.projects import project_manager
        except ImportError:
            logger.warning("projects module unavailable; cannot promote scratch project")
            return

        # Build a name for the new project. First try the descriptive
        # auto_name_sample helper (uses pe_data + triage + notes); if that
        # comes back empty (enrichment hasn't run yet), fall back to
        # filename_stem + sha8.
        try:
            scratch = project
            primary_sha = scratch.primary_sha256
            suggested = None
            if primary_sha and primary_sha in scratch.members:
                member = scratch.members[primary_sha]
                # Try the rich auto-name helper first
                try:
                    from arkana.mcp.tools_workflow import _build_sample_slug
                    info = _build_sample_slug(
                        pe_data=self.pe_data or {},
                        triage=self._cached_triage or {},
                        notes=self.get_notes(),
                        file_size_fallback=member.size or None,
                    )
                    rich_slug = info.get("slug") or ""
                    # _build_sample_slug returns "sample_<sha8>" when there's
                    # no signal. We want to fall through to filename-based
                    # naming in that case so the project name is recognisable.
                    if rich_slug and not rich_slug.startswith("sample_"):
                        # Sanitise to fit PROJECT_NAME_RE
                        import re as _re
                        rich_slug = _re.sub(r"[^\w\-. ]", "_", rich_slug)[:80]
                        suggested = f"{rich_slug}_{primary_sha[:8]}"
                except Exception:
                    suggested = None
                if not suggested:
                    stem = os.path.splitext(member.original_filename)[0] or "sample"
                    import re as _re
                    stem = _re.sub(r"[^\w\-. ]", "_", stem)[:80]
                    suggested = f"{stem}_{primary_sha[:8]}"
            real_project = project_manager.promote_scratch(scratch, suggested_name=suggested)
        except Exception as e:
            logger.warning("Failed to promote scratch project: %s", e, exc_info=True)
            return

        # Bind the real project under lock, then flush overlay OUTSIDE lock
        # to avoid blocking other threads during I/O.
        with self._project_lock:
            self.active_project = real_project
        sha = real_project.manifest.last_active_sha256
        if sha:
            try:
                overlay = self.snapshot_overlay()
                real_project.save_overlay(sha, overlay)
                with self._project_lock:
                    self._overlay_dirty = False
            except Exception as e:
                logger.warning("Failed to flush overlay after promotion: %s", e, exc_info=True)

    def flush_overlay(self) -> bool:
        """Persist current overlay to the active project (if any). Returns True on flush.

        Snapshot and dirty-flag update happen under ``_project_lock``, but the
        actual I/O (gzip + write) is done **outside** the lock to avoid
        blocking every thread that calls ``mark_overlay_dirty()`` or
        ``_maybe_promote_scratch()`` during the write.
        """
        # Phase 1: snapshot under lock
        with self._project_lock:
            project = self.active_project
            if project is None or getattr(project, "is_scratch", False):
                return False
            sha = project.manifest.last_active_sha256
            if not sha:
                return False
            overlay = self.snapshot_overlay()

        # Phase 2: I/O outside lock — other threads can proceed with mutations
        try:
            project.save_overlay(sha, overlay)
        except Exception as e:
            logger.warning("Failed to flush overlay for %s: %s", sha[:12], e)
            return False

        # Phase 3: mark clean under lock (best-effort — a concurrent mutation
        # may have re-dirtied between phase 1 and now; that's fine, the next
        # flush cycle will pick it up)
        with self._project_lock:
            self._overlay_dirty = False
        return True

    def close_pe(self):
        with self._pe_lock:
            # Always clear the deferred-promote flag, even if pe_object is
            # None — defends against the order-dependent case where the
            # flag was set by a previous open but pe_object failed to
            # construct (or was already cleared by reset_angr/cleanup).
            self._pe_object_needs_full_load = False
            if self.pe_object:
                # Close the PE object only if we own it.  Sessions that
                # inherited the reference at creation time must NOT close
                # it — doing so would invalidate the object for all other
                # sessions and the default state.
                # We use the ``_inherited_pe_object`` flag rather than
                # comparing ``is _default_state.pe_object`` because the
                # default state's reference can change if another session
                # calls ``open_file``.
                # _default_state is a module-level singleton (never reassigned).
                # For sessions: _inherited_pe_object prevents double-close.
                if self is _default_state or not self._inherited_pe_object:
                    try:
                        self.pe_object.close()
                    except (OSError, AttributeError) as e:
                        logger.debug("Failed to close PE object: %s", e)
                self.pe_object = None
                self._inherited_pe_object = False


# ---------------------------------------------------------------------------
# Session-scoped state (HTTP mode isolation)
# ---------------------------------------------------------------------------

# ContextVar holds the active AnalyzerState for the current async/thread context.
_current_state_var: contextvars.ContextVar[Optional[AnalyzerState]] = contextvars.ContextVar(
    '_current_state', default=None,
)

# Registry: session_key -> AnalyzerState
_session_registry: Dict[str, AnalyzerState] = {}
_registry_lock = threading.Lock()

# Default state instance (stdio / fallback)
_default_state = AnalyzerState()


def get_current_state() -> AnalyzerState:
    """Return the ``AnalyzerState`` for the current context."""
    s = _current_state_var.get()
    return s if s is not None else _default_state


def set_current_state(state: AnalyzerState) -> None:
    """Explicitly set the ``AnalyzerState`` for the current context."""
    _current_state_var.set(state)


def get_or_create_session_state(session_key: str) -> AnalyzerState:
    """Get or lazily create an ``AnalyzerState`` for *session_key*.

    For stdio mode (``"default"``), returns the global ``_default_state``
    directly so that files pre-loaded at startup via ``--input-file`` are
    immediately available to tool calls.

    For HTTP sessions, a new ``AnalyzerState`` is created and inherits the
    server-level configuration **and** any pre-loaded file data from the
    default state.  Each session can subsequently call ``open_file`` to
    load a different file without affecting other sessions.
    """
    # In stdio mode there is only one client — use the default state
    # directly so startup pre-loading works transparently.
    if session_key == "default":
        return _default_state

    stale_to_cleanup = []
    with _registry_lock:
        # Collect stale sessions — mark them as closing inside the lock
        # to prevent TOCTOU races with session key reuse.
        now = time.time()
        stale_keys = [
            key for key, st in _session_registry.items()
            if (now - st.last_active) > SESSION_TTL_SECONDS
        ]
        for key in stale_keys:
            stale_session = _session_registry.pop(key)
            # Mark as closing so it cannot be reactivated if the id()
            # is reused by Python's memory allocator.
            stale_session.last_active = 0
            stale_session._closing = True
            stale_to_cleanup.append(stale_session)

        # H-6: Enforce max session limit to prevent session flooding.
        if session_key not in _session_registry and len(_session_registry) >= MAX_ACTIVE_SESSIONS:
            # Try to evict the oldest session by last_active timestamp.
            oldest_key = None
            oldest_time = float('inf')
            for k, st in _session_registry.items():
                if st.last_active < oldest_time:
                    oldest_time = st.last_active
                    oldest_key = k
            if oldest_key is not None:
                evicted = _session_registry.pop(oldest_key)
                evicted._closing = True
                stale_to_cleanup.append(evicted)
                logger.warning(
                    "Session limit reached (%d). Evicted oldest session to make room.",
                    MAX_ACTIVE_SESSIONS,
                )

        if session_key not in _session_registry:
            _start_session_reaper()  # Lazy start on first session creation
            _start_overlay_flush_loop()  # Lazy start of background overlay flusher
            _start_lock_watchdog()  # Lazy start of lock-health watchdog
            new_state = AnalyzerState()
            # Inherit server-level config from the default state
            new_state.allowed_paths = _default_state.allowed_paths
            new_state.samples_path = _default_state.samples_path
            new_state.api_key = _default_state.api_key
            new_state.dashboard_token = _default_state.dashboard_token
            # Inherit any pre-loaded file data so HTTP clients can
            # immediately access files loaded at startup via --input-file.
            # Each session gets a shared reference; calling open_file
            # replaces the reference on the session only.
            if _default_state.filepath is not None:
                new_state.filepath = _default_state.filepath
                # Share pe_data read-only; copy-on-write via _ensure_pe_data_owned()
                new_state.pe_data = _default_state.pe_data
                new_state._pe_data_shared = True
                new_state.pe_object = _default_state.pe_object
                new_state._inherited_pe_object = True
                new_state.pefile_version = _default_state.pefile_version
                new_state.loaded_from_cache = _default_state.loaded_from_cache
                # angr objects are intentionally shared (read-only, expensive to copy).
                # Mutations to angr state affect all sessions — this is acceptable
                # because angr analysis is a global, immutable result.
                new_state.angr_project = _default_state.angr_project
                new_state.angr_cfg = _default_state.angr_cfg
            _session_registry[session_key] = new_state
        result = _session_registry[session_key]

    # Clean up stale sessions outside the lock.
    # Sessions with inherited PE objects must not close them (close_pe
    # now checks _inherited_pe_object flag).
    for stale in stale_to_cleanup:
        if stale.pe_object is not None:
            stale.close_pe()
        if stale.angr_project is not None and stale.angr_project is not _default_state.angr_project:
            stale.reset_angr()

    return result


def _session_reaper_loop() -> None:
    """M-M1: Background thread that periodically evicts stale sessions.

    Runs every 60 seconds to clean up sessions that have been idle longer
    than SESSION_TTL_SECONDS, preventing unbounded memory growth.
    """
    while True:
        time.sleep(60)
        stale_to_cleanup = []
        try:
            with _registry_lock:
                now = time.time()
                stale_keys = [
                    key for key, st in _session_registry.items()
                    if (now - st.last_active) > SESSION_TTL_SECONDS
                ]
                for key in stale_keys:
                    stale_session = _session_registry.pop(key)
                    stale_session._closing = True
                    stale_to_cleanup.append(stale_session)
            for stale in stale_to_cleanup:
                try:
                    # Snapshot cancel events and threads under lock
                    with stale._task_lock:
                        cancel_events = list(stale._task_cancel_events.values())
                        threads_to_join = list(stale._background_threads.items())
                    # Set cancel events outside lock (workers' finally blocks acquire it)
                    for cancel_evt in cancel_events:
                        cancel_evt.set()
                    # Join threads outside lock to avoid deadlock with worker finally blocks
                    for tid, thr in threads_to_join:
                        if thr.is_alive():
                            thr.join(timeout=5)
                            if thr.is_alive():
                                logger.warning("Session reaper: thread for task %s still alive after join", tid)
                    # Clear dicts under lock
                    with stale._task_lock:
                        stale._background_threads.clear()
                        stale._task_cancel_events.clear()
                    if stale.pe_object is not None:
                        stale.close_pe()
                    if stale.angr_project is not None and stale.angr_project is not _default_state.angr_project:
                        stale.reset_angr()
                    # M3-v8: Clean up module-level _decompile_meta entries for this session
                    try:
                        from arkana.mcp.tools_angr import clear_decompile_meta
                        clear_decompile_meta(stale._state_uuid)
                    except ImportError:
                        pass
                    # L5-v8: Clean up module-level state_api caches for this session
                    try:
                        from arkana.dashboard.state_api import _cleanup_session_caches
                        _cleanup_session_caches(stale._state_uuid)
                    except (ImportError, AttributeError):
                        pass
                    # M8-v10: Clean up phase detection cache for this session
                    try:
                        from arkana.mcp.tools_session import cleanup_phase_cache
                        cleanup_phase_cache(stale._state_uuid)
                    except (ImportError, AttributeError):
                        pass
                    # Clean up debug sessions for reaped state
                    try:
                        if getattr(stale, '_debug_manager', None) is not None:
                            stale._debug_manager.cleanup_all()
                    except Exception:
                        logger.warning("Session reaper: debug cleanup error", exc_info=True)
                    # Clean up emulation inspect sessions for reaped state
                    try:
                        if getattr(stale, '_emulation_manager', None) is not None:
                            stale._emulation_manager.cleanup_all()
                    except Exception:
                        logger.warning("Session reaper: emulation cleanup error", exc_info=True)
                except Exception:
                    logger.warning("Session reaper: cleanup error for session", exc_info=True)
            if stale_to_cleanup:
                logger.debug("Session reaper cleaned up %d stale sessions", len(stale_to_cleanup))
        except Exception:
            logger.warning("Session reaper: iteration error", exc_info=True)


_reaper_thread = None
_reaper_started = False


def _start_session_reaper():
    """Start the session reaper thread lazily on first session creation.

    NOTE: Must be called under _registry_lock to prevent duplicate reaper threads.
    """
    assert _registry_lock.locked(), "_start_session_reaper must be called under _registry_lock"
    global _reaper_thread, _reaper_started
    if _reaper_started and _reaper_thread is not None and _reaper_thread.is_alive():
        return
    _reaper_started = True
    _reaper_thread = threading.Thread(target=_session_reaper_loop, daemon=True, name="session-reaper")
    _reaper_thread.start()


# Background overlay flush — persists user-mutable state (notes, artifacts,
# renames, types, triage, coverage, sandbox) to the active project's overlay
# at a fixed cadence so a crash/SIGKILL between mutations and close_file
# doesn't lose work. Without this loop, mutations only persisted on
# close_file/close_project. Cadence is set by OVERLAY_FLUSH_INTERVAL_SECONDS
# in arkana/constants.py and is intentionally generous (30s) so the loop is
# essentially free under normal load.
def _overlay_flush_loop() -> None:
    """Daemon loop that flushes dirty overlays every OVERLAY_FLUSH_INTERVAL_SECONDS.

    Iterates the session registry plus the default state and calls
    ``flush_overlay()`` on any state with ``_overlay_dirty=True``. Errors are
    logged but never propagated — best-effort persistence.
    """
    from arkana.constants import OVERLAY_FLUSH_INTERVAL_SECONDS
    while True:
        time.sleep(OVERLAY_FLUSH_INTERVAL_SECONDS)
        try:
            with _registry_lock:
                states = [*list(_session_registry.values()), _default_state]
            for st in states:
                try:
                    if not st.is_overlay_dirty():
                        continue
                    flushed = st.flush_overlay()
                    if flushed:
                        logger.debug("overlay-flush: persisted dirty overlay for session %s",
                                     st._state_uuid[:8])
                except Exception:
                    logger.debug("overlay-flush: per-state error", exc_info=True)
        except Exception:
            logger.warning("overlay-flush: iteration error", exc_info=True)


# Module-level vars defined AFTER the loop function so they mirror the
# session-reaper layout (lines above) — keeps the two daemon-thread
# patterns visually identical for future maintainers.
_overlay_flush_thread = None
_overlay_flush_started = False


def _start_overlay_flush_loop() -> None:
    """Lazily start the background overlay flush daemon.

    Called from get_or_create_session_state alongside the session reaper.
    Idempotent — second call is a no-op if the thread is already running.
    Must be called under _registry_lock.
    """
    assert _registry_lock.locked(), "_start_overlay_flush_loop must be called under _registry_lock"
    global _overlay_flush_thread, _overlay_flush_started
    if _overlay_flush_started and _overlay_flush_thread is not None and _overlay_flush_thread.is_alive():
        return
    _overlay_flush_started = True
    _overlay_flush_thread = threading.Thread(
        target=_overlay_flush_loop, daemon=True, name="overlay-flush",
    )
    _overlay_flush_thread.start()


_LOCK_WATCHDOG_INTERVAL = int(os.environ.get("ARKANA_LOCK_WATCHDOG_INTERVAL", "60"))
_LOCK_ACQUIRE_TIMEOUT = 5.0  # seconds — if we can't acquire within this, something is stuck
_lock_watchdog_thread = None
_lock_watchdog_started = False


def _lock_watchdog_loop() -> None:
    """Daemon that periodically probes key locks to detect deadlocks.

    Every ``_LOCK_WATCHDOG_INTERVAL`` seconds, tries to acquire each major
    lock with a timeout.  If any acquisition fails, dumps all thread stacks
    via ``faulthandler`` so the deadlock is visible in container logs.
    """
    import faulthandler as _fh

    while True:
        time.sleep(_LOCK_WATCHDOG_INTERVAL)
        try:
            with _registry_lock:
                states = [*list(_session_registry.values()), _default_state]
        except Exception:
            continue

        for st in states:
            locks_to_probe = [
                ("_project_lock", st._project_lock),
                ("_task_lock", st._task_lock),
                ("_pe_lock", st._pe_lock),
            ]
            for name, lock in locks_to_probe:
                acquired = lock.acquire(timeout=_LOCK_ACQUIRE_TIMEOUT)
                if acquired:
                    lock.release()
                else:
                    logger.critical(
                        "LOCK WATCHDOG: %s on session %s could not be acquired "
                        "after %.0fs — possible deadlock. Dumping all thread stacks.",
                        name, st._state_uuid[:8], _LOCK_ACQUIRE_TIMEOUT,
                    )
                    try:
                        _fh.dump_traceback(file=sys.stderr, all_threads=True)
                    except Exception:
                        pass
                    # Don't spam — one dump per watchdog cycle is enough
                    break


def _start_lock_watchdog() -> None:
    """Lazily start the lock watchdog daemon. Must be called under _registry_lock."""
    assert _registry_lock.locked(), "_start_lock_watchdog must be called under _registry_lock"
    global _lock_watchdog_thread, _lock_watchdog_started
    if _lock_watchdog_started and _lock_watchdog_thread is not None and _lock_watchdog_thread.is_alive():
        return
    _lock_watchdog_started = True
    _lock_watchdog_thread = threading.Thread(
        target=_lock_watchdog_loop, daemon=True, name="lock-watchdog",
    )
    _lock_watchdog_thread.start()


def get_all_session_states() -> list:
    """Return a snapshot of all active session states (for heartbeat monitoring)."""
    with _registry_lock:
        return [*list(_session_registry.values()), _default_state]


def activate_session_state(session_key: str) -> AnalyzerState:
    """Activate the per-session state for the current context and return it."""
    s = get_or_create_session_state(session_key)
    _current_state_var.set(s)
    return s


# MCP SDK v2 constructs a fresh ``ServerSession`` for every request, so the
# object's identity cannot key a session — a marker written on one call is
# gone by the next, and every tool call would land in its own AnalyzerState
# ("No file is currently loaded" immediately after a successful open_file).
# SDK v1 keeps one ServerSession per connected client, where stamping is both
# valid and the only option: v1 exposes no transport session id to the tool.
#
# Probed locally rather than imported from ``arkana.imports`` so this module
# stays free of the heavy optional-dependency graph.
try:
    import mcp.server.mcpserver as _mcp_v2_probe  # noqa: F401
    _SESSION_OBJECT_PER_REQUEST = True
except Exception:
    _SESSION_OBJECT_PER_REQUEST = False


def _transport_session_id(ctx) -> Optional[str]:
    """Return the transport-level MCP session id, when the SDK exposes one.

    Streamable-HTTP assigns each client a stable ``Mcp-Session-Id`` for the
    life of the session; SDK v2 surfaces it on ``ctx.headers``.  Access is
    guarded because ``headers`` is not always a mapping — it is a plain
    ``str`` on SDK v1 stdio and ``None`` on both SDK v1 HTTP and v2 stdio.
    """
    headers = getattr(ctx, "headers", None)
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return None
    for key in ("mcp-session-id", "Mcp-Session-Id"):
        try:
            value = getter(key)
        except Exception:
            continue
        if value:
            return str(value)
    return None


def get_session_key_from_context(ctx) -> str:
    """Extract a unique session key from an MCP ``Context`` object.

    Resolution order:

    1. The transport-level MCP session id (``Mcp-Session-Id``). Stable across
       calls, and the only correct key on SDK v2, whose ``ServerSession`` is
       rebuilt per request.
    2. A UUID stamped onto the session object — used only where the SDK keeps
       one ``ServerSession`` per client (v1). A UUID is used rather than
       ``id(session)`` because CPython reuses ``id()`` values after garbage
       collection, which could let a new session inherit another's state.
    3. ``"default"``, which transparently collapses to the singleton model.
       This is the right answer for single-session transports (stdio).
    """
    try:
        sid = _transport_session_id(ctx)
        if sid:
            return f"mcp-{sid}"

        if not _SESSION_OBJECT_PER_REQUEST:
            session = None
            if hasattr(ctx, '_request_context'):
                session = getattr(ctx._request_context, 'session', None)
            if session is None and hasattr(ctx, 'session'):
                session = ctx.session
            if session is not None:
                sid = getattr(session, '_arkana_session_id', None)
                if sid is None:
                    sid = str(uuid.uuid4())
                    try:
                        session._arkana_session_id = sid
                    except AttributeError:
                        # Frozen/slotted objects — use stable UUID via WeakKeyDictionary
                        with _session_id_map_lock:
                            if session not in _session_id_map:
                                _session_id_map[session] = f"id-{uuid.uuid4().hex[:16]}"
                            sid = _session_id_map[session]
                return sid
    except Exception:
        # L: Elevated to WARNING — falling back to "default" in HTTP mode causes
        # all clients to share state, which is a session isolation failure.
        logger.warning("Could not extract session key from context, using default", exc_info=True)
    return "default"


class StateProxy:
    """Transparent proxy that delegates attribute access to the active session
    ``AnalyzerState`` (via *contextvars*).

    In stdio mode the default state is used.  In HTTP mode the per-session
    state set by the tool decorator is used.  All existing code that does
    ``state.pe_data``, ``state.filepath = ...``, etc. works unchanged.

    Note: ``__setattr__`` delegates ALL attribute sets to the underlying
    ``AnalyzerState``.  If you need to store private attributes on the proxy
    itself, use ``object.__setattr__(self, name, value)`` explicitly.
    """

    def __getattr__(self, name: str):
        return getattr(get_current_state(), name)

    def __setattr__(self, name: str, value):
        # Allow StateProxy's own private attributes (prefixed with _proxy_)
        # to be stored on the proxy instance itself rather than delegating.
        if name.startswith("_proxy_"):
            object.__setattr__(self, name, value)
        else:
            setattr(get_current_state(), name, value)

    def __repr__(self):
        current = get_current_state()
        return f"<StateProxy -> {current!r}>"
