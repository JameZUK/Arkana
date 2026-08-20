"""MCP tools for learner progress tracking across reverse engineering sessions.

Stores a persistent learner profile in ~/.arkana/learner_profile.json with
concept mastery levels, session history, and adaptive learning suggestions.
These tools are independent of the loaded binary — they track the *learner*,
not the *sample*.
"""
import json
import time
import datetime
import logging
import threading

from pathlib import Path
from typing import Dict, Any, List, Optional

from arkana.mcp.server import tool_decorator, _check_mcp_response_size

try:
    from arkana.config import Context, logger
except ImportError:  # pragma: no cover - standalone import fallback
    # Mirror arkana.imports: SDK v2 renamed FastMCP -> MCPServer and moved
    # the module, taking Context with it.  Try v2 first, then v1.
    try:
        from mcp.server.mcpserver import Context
    except ImportError:
        from mcp.server.fastmcp import Context
    logger = logging.getLogger("Arkana")

# ---------------------------------------------------------------------------
#  Profile storage
# ---------------------------------------------------------------------------

_PROFILE_DIR = Path.home() / ".arkana"
_PROFILE_PATH = _PROFILE_DIR / "learner_profile.json"
_profile_lock = threading.Lock()

# Valid mastery levels in progression order
MASTERY_LEVELS = ("introduced", "practiced", "mastered")

# Tier ordering for suggestions
TIER_ORDER = ("foundation", "intermediate", "advanced", "expert")

# Concept-to-module mapping (loaded from curriculum at runtime if available,
# but we embed the canonical mapping here for self-contained operation)
_CONCEPT_CATALOG: Dict[str, Dict[str, str]] = {
    # Tier 1: Foundation
    "binary_formats": {"module": "1.1", "tier": "foundation", "title": "Binary Basics"},
    "compilation_pipeline": {"module": "1.1", "tier": "foundation", "title": "Binary Basics"},
    "file_identification": {"module": "1.1", "tier": "foundation", "title": "Binary Basics"},
    "pe_headers": {"module": "1.2", "tier": "foundation", "title": "PE Structure Deep Dive"},
    "pe_sections": {"module": "1.2", "tier": "foundation", "title": "PE Structure Deep Dive"},
    "entry_point": {"module": "1.2", "tier": "foundation", "title": "PE Structure Deep Dive"},
    "pe_resources": {"module": "1.2", "tier": "foundation", "title": "PE Structure Deep Dive"},
    "string_extraction": {"module": "1.3", "tier": "foundation", "title": "String Analysis"},
    "string_types": {"module": "1.3", "tier": "foundation", "title": "String Analysis"},
    "operational_strings": {"module": "1.3", "tier": "foundation", "title": "String Analysis"},
    "encoded_strings": {"module": "1.3", "tier": "foundation", "title": "String Analysis"},
    "import_address_table": {"module": "1.4", "tier": "foundation", "title": "Import & Export Analysis"},
    "dynamic_linking": {"module": "1.4", "tier": "foundation", "title": "Import & Export Analysis"},
    "suspicious_imports": {"module": "1.4", "tier": "foundation", "title": "Import & Export Analysis"},
    "dll_sideloading": {"module": "1.4", "tier": "foundation", "title": "Import & Export Analysis"},
    "x86_registers": {"module": "1.5", "tier": "foundation", "title": "Introduction to Assembly"},
    "common_instructions": {"module": "1.5", "tier": "foundation", "title": "Introduction to Assembly"},
    "stack_frames": {"module": "1.5", "tier": "foundation", "title": "Introduction to Assembly"},
    "calling_conventions": {"module": "1.5", "tier": "foundation", "title": "Introduction to Assembly"},
    "reading_disassembly": {"module": "1.5", "tier": "foundation", "title": "Introduction to Assembly"},
    # Tier 2: Intermediate
    "basic_blocks": {"module": "2.1", "tier": "intermediate", "title": "Control Flow Analysis"},
    "control_flow_graphs": {"module": "2.1", "tier": "intermediate", "title": "Control Flow Analysis"},
    "branches": {"module": "2.1", "tier": "intermediate", "title": "Control Flow Analysis"},
    "loops": {"module": "2.1", "tier": "intermediate", "title": "Control Flow Analysis"},
    "switch_tables": {"module": "2.1", "tier": "intermediate", "title": "Control Flow Analysis"},
    "indirect_jumps": {"module": "2.1", "tier": "intermediate", "title": "Control Flow Analysis"},
    "decompiler_output": {"module": "2.2", "tier": "intermediate", "title": "Decompilation"},
    "type_recovery": {"module": "2.2", "tier": "intermediate", "title": "Decompilation"},
    "variable_naming": {"module": "2.2", "tier": "intermediate", "title": "Decompilation"},
    "decompiler_artefacts": {"module": "2.2", "tier": "intermediate", "title": "Decompilation"},
    "pseudocode_reading": {"module": "2.2", "tier": "intermediate", "title": "Decompilation"},
    "packing_purpose": {"module": "2.3", "tier": "intermediate", "title": "Packing & Unpacking"},
    "packer_identification": {"module": "2.3", "tier": "intermediate", "title": "Packing & Unpacking"},
    "entropy_analysis": {"module": "2.3", "tier": "intermediate", "title": "Packing & Unpacking"},
    "unpacking_methods": {"module": "2.3", "tier": "intermediate", "title": "Packing & Unpacking"},
    "oep_concept": {"module": "2.3", "tier": "intermediate", "title": "Packing & Unpacking"},
    "crypto_constants": {"module": "2.4", "tier": "intermediate", "title": "Crypto Pattern Recognition"},
    "xor_encryption": {"module": "2.4", "tier": "intermediate", "title": "Crypto Pattern Recognition"},
    "rc4_pattern": {"module": "2.4", "tier": "intermediate", "title": "Crypto Pattern Recognition"},
    "aes_pattern": {"module": "2.4", "tier": "intermediate", "title": "Crypto Pattern Recognition"},
    "key_identification": {"module": "2.4", "tier": "intermediate", "title": "Crypto Pattern Recognition"},
    "iv_identification": {"module": "2.4", "tier": "intermediate", "title": "Crypto Pattern Recognition"},
    "capa_rules": {"module": "2.5", "tier": "intermediate", "title": "Capability Mapping"},
    "attack_techniques": {"module": "2.5", "tier": "intermediate", "title": "Capability Mapping"},
    "capability_validation": {"module": "2.5", "tier": "intermediate", "title": "Capability Mapping"},
    "behavioural_indicators": {"module": "2.5", "tier": "intermediate", "title": "Capability Mapping"},
    "false_positives": {"module": "2.5", "tier": "intermediate", "title": "Capability Mapping"},
    # Tier 3: Advanced
    "reaching_definitions": {"module": "3.1", "tier": "advanced", "title": "Data Flow Analysis"},
    "def_use_chains": {"module": "3.1", "tier": "advanced", "title": "Data Flow Analysis"},
    "control_dependencies": {"module": "3.1", "tier": "advanced", "title": "Data Flow Analysis"},
    "constant_propagation": {"module": "3.1", "tier": "advanced", "title": "Data Flow Analysis"},
    "backward_slice": {"module": "3.1", "tier": "advanced", "title": "Data Flow Analysis"},
    "forward_slice": {"module": "3.1", "tier": "advanced", "title": "Data Flow Analysis"},
    "value_set_analysis": {"module": "3.1", "tier": "advanced", "title": "Data Flow Analysis"},
    "emulation_vs_execution": {"module": "3.2", "tier": "advanced", "title": "Emulation & Dynamic Analysis"},
    "api_hooking": {"module": "3.2", "tier": "advanced", "title": "Emulation & Dynamic Analysis"},
    "memory_inspection": {"module": "3.2", "tier": "advanced", "title": "Emulation & Dynamic Analysis"},
    "symbolic_execution": {"module": "3.2", "tier": "advanced", "title": "Emulation & Dynamic Analysis"},
    "watchpoints": {"module": "3.2", "tier": "advanced", "title": "Emulation & Dynamic Analysis"},
    "qiling_vs_speakeasy": {"module": "3.2", "tier": "advanced", "title": "Emulation & Dynamic Analysis"},
    "anti_debug": {"module": "3.3", "tier": "advanced", "title": "Anti-Analysis Techniques"},
    "anti_vm": {"module": "3.3", "tier": "advanced", "title": "Anti-Analysis Techniques"},
    "timing_checks": {"module": "3.3", "tier": "advanced", "title": "Anti-Analysis Techniques"},
    "tls_callbacks": {"module": "3.3", "tier": "advanced", "title": "Anti-Analysis Techniques"},
    "obfuscation_techniques": {"module": "3.3", "tier": "advanced", "title": "Anti-Analysis Techniques"},
    "control_flow_flattening": {"module": "3.3", "tier": "advanced", "title": "Anti-Analysis Techniques"},
    "string_encryption": {"module": "3.3", "tier": "advanced", "title": "Anti-Analysis Techniques"},
    "c2_config_patterns": {"module": "3.4", "tier": "advanced", "title": "Malware Configuration Extraction"},
    "config_storage": {"module": "3.4", "tier": "advanced", "title": "Malware Configuration Extraction"},
    "encryption_layers": {"module": "3.4", "tier": "advanced", "title": "Malware Configuration Extraction"},
    "extraction_methodology": {"module": "3.4", "tier": "advanced", "title": "Malware Configuration Extraction"},
    "validation": {"module": "3.4", "tier": "advanced", "title": "Malware Configuration Extraction"},
    # Tier 4: Expert
    "manual_oep_recovery": {"module": "4.1", "tier": "expert", "title": "Advanced Unpacking"},
    "multi_layer_packing": {"module": "4.1", "tier": "expert", "title": "Advanced Unpacking"},
    "process_hollowing": {"module": "4.1", "tier": "expert", "title": "Advanced Unpacking"},
    "dotnet_obfuscators": {"module": "4.1", "tier": "expert", "title": "Advanced Unpacking"},
    "pe_reconstruction": {"module": "4.1", "tier": "expert", "title": "Advanced Unpacking"},
    "emulation_based_dumping": {"module": "4.1", "tier": "expert", "title": "Advanced Unpacking"},
    "network_protocols": {"module": "4.2", "tier": "expert", "title": "Protocol Reverse Engineering"},
    "serialization_formats": {"module": "4.2", "tier": "expert", "title": "Protocol Reverse Engineering"},
    "command_dispatch": {"module": "4.2", "tier": "expert", "title": "Protocol Reverse Engineering"},
    "session_management": {"module": "4.2", "tier": "expert", "title": "Protocol Reverse Engineering"},
    "custom_encodings": {"module": "4.2", "tier": "expert", "title": "Protocol Reverse Engineering"},
    "yara_syntax": {"module": "4.3", "tier": "expert", "title": "YARA Rule Authoring"},
    "byte_patterns": {"module": "4.3", "tier": "expert", "title": "YARA Rule Authoring"},
    "string_selection": {"module": "4.3", "tier": "expert", "title": "YARA Rule Authoring"},
    "condition_logic": {"module": "4.3", "tier": "expert", "title": "YARA Rule Authoring"},
    "false_positive_avoidance": {"module": "4.3", "tier": "expert", "title": "YARA Rule Authoring"},
    "rule_testing": {"module": "4.3", "tier": "expert", "title": "YARA Rule Authoring"},
    "binary_diffing": {"module": "4.4", "tier": "expert", "title": "Campaign Analysis"},
    "similarity_hashing": {"module": "4.4", "tier": "expert", "title": "Campaign Analysis"},
    "variant_evolution": {"module": "4.4", "tier": "expert", "title": "Campaign Analysis"},
    "infrastructure_tracking": {"module": "4.4", "tier": "expert", "title": "Campaign Analysis"},
    "multi_sample_workflows": {"module": "4.4", "tier": "expert", "title": "Campaign Analysis"},
    "attribution": {"module": "4.4", "tier": "expert", "title": "Campaign Analysis"},
}


def _empty_profile() -> Dict[str, Any]:
    """Return a fresh learner profile structure."""
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {
        "version": 1,
        "created_at": now,
        "updated_at": now,
        "session_count": 0,
        "total_concepts_introduced": 0,
        "total_concepts_mastered": 0,
        "current_tier": "foundation",
        "concepts": {},
        "session_log": [],
    }


def _load_profile_unlocked() -> Dict[str, Any]:
    """Load learner profile from disk without acquiring the lock.

    Caller MUST hold ``_profile_lock``.
    """
    if _PROFILE_PATH.exists():
        try:
            data = json.loads(_PROFILE_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("version") == 1:
                return data
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Learner profile corrupt, creating fresh: %s", exc)
    return _empty_profile()


def _save_profile_unlocked(profile: Dict[str, Any]) -> None:
    """Persist learner profile to disk without acquiring the lock.

    Caller MUST hold ``_profile_lock``.
    """
    profile["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    _PROFILE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)  # L2-v9: restrictive dir perms
    tmp = _PROFILE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(profile, indent=2, default=str), encoding="utf-8")
    import os as _os
    _os.chmod(str(tmp), 0o600)  # L2-v9: restrictive file perms
    tmp.replace(_PROFILE_PATH)


def _load_profile() -> Dict[str, Any]:
    """Load learner profile from disk, creating a fresh one if absent/corrupt."""
    with _profile_lock:
        return _load_profile_unlocked()


def _save_profile(profile: Dict[str, Any]) -> None:
    """Persist learner profile to disk."""
    with _profile_lock:
        _save_profile_unlocked(profile)


def _update_profile(modifier_fn) -> Dict[str, Any]:
    """Load, modify, and save the learner profile atomically."""
    with _profile_lock:
        profile = _load_profile_unlocked()
        modifier_fn(profile)
        _save_profile_unlocked(profile)
        return profile


def _compute_tier(profile: Dict[str, Any]) -> str:
    """Determine the learner's current tier based on concept mastery."""
    concepts = profile.get("concepts", {})

    for tier in TIER_ORDER:
        tier_concepts = [
            cid for cid, info in _CONCEPT_CATALOG.items()
            if info["tier"] == tier
        ]
        if not tier_concepts:
            continue
        mastered_count = sum(
            1 for cid in tier_concepts
            if concepts.get(cid, {}).get("level") == "mastered"
        )
        # Need >= 70% mastery of a tier to advance past it
        if mastered_count < len(tier_concepts) * 0.7:
            return tier

    return "expert"


def _module_completion(profile: Dict[str, Any], module_id: str) -> Dict[str, Any]:
    """Calculate completion stats for a curriculum module."""
    concepts = profile.get("concepts", {})
    module_concepts = [
        cid for cid, info in _CONCEPT_CATALOG.items()
        if info["module"] == module_id
    ]
    total = len(module_concepts)
    if total == 0:
        return {"module": module_id, "total": 0, "mastered": 0, "practiced": 0,
                "introduced": 0, "not_started": 0, "completion_pct": 0}

    mastered = sum(1 for c in module_concepts if concepts.get(c, {}).get("level") == "mastered")
    practiced = sum(1 for c in module_concepts if concepts.get(c, {}).get("level") == "practiced")
    introduced = sum(1 for c in module_concepts if concepts.get(c, {}).get("level") == "introduced")
    not_started = total - mastered - practiced - introduced

    return {
        "module": module_id,
        "total": total,
        "mastered": mastered,
        "practiced": practiced,
        "introduced": introduced,
        "not_started": not_started,
        "completion_pct": round((mastered / total) * 100),
    }


# ---------------------------------------------------------------------------
#  MCP Tools
# ---------------------------------------------------------------------------

@tool_decorator
async def get_learner_profile(
    ctx: Context,
) -> Dict[str, Any]:
    """
    [Phase: learning] Retrieve the learner's progress profile. Returns current
    tier, concept mastery counts, module completion percentages, and session
    history. Creates a fresh profile if none exists.

    ---compact: retrieve learner progress — tier, mastery counts, module completion

    When to use: At the start of a learning session to understand the learner's
    current level and adapt teaching accordingly. Also useful for reviewing
    overall progress.

    Returns:
        A dictionary with the learner profile including tier, mastery stats,
        module completion, and recent session history.
    """
    def _start_session(profile):
        profile["session_count"] += 1
        profile["current_tier"] = _compute_tier(profile)
        # Deduplicate: skip if the last log entry is already a session_start
        if not (profile["session_log"] and profile["session_log"][-1].get("type") == "session_start"):
            profile["session_log"].append({
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "type": "session_start",
            })
        if len(profile["session_log"]) > 50:
            profile["session_log"] = profile["session_log"][-50:]

    profile = _update_profile(_start_session)

    # Build module completion summary
    modules_seen: set = set()
    module_completions = []
    for info in _CONCEPT_CATALOG.values():
        mid = info["module"]
        if mid not in modules_seen:
            modules_seen.add(mid)
            module_completions.append(_module_completion(profile, mid))

    # Count mastery stats
    concepts = profile.get("concepts", {})
    mastered = sum(1 for c in concepts.values() if c.get("level") == "mastered")
    practiced = sum(1 for c in concepts.values() if c.get("level") == "practiced")
    introduced = sum(1 for c in concepts.values() if c.get("level") == "introduced")

    return {
        "status": "success",
        "current_tier": profile["current_tier"],
        "session_count": profile["session_count"],
        "total_concepts": len(_CONCEPT_CATALOG),
        "concepts_mastered": mastered,
        "concepts_practiced": practiced,
        "concepts_introduced": introduced,
        "concepts_not_started": len(_CONCEPT_CATALOG) - mastered - practiced - introduced,
        "module_completion": sorted(module_completions, key=lambda m: m["module"]),
        "recent_sessions": profile["session_log"][-5:],
        "created_at": profile["created_at"],
        "updated_at": profile["updated_at"],
    }


@tool_decorator
async def update_concept_mastery(
    ctx: Context,
    concept: str,
    level: str,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: learning] Update the mastery level for a specific concept. Mastery
    levels progress: introduced -> practiced -> mastered.

    ---compact: update concept mastery level | introduced -> practiced -> mastered Optionally attach a
    note about the learning context.

    When to use: After teaching or practicing a concept during a learning
    session. Call this to record that the learner has been exposed to or has
    demonstrated understanding of a concept.

    Args:
        ctx: The MCP Context object.
        concept: (str) The concept ID from the curriculum (e.g. 'pe_headers',
            'decompiler_output', 'anti_debug'). Use get_learner_profile() to
            see all concept IDs.
        level: (str) The mastery level: 'introduced' (first exposure),
            'practiced' (hands-on exercise completed), or 'mastered'
            (demonstrated understanding without guidance).
        notes: (Optional[str]) Context about how/when this was learned.

    Returns:
        A dictionary with the updated concept entry and module completion.
    """
    if concept not in _CONCEPT_CATALOG:
        valid_concepts = sorted(_CONCEPT_CATALOG.keys())
        # Find close matches for helpful error
        close = [c for c in valid_concepts if concept.lower() in c.lower()]
        return {
            "status": "error",
            "message": f"Unknown concept '{concept}'.",
            "did_you_mean": close[:5] if close else [],
            "hint": "Use get_learner_profile() to see all valid concept IDs.",
        }

    if level not in MASTERY_LEVELS:
        return {
            "status": "error",
            "message": f"Invalid mastery level '{level}'. Must be one of: {', '.join(MASTERY_LEVELS)}",
        }

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Perform entire load→check→modify→save atomically under the lock
    regression_error = None
    old_level = None

    def _do_update(profile):
        nonlocal regression_error, old_level
        existing = profile["concepts"].get(concept, {})
        old_level = existing.get("level")

        # Don't allow regression unless explicitly forced
        if old_level and MASTERY_LEVELS.index(old_level) > MASTERY_LEVELS.index(level):
            regression_error = {
                "status": "warning",
                "message": f"Concept '{concept}' is already at '{old_level}' — cannot regress to '{level}'.",
                "current_level": old_level,
                "hint": "Use reset_learner_profile() to start fresh if needed.",
            }
            return  # modifier returns without saving changes

        entry = {
            "level": level,
            "first_seen": existing.get("first_seen", now),
            "last_updated": now,
            "update_count": existing.get("update_count", 0) + 1,
        }
        if notes:
            entry["last_note"] = notes
        profile["concepts"][concept] = entry

        profile["total_concepts_introduced"] = sum(
            1 for c in profile["concepts"].values() if c.get("level") == "introduced"
        )
        profile["total_concepts_mastered"] = sum(
            1 for c in profile["concepts"].values() if c.get("level") == "mastered"
        )
        profile["current_tier"] = _compute_tier(profile)
        profile["session_log"].append({
            "timestamp": now,
            "type": "mastery_update",
            "concept": concept,
            "old_level": old_level,
            "new_level": level,
        })
        if len(profile["session_log"]) > 50:
            profile["session_log"] = profile["session_log"][-50:]

    profile = _update_profile(_do_update)

    if regression_error:
        return regression_error

    concept_info = _CONCEPT_CATALOG[concept]
    module_status = _module_completion(profile, concept_info["module"])

    return {
        "status": "success",
        "concept": concept,
        "previous_level": old_level,
        "new_level": level,
        "module": concept_info["module"],
        "module_title": concept_info["title"],
        "tier": concept_info["tier"],
        "module_completion": module_status,
        "current_tier": profile["current_tier"],
    }


@tool_decorator
async def get_learning_suggestions(
    ctx: Context,
    focus: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: learning] Get personalised learning suggestions based on current
    mastery state. Recommends next concepts to learn, modules to complete, and
    exercises to try.

    ---compact: personalised next-concept and module suggestions based on mastery state

    When to use: When the learner asks "what should I learn next?" or at the
    start of a session to plan the learning path.

    Args:
        ctx: The MCP Context object.
        focus: (Optional[str]) Focus area to prioritise suggestions for.
            Options: 'foundation', 'intermediate', 'advanced', 'expert',
            or a specific module ID like '2.3'. If not specified, suggestions
            follow the natural progression from the current tier.

    Returns:
        A dictionary with suggested next concepts, modules, and exercises.
    """
    profile = _load_profile()
    concepts = profile.get("concepts", {})
    current_tier = _compute_tier(profile)

    suggestions: Dict[str, Any] = {
        "status": "success",
        "current_tier": current_tier,
        "focus": focus,
    }

    # Determine which tier(s) to suggest from
    if focus and focus in TIER_ORDER:
        target_tiers = [focus]
    elif focus and "." in focus:
        # Module ID specified — suggest concepts from that module
        module_concepts = [
            (cid, info) for cid, info in _CONCEPT_CATALOG.items()
            if info["module"] == focus
        ]
        if not module_concepts:
            return {"status": "error", "message": f"Unknown module '{focus}'."}

        not_started = [
            cid for cid, info in module_concepts
            if cid not in concepts
        ]
        in_progress = [
            cid for cid, info in module_concepts
            if concepts.get(cid, {}).get("level") in ("introduced", "practiced")
        ]

        suggestions["module_focus"] = focus
        suggestions["module_title"] = module_concepts[0][1]["title"]
        suggestions["concepts_to_start"] = not_started[:5]
        suggestions["concepts_to_practice"] = in_progress[:5]
        suggestions["module_completion"] = _module_completion(profile, focus)
        return suggestions
    else:
        # Natural progression: current tier + one tier ahead
        idx = TIER_ORDER.index(current_tier) if current_tier in TIER_ORDER else 0
        target_tiers = list(TIER_ORDER[idx:idx + 2])

    # Find incomplete modules in target tiers
    incomplete_modules: List[Dict[str, Any]] = []
    modules_seen: set = set()
    for _cid, info in _CONCEPT_CATALOG.items():
        if info["tier"] not in target_tiers:
            continue
        mid = info["module"]
        if mid in modules_seen:
            continue
        modules_seen.add(mid)
        completion = _module_completion(profile, mid)
        if completion["completion_pct"] < 100:
            incomplete_modules.append({
                "module": mid,
                "title": info["title"],
                "tier": info["tier"],
                **completion,
            })

    # Sort: partially-started modules first, then by module ID
    incomplete_modules.sort(
        key=lambda m: (m["not_started"] == m["total"], m["module"])
    )

    # Find specific concepts to work on
    concepts_to_start: List[Dict[str, str]] = []
    concepts_to_practice: List[Dict[str, str]] = []

    for cid, info in sorted(_CONCEPT_CATALOG.items(), key=lambda x: x[1]["module"]):
        if info["tier"] not in target_tiers:
            continue
        if cid not in concepts:
            concepts_to_start.append({
                "concept": cid,
                "module": info["module"],
                "title": info["title"],
            })
        elif concepts[cid].get("level") in ("introduced", "practiced"):
            concepts_to_practice.append({
                "concept": cid,
                "module": info["module"],
                "title": info["title"],
                "current_level": concepts[cid]["level"],
            })

    # Determine recommended next module
    recommended_module = None
    if incomplete_modules:
        recommended_module = incomplete_modules[0]

    suggestions["recommended_module"] = recommended_module
    suggestions["incomplete_modules"] = incomplete_modules[:5]
    suggestions["concepts_to_start"] = concepts_to_start[:8]
    suggestions["concepts_to_practice"] = concepts_to_practice[:8]
    suggestions["target_tiers"] = target_tiers

    # Generate contextual advice
    total_mastered = sum(1 for c in concepts.values() if c.get("level") == "mastered")
    if total_mastered == 0:
        suggestions["advice"] = (
            "Welcome to reverse engineering! Start with Module 1.1 (Binary Basics) "
            "to build your foundation. Load any binary and we'll explore it together."
        )
    elif current_tier == "foundation":
        suggestions["advice"] = (
            "Good progress on the fundamentals! Focus on mastering the remaining "
            "foundation concepts before moving to intermediate topics. Hands-on "
            "practice with real binaries is the fastest way to solidify these."
        )
    elif current_tier == "intermediate":
        suggestions["advice"] = (
            "You have a solid foundation. Intermediate topics like decompilation "
            "and packing analysis will unlock much deeper understanding. Try "
            "analysing a packed malware sample to practice multiple skills."
        )
    elif current_tier == "advanced":
        suggestions["advice"] = (
            "Strong skills across the core topics. Advanced techniques like data "
            "flow analysis and emulation will let you tackle even heavily "
            "obfuscated binaries. Consider working through a C2 extraction exercise."
        )
    else:
        suggestions["advice"] = (
            "Expert-level progress! Focus on the remaining advanced and expert "
            "topics. Campaign analysis and YARA rule authoring are excellent for "
            "synthesising everything you've learned."
        )

    return suggestions


@tool_decorator
async def reset_learner_profile(
    ctx: Context,
    confirm: bool = False,
) -> Dict[str, Any]:
    """
    [Phase: learning] Reset the learner profile to start fresh. Requires
    explicit confirmation.

    ---compact: reset all learning progress | requires confirm=True

    When to use: When the learner wants to start over from scratch, or when
    the profile data is no longer relevant.

    Args:
        ctx: The MCP Context object.
        confirm: (bool) Must be True to proceed with the reset. Safety guard
            to prevent accidental data loss.

    Returns:
        A dictionary confirming the reset or requesting confirmation.
    """
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": (
                "This will permanently delete all learning progress. "
                "Call reset_learner_profile(confirm=True) to proceed."
            ),
        }

    profile = _load_profile()
    old_stats = {
        "session_count": profile.get("session_count", 0),
        "concepts_tracked": len(profile.get("concepts", {})),
        "mastered": sum(
            1 for c in profile.get("concepts", {}).values()
            if c.get("level") == "mastered"
        ),
    }

    fresh = _empty_profile()
    _save_profile(fresh)

    await ctx.info("Learner profile reset to fresh state")
    return {
        "status": "success",
        "message": "Learner profile has been reset.",
        "previous_stats": old_stats,
    }
