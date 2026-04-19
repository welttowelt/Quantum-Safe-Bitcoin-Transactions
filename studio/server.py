#!/usr/bin/env python3
"""Local-first operator UI for the QSB pipeline."""

from __future__ import annotations

import json
import math
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
import zipfile
from html import escape
from functools import lru_cache
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


REPO_DIR = Path(__file__).resolve().parents[1]
STUDIO_DIR = REPO_DIR / "studio"
STATIC_DIR = STUDIO_DIR / "static"
SESSIONS_DIR = STUDIO_DIR / "sessions"
PIPELINE_DIR = REPO_DIR / "pipeline"
PIPELINE_SCRIPT = REPO_DIR / "pipeline" / "qsb_pipeline.py"
BENCHMARK_SCRIPT = REPO_DIR / "pipeline" / "benchmark.py"
QSB_RUN_SCRIPT = REPO_DIR / "pipeline" / "qsb_run.py"
LAUNCH_MULTI_GPU_SCRIPT = REPO_DIR / "gpu" / "launch_multi_gpu.sh"
VENV_PYTHON = REPO_DIR / ".venv" / "bin" / "python"
PYTHON_BIN = str(VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable))

if str(PIPELINE_DIR) not in sys.path:
    sys.path.insert(0, str(PIPELINE_DIR))

from bitcoin_tx import find_and_delete, QSBScriptBuilder
from qsb_pipeline import QSB_INPUT_INDEX, build_spending_transaction, decode_pubkey_hash
from secp256k1 import compress_pubkey, ecdsa_recover, encode_der_sig, is_valid_der_sig, qsb_puzzle_hash

ARTIFACT_TEXT = {
    "qsb_raw_tx.hex",
    "pinning_hit.txt",
    "digest_r1_hit.txt",
    "digest_r2_hit.txt",
    "pinning_result.txt",
    "digest_result.txt",
    "binding_report.html",
    "frontier_report.html",
}

ARTIFACT_JSON = {
    "qsb_state.json",
    "gpu_pinning_params.json",
    "gpu_digest_r1_params.json",
    "gpu_digest_r2_params.json",
    "qsb_solution.json",
    "benchmark_results.json",
    "pinning_import.json",
    "digest_r1_import.json",
    "digest_r2_import.json",
    "qsb_vast_package.json",
    "qsb_fleet_state.json",
    "qsb_fleet_status.json",
    "binding_report.json",
    "frontier_report.json",
}

ARTIFACT_BINARY = {
    "pinning.bin",
    "digest_r1.bin",
    "digest_r2.bin",
}

KNOWN_ARTIFACTS = ARTIFACT_JSON | ARTIFACT_TEXT | ARTIFACT_BINARY
PACKAGE_INCLUDE = [
    "LICENSE",
    "README.md",
    "gpu",
    "pipeline",
    "script",
]
INTERNAL_COMMANDS = {
    "import-pinning-hit",
    "import-digest-hit",
}
FRONTIER_TARGET_BITS = 46.2
FRONTIER_PRESETS = [
    {
        "key": "baseline",
        "label": "Baseline",
        "kind": "published",
        "n": 150,
        "t1s": 8,
        "t1b": 0,
        "t2s": 8,
        "t2b": 0,
        "notes": "Published reference point with strong digest entropy but heavy subset mismatch and ~180x grinding overhead.",
    },
    {
        "key": "config-a",
        "label": "Config A",
        "kind": "published",
        "n": 150,
        "t1s": 8,
        "t1b": 1,
        "t2s": 7,
        "t2b": 2,
        "notes": "Recommended paper config: fits exactly in 201 ops and matches the ~2^46 frontier without baseline grinding overhead.",
    },
    {
        "key": "config-b",
        "label": "Config B",
        "kind": "published-overflow",
        "n": 150,
        "t1s": 8,
        "t1b": 1,
        "t2s": 8,
        "t2b": 0,
        "notes": "Interesting theoretical point: keeps full digest strength, but exceeds the opcode budget by one non-push opcode.",
    },
    {
        "key": "a120",
        "label": "A120",
        "kind": "repo-only",
        "n": 120,
        "t1s": 8,
        "t1b": 1,
        "t2s": 7,
        "t2b": 2,
        "notes": "Hidden repo preset. Smaller n saves script bytes, but the frontier model shows RIPEMD160 subset mismatch returns.",
    },
    {
        "key": "a110",
        "label": "A110",
        "kind": "repo-only",
        "n": 110,
        "t1s": 8,
        "t1b": 1,
        "t2s": 7,
        "t2b": 2,
        "notes": "More aggressive repo preset. Lower byte pressure, materially worse subset mismatch under the same puzzle target.",
    },
    {
        "key": "a100",
        "label": "A100",
        "kind": "repo-only",
        "n": 100,
        "t1s": 8,
        "t1b": 1,
        "t2s": 7,
        "t2b": 2,
        "notes": "Fastest hidden preset in comments, but also the furthest from the paper’s balanced frontier under current assumptions.",
    },
]
FRONTIER_RATE_PROFILES = [
    {
        "key": "rtx-4070-super",
        "label": "RTX 4070 SUPER",
        "kind": "reference",
        "note": "Cheap Vast reference from the repo docs.",
        "pin_rate_per_sec": 88_000_000.0,
        "r1_rate_per_sec": 82_000_000.0,
        "r2_rate_per_sec": 82_000_000.0,
        "hourly_usd": 0.089,
    },
    {
        "key": "rtx-pro-6000",
        "label": "RTX PRO 6000",
        "kind": "reference",
        "note": "Fast cloud reference from the repo docs; digest rate remains an estimate.",
        "pin_rate_per_sec": 238_000_000.0,
        "r1_rate_per_sec": 160_000_000.0,
        "r2_rate_per_sec": 160_000_000.0,
        "hourly_usd": 10.69,
    },
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = value.strip("-")
    return value or "session"


def truncate(text: str, limit: int = 2000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n…"


def read_json(path: Path) -> Any:
    with path.open() as handle:
        return json.load(handle)


def decode_args(payload: dict[str, Any] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in (payload or {}).items():
        if value is None:
            continue
        result[key] = str(value)
    return result


def summarize_state(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "config": data.get("config"),
        "funding_mode": data.get("funding_mode"),
        "n": data.get("n"),
        "t1": (data.get("t1s", 0) + data.get("t1b", 0)),
        "t2": (data.get("t2s", 0) + data.get("t2b", 0)),
        "script_size": len(bytes.fromhex(data["full_script_hex"])) if data.get("full_script_hex") else None,
        "script_hash160": data.get("script_hash160"),
        "funding_script_pubkey_size": len(bytes.fromhex(data["funding_script_pubkey"])) if data.get("funding_script_pubkey") else None,
    }


def summarize_solution(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "locktime": data.get("locktime"),
        "sequence": data.get("sequence"),
        "funding_mode": data.get("funding_mode"),
        "dest_value": data.get("dest_value"),
        "round1_indices": data.get("round1_indices"),
        "round2_indices": data.get("round2_indices"),
    }


def summarize_benchmark(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "backend": data.get("backend"),
        "pin_full_candidate_per_sec": data.get("pin_full_candidate_per_sec"),
        "r1_full_candidate_per_sec": data.get("r1_full_candidate_per_sec"),
        "r2_full_candidate_per_sec": data.get("r2_full_candidate_per_sec"),
        "estimated_total_hours": data.get("estimated_total_hours"),
        "estimated_cost_usd": data.get("estimated_cost_usd"),
    }


def summarize_import(data: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "source_name": data.get("source_name"),
        "selected": data.get("selected"),
    }
    if data.get("type") == "pinning-hit":
        summary["sequence"] = data.get("sequence")
        summary["locktime"] = data.get("locktime")
    else:
        summary["round"] = data.get("round")
        summary["indices"] = data.get("selected_indices")
    return summary


def summarize_package(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": data.get("mode"),
        "params_name": data.get("params_name"),
        "zip_name": data.get("zip_name"),
        "size_bytes": data.get("size_bytes"),
        "included_files": data.get("included_files"),
    }


def summarize_fleet(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "stage": data.get("stage"),
        "phase": data.get("phase"),
        "active_instances": data.get("active_instances"),
        "cost_so_far": data.get("cost_so_far"),
        "fleet_hourly": data.get("fleet_hourly"),
        "fleet_rate_est_mhs": data.get("fleet_rate_est_mhs"),
        "hit_file": data.get("hit_file"),
    }


def summarize_binding_report(data: dict[str, Any]) -> dict[str, Any]:
    mutations = data.get("mutations") or []
    mutation = data.get("mutation") or (mutations[0] if mutations else {})
    return {
        "mode": data.get("mode"),
        "headline": data.get("headline"),
        "steps": len(data.get("steps") or []),
        "mutation_count": len(mutations),
        "checks_changed": mutation.get("all_checks_changed"),
    }


def summarize_frontier_report(data: dict[str, Any]) -> dict[str, Any]:
    profiles = data.get("profiles") or []
    selected_key = data.get("selected_profile_key")
    selected = next((profile for profile in profiles if profile.get("key") == selected_key), None)
    return {
        "headline": data.get("headline"),
        "profile_count": len(profiles),
        "selected_profile": selected.get("label") if selected else None,
        "has_session_overlay": any(
            estimate.get("kind") == "session"
            for profile in profiles
            for estimate in (profile.get("runtime_estimates") or [])
        ),
    }


def log2_comb(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float("-inf")
    if k == 0 or k == n:
        return 0.0
    return math.log2(math.comb(n, k))


def log2sumexp(values: list[float]) -> float:
    finite = [value for value in values if value != float("-inf")]
    if not finite:
        return float("-inf")
    peak = max(finite)
    return peak + math.log2(sum(2 ** (value - peak) for value in finite))


def format_bits(value: float | None) -> str:
    if value is None or value == float("-inf"):
        return "—"
    return f"{value:.1f}b"


def format_power(value: float | None) -> str:
    if value is None or value == float("-inf"):
        return "—"
    return f"2^{value:.1f}"


def fixed_frontier_signatures() -> tuple[bytes, bytes, bytes]:
    return (
        encode_der_sig(111, 222, sighash=0x01),
        encode_der_sig(333, 444, sighash=0x01),
        encode_der_sig(555, 666, sighash=0x01),
    )


def detect_frontier_profile_key(state: dict[str, Any]) -> str | None:
    if not state:
        return None
    try:
        n = int(state.get("n"))
        t1s = int(state.get("t1s"))
        t1b = int(state.get("t1b", 0))
        t2s = int(state.get("t2s"))
        t2b = int(state.get("t2b", 0))
    except (TypeError, ValueError):
        return None
    for preset in FRONTIER_PRESETS:
        if (
            preset["n"] == n
            and preset["t1s"] == t1s
            and preset["t1b"] == t1b
            and preset["t2s"] == t2s
            and preset["t2b"] == t2b
        ):
            return preset["key"]
    return None


def build_frontier_rate_profiles(benchmark: dict[str, Any]) -> list[dict[str, Any]]:
    profiles = [dict(profile) for profile in FRONTIER_RATE_PROFILES]
    pin_rate = benchmark.get("pin_full_candidate_per_sec")
    r1_rate = benchmark.get("r1_full_candidate_per_sec")
    r2_rate = benchmark.get("r2_full_candidate_per_sec")
    if pin_rate and r1_rate and r2_rate:
        hourly_usd = None
        total_hours = benchmark.get("estimated_total_hours")
        total_cost = benchmark.get("estimated_cost_usd")
        if total_hours not in (None, 0, "") and total_cost not in (None, ""):
            try:
                total_hours_f = float(total_hours)
                total_cost_f = float(total_cost)
                if total_hours_f > 0:
                    hourly_usd = total_cost_f / total_hours_f
            except (TypeError, ValueError, ZeroDivisionError):
                hourly_usd = None
        profiles.append(
            {
                "key": "session-benchmark",
                "label": f"Current benchmark ({benchmark.get('backend', 'local')})",
                "kind": "session",
                "note": "Measured locally from this workspace's benchmark artifact.",
                "pin_rate_per_sec": float(pin_rate),
                "r1_rate_per_sec": float(r1_rate),
                "r2_rate_per_sec": float(r2_rate),
                "hourly_usd": hourly_usd,
            }
        )
    return profiles


def estimate_frontier_runtime(profile: dict[str, Any], rate_profile: dict[str, Any]) -> dict[str, Any]:
    def phase_hours(bits: float, rate_per_sec: float | None) -> float | None:
        if not rate_per_sec:
            return None
        return (2 ** bits) / rate_per_sec / 3600

    pin_hours = phase_hours(profile["pinning_phase_bits"], rate_profile.get("pin_rate_per_sec"))
    round1_hours = phase_hours(profile["round1_phase_bits"], rate_profile.get("r1_rate_per_sec"))
    round2_hours = phase_hours(profile["round2_phase_bits"], rate_profile.get("r2_rate_per_sec"))
    phases = {
        "pinning": pin_hours,
        "round1": round1_hours,
        "round2": round2_hours,
    }
    finite = {key: value for key, value in phases.items() if value is not None}
    total_hours = sum(finite.values()) if finite else None
    hourly_usd = rate_profile.get("hourly_usd")
    total_cost = total_hours * hourly_usd if total_hours is not None and hourly_usd is not None else None
    bottleneck_key = max(finite, key=finite.get) if finite else None
    bottleneck_label = {
        "pinning": "pinning",
        "round1": "digest round 1",
        "round2": "digest round 2",
    }.get(bottleneck_key)
    return {
        "key": rate_profile["key"],
        "label": rate_profile["label"],
        "kind": rate_profile["kind"],
        "note": rate_profile["note"],
        "pin_rate_per_sec": rate_profile.get("pin_rate_per_sec"),
        "r1_rate_per_sec": rate_profile.get("r1_rate_per_sec"),
        "r2_rate_per_sec": rate_profile.get("r2_rate_per_sec"),
        "hourly_usd": hourly_usd,
        "pin_hours": pin_hours,
        "round1_hours": round1_hours,
        "round2_hours": round2_hours,
        "total_hours": total_hours,
        "total_cost_usd": total_cost,
        "bottleneck": bottleneck_label,
    }


def classify_frontier_profile(opcode_headroom: int, script_headroom: int, tx_grinds_bits: float) -> tuple[str, dict[str, str], str]:
    if opcode_headroom < 0:
        return (
            "over-limit",
            {
                "label": "opcode wall",
                "detail": f"misses the 201 non-push opcode limit by {abs(opcode_headroom)} opcode(s).",
            },
            "Interesting on paper, but not deployable under today's legacy limits.",
        )
    if script_headroom < 0:
        return (
            "over-limit",
            {
                "label": "script wall",
                "detail": f"misses the 10,000-byte script limit by {abs(script_headroom)} byte(s).",
            },
            "Byte pressure, not cryptography, is what breaks this profile first.",
        )
    if tx_grinds_bits > 4:
        return (
            "mismatch-heavy",
            {
                "label": "subset mismatch",
                "detail": f"the digest rounds undershoot the ~2^46 puzzle target badly enough that the whole transaction must be reground about {2 ** tx_grinds_bits:.1f} times on average.",
            },
            "The saved bytes come back as repeated full-transaction grinding.",
        )
    if tx_grinds_bits > 0.5:
        return (
            "mismatch",
            {
                "label": "frontier mismatch",
                "detail": f"still deployable, but the digest rounds are short by about {tx_grinds_bits:.1f} bits of whole-transaction grind overhead.",
            },
            "This works, but it pays extra wall-clock because the subset frontier and puzzle frontier no longer line up.",
        )
    if opcode_headroom == 0:
        return (
            "knife-edge",
            {
                "label": "opcode knife-edge",
                "detail": "fits only because it spends the last available non-push opcode.",
            },
            "This is the narrow lane QSB lives in today: just enough subset entropy, just enough opcode budget.",
        )
    return (
        "balanced",
        {
            "label": "deployable slack",
            "detail": f"fits with {opcode_headroom} opcode(s) and {script_headroom} byte(s) of remaining headroom.",
        },
        "This profile fits cleanly under the current envelope without paying a mismatch penalty.",
    )


@lru_cache(maxsize=1)
def build_static_frontier_profiles() -> list[dict[str, Any]]:
    pin_sig, round1_sig, round2_sig = fixed_frontier_signatures()
    profiles = []

    for preset in FRONTIER_PRESETS:
        n = preset["n"]
        t1s = preset["t1s"]
        t1b = preset["t1b"]
        t2s = preset["t2s"]
        t2b = preset["t2b"]
        t1 = t1s + t1b
        t2 = t2s + t2b

        builder = QSBScriptBuilder(n=n, t1_signed=t1s, t1_bonus=t1b, t2_signed=t2s, t2_bonus=t2b)
        builder.generate_keys()
        script_bytes = len(builder.build_full_script(pin_sig, round1_sig, round2_sig))

        round1_subset_bits = log2_comb(n, t1)
        round2_subset_bits = log2_comb(n, t2)
        digest_bits = log2_comb(n, t1s) + log2_comb(n, t2s)

        round1_gap_bits = max(0.0, FRONTIER_TARGET_BITS - round1_subset_bits)
        round2_gap_bits = max(0.0, FRONTIER_TARGET_BITS - round2_subset_bits)
        tx_grinds_bits = round1_gap_bits + round2_gap_bits
        tx_grinds = 2 ** tx_grinds_bits

        preimage_reduction = log2_comb(n - t1s, t1b) + log2_comb(n - t2s, t2b)
        collision_reduction = log2_comb(t1, t1s) + log2_comb(t2, t2s)
        preimage_bits = (3 * FRONTIER_TARGET_BITS) - preimage_reduction
        collision_bits = FRONTIER_TARGET_BITS + (digest_bits / 2) - collision_reduction

        opcode_used = 21 + (11 * (t1s + t2s)) + (5 * (t1b + t2b))
        opcode_headroom = 201 - opcode_used
        script_headroom = 10_000 - script_bytes

        pinning_phase_bits = FRONTIER_TARGET_BITS + tx_grinds_bits
        round1_phase_bits = round1_subset_bits + tx_grinds_bits
        round2_phase_bits = round2_subset_bits + tx_grinds_bits
        honest_phase_bits = [pinning_phase_bits, round1_phase_bits, round2_phase_bits]
        total_work_bits = log2sumexp(honest_phase_bits)
        phase_share = {
            "pinning": 2 ** (pinning_phase_bits - total_work_bits),
            "round1": 2 ** (round1_phase_bits - total_work_bits),
            "round2": 2 ** (round2_phase_bits - total_work_bits),
        }
        dominant_phase_key = max(
            ("pinning", "round1", "round2"),
            key=lambda key: {
                "pinning": pinning_phase_bits,
                "round1": round1_phase_bits,
                "round2": round2_phase_bits,
            }[key],
        )
        dominant_phase_label = {
            "pinning": "pinning",
            "round1": "digest round 1",
            "round2": "digest round 2",
        }[dominant_phase_key]

        status, dominant_constraint, takeaway = classify_frontier_profile(opcode_headroom, script_headroom, tx_grinds_bits)

        profiles.append(
            {
                "key": preset["key"],
                "label": preset["label"],
                "kind": preset["kind"],
                "notes": preset["notes"],
                "n": n,
                "t1": f"{t1s}+{t1b}b" if t1b else str(t1s),
                "t2": f"{t2s}+{t2b}b" if t2b else str(t2s),
                "opcode_used": opcode_used,
                "opcode_headroom": opcode_headroom,
                "script_bytes": script_bytes,
                "script_headroom": script_headroom,
                "round1_subset_bits": round1_subset_bits,
                "round2_subset_bits": round2_subset_bits,
                "round1_gap_bits": round1_gap_bits,
                "round2_gap_bits": round2_gap_bits,
                "digest_bits": digest_bits,
                "preimage_bits": preimage_bits,
                "collision_bits": collision_bits,
                "tx_grinds_bits": tx_grinds_bits,
                "tx_grinds": tx_grinds,
                "pinning_phase_bits": pinning_phase_bits,
                "round1_phase_bits": round1_phase_bits,
                "round2_phase_bits": round2_phase_bits,
                "total_work_bits": total_work_bits,
                "phase_share": phase_share,
                "dominant_phase": dominant_phase_label,
                "dominant_constraint": dominant_constraint,
                "takeaway": takeaway,
                "status": status,
            }
        )

    config_a = next(profile for profile in profiles if profile["key"] == "config-a")
    for profile in profiles:
        profile["delta_digest_vs_a"] = profile["digest_bits"] - config_a["digest_bits"]
        profile["delta_preimage_vs_a"] = profile["preimage_bits"] - config_a["preimage_bits"]
        profile["delta_collision_vs_a"] = profile["collision_bits"] - config_a["collision_bits"]
        profile["delta_script_vs_a"] = profile["script_bytes"] - config_a["script_bytes"]
        profile["delta_opcode_vs_a"] = profile["opcode_used"] - config_a["opcode_used"]
        profile["relative_work_bits_vs_a"] = profile["total_work_bits"] - config_a["total_work_bits"]
        profile["relative_work_vs_a"] = 2 ** profile["relative_work_bits_vs_a"]
    return profiles


def build_frontier_summary(state: dict[str, Any] | None = None, benchmark: dict[str, Any] | None = None) -> dict[str, Any]:
    benchmark = benchmark or {}
    selected_profile_key = detect_frontier_profile_key(state or {})
    rate_profiles = build_frontier_rate_profiles(benchmark)
    profiles = [dict(profile) for profile in build_static_frontier_profiles()]
    for profile in profiles:
        profile["selected"] = profile["key"] == selected_profile_key
        profile["runtime_estimates"] = [estimate_frontier_runtime(profile, rate_profile) for rate_profile in rate_profiles]
    selected_profile = next((profile for profile in profiles if profile["selected"]), None)

    selection = None
    if state:
        t1 = f"{state.get('t1s', 0)}+{state.get('t1b', 0)}b" if state.get("t1b") else str(state.get("t1s", 0))
        t2 = f"{state.get('t2s', 0)}+{state.get('t2b', 0)}b" if state.get("t2b") else str(state.get("t2s", 0))
        if selected_profile:
            selection = {
                "label": f"Current session maps to {selected_profile['label']}",
                "detail": f"n={selected_profile['n']} · r1 {selected_profile['t1']} · r2 {selected_profile['t2']} · {selected_profile['dominant_constraint']['label']}",
            }
        else:
            selection = {
                "label": "Current session is a custom point",
                "detail": f"n={state.get('n')} · r1 {t1} · r2 {t2}. It does not match the published or repo presets in this lab.",
            }

    baseline = next(profile for profile in profiles if profile["key"] == "baseline")
    config_b = next(profile for profile in profiles if profile["key"] == "config-b")
    repo_only = [profile for profile in profiles if profile["kind"] == "repo-only"]
    repo_only_labels = " / ".join(f"{profile['label']} ({profile['relative_work_vs_a']:.1f}×)" for profile in repo_only)

    return {
        "headline": "The frontier is a staged search problem, not just a parameter table.",
        "summary": "For each profile, this lab asks four questions: does it fit inside 201 ops / 10kb, how many whole-transaction regrounds does subset mismatch force, which phase actually dominates the search, and what wall-clock / cost does that imply on real hardware.",
        "selection": selection,
        "assumptions": [
            "Uses the repo's current RIPEMD160 puzzle framing with a ~2^46.2 target shorthand so every profile is compared on the same binding target.",
            "Computes actual script bytes from the current builder, not handwritten estimates, and keeps the paper's opcode formulas for the round logic.",
            "Models subset mismatch as repeated whole-transaction grinds: if one digest round undershoots the puzzle frontier, pinning and both rounds all get paid again.",
            "Reference hardware comes from the repo's own README and GPU README. The session benchmark, if present, is overlaid as a third local reference.",
        ],
        "insights": [
            "Config A is not arbitrary. It is the only preset here that reaches the 9-selection frontier and still fits exactly inside today's 201-opcode wall.",
            f"Baseline buys {baseline['delta_preimage_vs_a']:+.1f}b of pre-image slack over Config A, but it pays for that with about {baseline['relative_work_vs_a']:.1f}× more raw work because both digest rounds undershoot the puzzle frontier.",
            f"Config B is the cleanest 'stronger but illegal' point: {config_b['delta_preimage_vs_a']:+.1f}b pre-image and {config_b['delta_collision_vs_a']:+.1f}b collision slack over Config A, but it misses deployability by {abs(config_b['opcode_headroom'])} opcode.",
            f"The smaller repo-only presets save bytes, but the saved bytes come back as repeated full-transaction grinds: {repo_only_labels}.",
            "Because the search is embarrassingly parallel, fleet size mainly changes wall-clock. Total dollar cost mostly follows total candidates, not how you shard them.",
        ],
        "rate_profiles": rate_profiles,
        "selected_profile_key": selected_profile_key,
        "profiles": profiles,
    }


def build_frontier_report(by_name: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    state = by_name.get("qsb_state.json", {}).get("data", {})
    benchmark = by_name.get("benchmark_results.json", {}).get("data", {})
    if not state and not benchmark:
        return None
    return build_frontier_summary(state, benchmark)


def build_constraints_summary(state: dict[str, Any], benchmark: dict[str, Any]) -> list[dict[str, Any]]:
    if not state:
        return []
    funding_mode = state.get("funding_mode", "bare")
    script_size = len(bytes.fromhex(state["full_script_hex"])) if state.get("full_script_hex") else None
    script_desc = f"{script_size} bytes" if script_size else "script size unknown"
    cost = benchmark.get("estimated_cost_usd")
    return [
        {
            "label": "Relay",
            "detail": f"Non-standard {funding_mode} script. Expect private relay or direct miner submission, not normal mempool propagation.",
            "value": script_desc,
        },
        {
            "label": "Coverage",
            "detail": "This repo models the QSB-prepared output path. It does not rescue exposed pubkeys, dormant P2PK, or reused-key outputs.",
            "value": "QSB output path only",
        },
        {
            "label": "Compatibility",
            "detail": "Legacy Script only. No Lightning path, no Taproot spend path, and no SegWit destination flow in the current assembler.",
            "value": "Legacy only",
        },
        {
            "label": "Cost posture",
            "detail": "Treat this as an emergency or last-resort operator flow, not a retail payment path.",
            "value": f"${float(cost):.2f} est" if cost not in (None, "") else "run benchmark",
        },
    ]


def build_architecture_summary() -> dict[str, Any]:
    return {
        "headline": "QSB is a coprocessing system with an on-chain verifier.",
        "roles": [
            {
                "label": "Secure signer",
                "boundary": "trusted",
                "detail": "Holds the HORS preimages, verifies candidate hits, builds the unlocking stack, and decides what gets broadcast.",
                "never_sees": "It never has to outsource the actual secrets.",
            },
            {
                "label": "GPU grinder",
                "boundary": "untrusted",
                "detail": "Searches public-data spaces for pinning and digest hits: recovered keys, RIPEMD160 puzzles, subset choices, and sighash candidates.",
                "never_sees": "It never needs the HORS preimages or a spending key.",
            },
            {
                "label": "Bitcoin verifier",
                "boundary": "consensus",
                "detail": "Runs the legacy script path on-chain: checks sig_nonce, recovers the puzzle chain, and verifies the chosen digest-round subset.",
                "never_sees": "It only sees the final transaction and revealed unlocking data.",
            },
        ],
        "flows": [
            "Studio exports binaries and metadata from the planned spend into a public search job.",
            "The GPU fleet returns only candidate hits, not secrets.",
            "The secure side verifies the hit, assembles the spend, and reveals only the exact material needed for that transaction.",
        ],
    }


def build_lineage_summary() -> dict[str, Any]:
    return {
        "headline": "QSB is Binohash-derived, not Binohash with a new label.",
        "inherits": [
            "HORS-style digest signing via hash commitments and revealed preimages",
            "Dummy signatures plus FindAndDelete so subset choices change scriptCode",
            "The SIGHASH_SINGLE bug trick to precompute 9-byte dummy signatures with z = 1",
            "Legacy-script constraints: 201 opcodes, 10,000 bytes, no SegWit/Taproot path",
        ],
        "replaces": [
            "The OP_SIZE small-r puzzle becomes RIPEMD160(pubkey) -> valid DER",
            "Digest-round grinding moves off elliptic-curve structure and onto hash structure",
            "Pinning no longer needs Binohash's broader multi-sighash construction",
        ],
    }


def build_landscape_summary() -> dict[str, Any]:
    return {
        "headline": "Bitcoin's quantum response now has three layers.",
        "layers": [
            {
                "label": "QSB",
                "timing": "before a fork",
                "coverage": "QSB-prepared / unrevealed-key path",
                "detail": "works now under current legacy rules; narrow and non-standard",
            },
            {
                "label": "zk-STARK hatch",
                "timing": "after an emergency fork",
                "coverage": "exposed BIP-32 / HD-wallet path",
                "detail": "recovery mechanism once vulnerable keyspends are disabled",
            },
            {
                "label": "P2MR / BIP-360",
                "timing": "long-term rail",
                "coverage": "future opted-in outputs",
                "detail": "draft protocol path for long-exposure resistance, not a retroactive rescue",
            },
        ],
        "routing": [
            {
                "case": "unrevealed keys you can prepare or move now",
                "best": "QSB",
                "detail": "pre-fork emergency option under today's rules",
            },
            {
                "case": "exposed HD-wallet or BIP-86 coins",
                "best": "zk-STARK hatch",
                "detail": "recovery path after coordinated protocol action",
            },
            {
                "case": "new future outputs",
                "best": "P2MR",
                "detail": "cleanest protocol-native path if activated",
            },
            {
                "case": "old exposed P2PK or lost-key coins",
                "best": "none yet",
                "detail": "still one of the hardest unsolved buckets",
            },
        ],
    }


def build_research_status_summary() -> dict[str, Any]:
    return {
        "headline": "The public state is real but still early.",
        "milestones": [
            "Apr 9, 2026: QSB paper + repo published",
            "Apr 15, 2026: one reported mainnet QSB POC routed via Slipstream",
            "External repo work exists: bug-fix PRs, active forks, and technical issues",
        ],
        "open_questions": [
            {
                "label": "Issue #3",
                "detail": "darosior raised a public question about key_nonce usage across different sighash contexts. This repo now audits the current round-script structure, but the broader paper-level question remains open.",
            },
            {
                "label": "Operational proof",
                "detail": "The local harness is healthy, but repeated GPU-hit-to-broadcast evidence is still thin.",
            },
            {
                "label": "Adoption",
                "detail": "No wallet, custody, or exchange integration is visible yet. Activity is still mostly research, review, and one-off demos.",
            },
        ],
    }


def mutate_dest_address(dest_address: str) -> str:
    raw = bytearray(decode_pubkey_hash(dest_address))
    if not raw:
        return dest_address
    raw[-1] ^= 0x01
    if all(b == 0 for b in raw):
        raw[-1] = 0x01
    return raw.hex()


def mutate_u32(value: int) -> int:
    return value + 1 if value < 0xFFFFFFFF else value - 1


def format_outpoint(txid_hex: str, vout: int) -> str:
    return f"{txid_hex}:{vout}"


def recover_binding_puzzle(sig_r: int, sig_s: int, sighash: int) -> dict[str, Any] | None:
    for flag in (0, 1):
        point = ecdsa_recover(sig_r, sig_s, sighash, flag)
        if not point:
            continue
        key_nonce = compress_pubkey(point)
        sig_puzzle = qsb_puzzle_hash(key_nonce)
        real_der = is_valid_der_sig(sig_puzzle)
        easy_der = (sig_puzzle[0] >> 4) == 3
        if real_der or easy_der:
            return {
                "recovery_flag": flag,
                "key_nonce": key_nonce.hex(),
                "sig_puzzle": sig_puzzle.hex(),
                "real_der": real_der,
                "easy_mode_match": easy_der and not real_der,
            }
    return None


def build_static_binding_report(state: dict[str, Any]) -> dict[str, Any]:
    funding_mode = state.get("funding_mode", "bare")
    return {
        "mode": "static",
        "headline": "QSB rebuilds authorization, not only the unlock.",
        "summary": "The script checks a hardcoded signature against the current sighash, hashes the recovered key into a puzzle signature, and repeats that pattern inside the digest rounds after FindAndDelete removes the selected dummy signatures.",
        "steps": [
            {
                "label": "Pinning",
                "detail": "A hardcoded sig_nonce and SIGHASH_ALL bind sequence, locktime, inputs, and outputs to one recovered key_nonce.",
                "value": funding_mode,
            },
            {
                "label": "Puzzle",
                "detail": "The script hashes key_nonce with RIPEMD160 and treats the 20-byte output as sig_puzzle.",
                "value": state.get("script_hash160"),
            },
            {
                "label": "Digest rounds",
                "detail": "Each selected dummy-signature subset changes scriptCode via FindAndDelete, which changes the sighash and forces a new puzzle solve.",
                "value": f"n={state.get('n')} | t1={state.get('t1s', 0) + state.get('t1b', 0)} | t2={state.get('t2s', 0) + state.get('t2b', 0)}",
            },
        ],
        "mutations": [],
        "mutation": None,
    }


def build_binding_report(by_name: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    state = by_name.get("qsb_state.json", {}).get("data")
    if not state:
        return None

    report = build_static_binding_report(state)
    solution = by_name.get("qsb_solution.json", {}).get("data")
    if not solution:
        return report

    required = (
        "sequence",
        "locktime",
        "helper_txid",
        "helper_vout",
        "funding_txid",
        "funding_vout",
        "funding_value",
        "dest_address",
        "round1_indices",
        "round2_indices",
    )
    if any(solution.get(key) in (None, "") for key in required):
        return report

    try:
        full_script = bytes.fromhex(state["full_script_hex"])
        helper_script_sig = bytes.fromhex(solution.get("helper_script_sig_hex", ""))
        sequence = int(solution["sequence"])
        locktime = int(solution["locktime"])
        funding_value = int(solution["funding_value"])
        helper_vout = int(solution["helper_vout"])
        funding_vout = int(solution["funding_vout"])
        helper_txid_hex = solution["helper_txid"]
        funding_txid_hex = solution["funding_txid"]
        dest_address = solution["dest_address"]

        def make_tx(
            *,
            helper_txid_text: str = helper_txid_hex,
            helper_vout_value: int = helper_vout,
            dest_address_value: str = dest_address,
            locktime_value: int = locktime,
            qsb_sequence_value: int = sequence,
        ):
            tx, _ = build_spending_transaction(
                bytes.fromhex(helper_txid_text)[::-1],
                helper_vout_value,
                bytes.fromhex(funding_txid_hex)[::-1],
                funding_vout,
                funding_value,
                dest_address_value,
                locktime=locktime_value,
                qsb_sequence=qsb_sequence_value,
                helper_script_sig=helper_script_sig,
            )
            return tx

        def compute_checks(tx):
            pin_sig = bytes.fromhex(state["pin_sig"])
            pin_sc = find_and_delete(full_script, pin_sig)
            checks = [
                {
                    "key": "pinning",
                    "label": "Pinning",
                    "detail": "sig_nonce ties sequence, locktime, inputs, and outputs to one recovered key_nonce before RIPEMD160 turns that key into sig_puzzle.",
                    "value": f"sequence={sequence} | locktime={locktime}",
                    "result": recover_binding_puzzle(
                        state["pin_r"],
                        state["pin_s"],
                        tx.sighash(QSB_INPUT_INDEX, pin_sc, sighash_type=0x01),
                    ),
                }
            ]
            round_pairs = [
                ("round1", "Round 1", 0, solution["round1_indices"]),
                ("round2", "Round 2", 1, solution["round2_indices"]),
            ]
            for key, label, round_index, indices in round_pairs:
                sig_nonce = bytes.fromhex(state["round_sigs"][round_index]["sig"])
                script_code = find_and_delete(full_script, sig_nonce)
                for idx in indices:
                    script_code = find_and_delete(script_code, bytes.fromhex(state["dummy_sigs"][round_index][idx]))
                checks.append(
                    {
                        "key": key,
                        "label": label,
                        "detail": "The chosen dummy-signature subset changes scriptCode before sighash, so the recovered key and puzzle stay tied to the exact spend.",
                        "value": f"subset {', '.join(str(i) for i in indices)}",
                        "result": recover_binding_puzzle(
                            state["round_sigs"][round_index]["r"],
                            state["round_sigs"][round_index]["s"],
                            tx.sighash(QSB_INPUT_INDEX, script_code, sighash_type=0x01),
                        ),
                    }
                )
            return checks

        original_tx = make_tx()
        original_checks = compute_checks(original_tx)
        mutated_dest_address = mutate_dest_address(dest_address)

        scenario_specs = [
            {
                "label": "Destination output",
                "field": "destination output",
                "detail": "Outputs are committed by SIGHASH_ALL. If the payee changes, the recovered key and puzzle chain must change too.",
                "why": "This is the direct Darth Vader swap attack the podcast is about.",
                "original": dest_address,
                "mutated": mutated_dest_address,
                "builder": lambda: make_tx(dest_address_value=mutated_dest_address),
            },
            {
                "label": "QSB sequence",
                "field": "qsb input sequence",
                "detail": "The searched QSB sequence is part of the exact transaction being authorized. Changing it should invalidate the same unlock.",
                "why": "Pinning commits to the transaction envelope, not only the destination output.",
                "original": str(sequence),
                "mutated": str(mutate_u32(sequence)),
                "builder": lambda: make_tx(qsb_sequence_value=mutate_u32(sequence)),
            },
            {
                "label": "Locktime",
                "field": "locktime",
                "detail": "Locktime is part of the same sighash. A different locktime should force a fresh puzzle solve across pinning and digest rounds.",
                "why": "The pinning search literally hunts for a valid (sequence, locktime) pair.",
                "original": str(locktime),
                "mutated": str(mutate_u32(locktime)),
                "builder": lambda: make_tx(locktime_value=mutate_u32(locktime)),
            },
            {
                "label": "Helper input",
                "field": "helper input outpoint",
                "detail": "Even the non-QSB helper input sits inside the same SIGHASH_ALL transaction. Change the outpoint and the authorization chain should break.",
                "why": "QSB ties the unlock to the full spend shape, not only the QSB input itself.",
                "original": format_outpoint(helper_txid_hex, helper_vout),
                "mutated": format_outpoint(helper_txid_hex, mutate_u32(helper_vout)),
                "builder": lambda: make_tx(helper_vout_value=mutate_u32(helper_vout)),
            },
        ]

        mutations = []
        for spec in scenario_specs:
            mutated_checks = compute_checks(spec["builder"]())
            scenario_checks = []
            change_flags = []
            for original_check, mutated_check in zip(original_checks, mutated_checks):
                original_result = original_check.get("result")
                mutated_result = mutated_check.get("result")
                changed = bool(
                    original_result
                    and mutated_result
                    and original_result["sig_puzzle"] != mutated_result["sig_puzzle"]
                )
                change_flags.append(changed)
                scenario_checks.append(
                    {
                        "key": original_check["key"],
                        "label": original_check["label"],
                        "changed": changed,
                        "reason": original_check["detail"],
                        "original_sig_puzzle": original_result["sig_puzzle"] if original_result else None,
                        "mutated_sig_puzzle": mutated_result["sig_puzzle"] if mutated_result else None,
                    }
                )
            changed_count = sum(1 for changed in change_flags if changed)
            mutations.append(
                {
                    "label": spec["label"],
                    "field": spec["field"],
                    "detail": spec["detail"],
                    "why": spec["why"],
                    "original": spec["original"],
                    "mutated": spec["mutated"],
                    "checks": scenario_checks,
                    "changed_count": changed_count,
                    "all_checks_changed": all(change_flags),
                    "verdict": "The same unlocking data no longer authorizes this mutated spend."
                    if all(change_flags)
                    else "Some puzzles stayed the same, so this mutation did not fully invalidate every check.",
                }
            )

        report = {
            "mode": "dynamic",
            "headline": "Changing committed transaction fields forces a new puzzle solve.",
            "summary": "Studio rebuilt the assembled spend and mutated the destination, QSB sequence, locktime, and helper input. Every changed puzzle shows that the unlock no longer authorizes that altered transaction.",
            "steps": [
                {
                    "label": check["label"],
                    "detail": check["detail"],
                    "value": check["value"],
                    "sig_puzzle": check["result"]["sig_puzzle"] if check.get("result") else None,
                }
                for check in original_checks
            ],
            "mutations": mutations,
            "mutation": mutations[0] if mutations else None,
        }
        return report
    except Exception as exc:
        report["summary"] = f"{report['summary']} Studio could not build a live mutation check from the current artifacts: {exc}"
        return report


def render_binding_report_html(report: dict[str, Any], session_label: str) -> str:
    architecture = build_architecture_summary()
    steps = []
    for step in report.get("steps") or []:
        chips = []
        if step.get("value"):
            chips.append(f'<span class="chip mono">{escape(str(step["value"]))}</span>')
        if step.get("sig_puzzle"):
            chips.append(f'<span class="chip mono">orig {escape(str(step["sig_puzzle"]))}</span>')
        steps.append(
            f"""
            <section class="step">
              <div class="step-copy">
                <h3>{escape(str(step.get("label", "")))}</h3>
                <p>{escape(str(step.get("detail", "")))}</p>
              </div>
              <div class="chip-row">{''.join(chips)}</div>
            </section>
            """
        )

    mutations = report.get("mutations") or []
    mutation_html = ""
    if mutations:
        mutation_sections = []
        for mutation in mutations:
            check_chips = "".join(
                f'<span class="chip {"ok" if check.get("changed") else "warn"}">{escape(str(check.get("label", "")))}: {"changed" if check.get("changed") else "same"}</span>'
                for check in mutation.get("checks") or []
            )
            mutation_sections.append(
                f"""
                <section class="mutation-scenario">
                  <div class="mutation-copy">
                    <h3>{escape(str(mutation.get("label", "")))}</h3>
                    <p>{escape(str(mutation.get("detail", "")))}</p>
                    <p class="mutation-why">{escape(str(mutation.get("why", "")))}</p>
                  </div>
                  <div class="mutation">
                    <div class="card">
                      <span>Original</span>
                      <strong>{escape(str(mutation.get("original", "")))}</strong>
                    </div>
                    <div class="card">
                      <span>Mutated</span>
                      <strong>{escape(str(mutation.get("mutated", "")))}</strong>
                    </div>
                    <div class="card">
                      <span>Checks changed</span>
                      <strong>{escape(str(mutation.get("changed_count", 0)))} / {len(mutation.get("checks") or [])}</strong>
                    </div>
                    <div class="card">
                      <span>Verdict</span>
                      <strong>{escape(str(mutation.get("verdict", "")))}</strong>
                    </div>
                  </div>
                  <div class="chip-row">{check_chips}</div>
                </section>
                """
            )
        mutation_html = "".join(mutation_sections)

    report_mode = "LIVE CHECK" if report.get("mode") == "dynamic" else "STATIC MAP"
    mode_copy = (
        "Studio rebuilt the spend, mutated several committed fields, and recomputed the recovered puzzle chain for each scenario."
        if report.get("mode") == "dynamic"
        else "This session has enough artifacts to explain the authorization path, but not enough to run a mutation proof yet."
    )
    takeaway = (
        "Each scenario shows the same unlock stops authorizing the spend once a committed field changes."
        if mutations
        else "The unlock works only because the script ties the recovered key to one exact transaction."
    )
    problem_copy = (
        "An honest spender can reveal valid unlocking data. A quantum attacker still wins if they can keep that unlock and rewrite the outputs."
    )
    mechanism_copy = (
        "QSB hardcodes sig_nonce, recovers key_nonce from the current sighash, hashes that key with RIPEMD160 into sig_puzzle, and repeats the same logic inside the digest rounds after FindAndDelete removes the chosen dummy signatures."
    )

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>QSB Binding Report · {escape(session_label)}</title>
    <style>
      :root {{
        --bg: #0c0a18;
        --bg-alt: #151225;
        --card: rgba(30, 26, 48, 0.9);
        --line: rgba(196, 136, 61, 0.22);
        --text: #ffffff;
        --text-soft: #b0acc0;
        --text-dim: #7a7490;
        --accent: #e86a2d;
        --accent-soft: #c4883d;
        --ok: #00c853;
        --warn: #ffb300;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        min-height: 100vh;
        color: var(--text);
        font-family: "IBM Plex Sans", sans-serif;
        background:
          radial-gradient(circle at top right, rgba(232, 106, 45, 0.16), transparent 26%),
          linear-gradient(135deg, #090712, #0c0a18 42%, #151225 100%);
      }}
      .wrap {{ max-width: 1040px; margin: 0 auto; padding: 48px 24px 72px; }}
      .hero {{
        display: grid;
        gap: 22px;
        padding: 30px;
        border: 1px solid var(--line);
        border-radius: 28px;
        background: var(--card);
        box-shadow: 0 26px 80px rgba(0, 0, 0, 0.32);
      }}
      .eyebrow {{
        margin: 0;
        text-transform: uppercase;
        letter-spacing: 0.18em;
        font-size: 0.72rem;
        color: var(--accent-soft);
      }}
      h1, h2, h3 {{ margin: 0; font-family: Georgia, serif; }}
      h1 {{ font-size: clamp(2.2rem, 5vw, 4rem); line-height: 0.98; max-width: 12ch; }}
      .hero p:last-child {{ margin: 0; color: var(--text-soft); line-height: 1.6; max-width: 70ch; }}
      .hero-top {{
        display: flex;
        align-items: start;
        justify-content: space-between;
        gap: 16px;
      }}
      .hero-mode {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 10px 14px;
        border-radius: 999px;
        border: 1px solid var(--line);
        background: rgba(255, 255, 255, 0.04);
        font-size: 0.78rem;
        letter-spacing: 0.08em;
      }}
      .meta, .mutation, .concepts {{
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 12px;
        margin-top: 18px;
      }}
      .architecture {{
        display: grid;
        gap: 14px;
        margin-top: 18px;
      }}
      .card, .step {{
        padding: 18px;
        border-radius: 22px;
        border: 1px solid var(--line);
        background: rgba(255, 255, 255, 0.035);
      }}
      .card span {{
        display: block;
        color: var(--text-dim);
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-size: 0.74rem;
      }}
      .card strong {{ display: block; margin-top: 8px; font-size: 1rem; line-height: 1.45; word-break: break-all; }}
      .card p {{
        margin: 8px 0 0;
        color: var(--text-soft);
        line-height: 1.55;
      }}
      .steps {{ display: grid; gap: 14px; margin-top: 22px; }}
      .step {{
        display: grid;
        gap: 14px;
      }}
      .mutation-scenario {{
        display: grid;
        gap: 14px;
        margin-top: 14px;
      }}
      .mutation-copy p {{
        margin: 8px 0 0;
        color: var(--text-soft);
        line-height: 1.55;
      }}
      .mutation-why {{
        color: var(--text-dim);
      }}
      .step p {{ margin: 8px 0 0; color: var(--text-soft); line-height: 1.55; }}
      .chip-row {{ display: flex; flex-wrap: wrap; gap: 8px; }}
      .chip {{
        padding: 9px 12px;
        border-radius: 999px;
        border: 1px solid var(--line);
        background: rgba(255, 255, 255, 0.04);
        color: var(--text-soft);
        font-size: 0.82rem;
      }}
      .chip.mono {{ font-family: "IBM Plex Mono", monospace; font-size: 0.75rem; }}
      .chip.ok {{ color: var(--ok); }}
      .chip.warn {{ color: var(--warn); }}
      .section-label {{
        margin: 26px 0 10px;
        color: var(--accent-soft);
        text-transform: uppercase;
        letter-spacing: 0.18em;
        font-size: 0.72rem;
      }}
      .takeaway {{
        margin-top: 18px;
        padding: 18px;
        border-radius: 22px;
        border: 1px solid rgba(232, 106, 45, 0.28);
        background:
          radial-gradient(circle at top right, rgba(232, 106, 45, 0.14), transparent 38%),
          rgba(255, 255, 255, 0.035);
      }}
      .takeaway span {{
        display: block;
        color: var(--accent-soft);
        text-transform: uppercase;
        letter-spacing: 0.12em;
        font-size: 0.74rem;
      }}
      .takeaway strong {{
        display: block;
        margin-top: 8px;
        font-size: 1.08rem;
        line-height: 1.5;
      }}
      @media (max-width: 720px) {{
        .hero-top {{
          display: grid;
        }}
        .meta, .mutation, .concepts {{ grid-template-columns: 1fr; }}
      }}
    </style>
  </head>
  <body>
    <div class="wrap">
      <section class="hero">
        <div class="hero-top">
          <p class="eyebrow">QSB Authorization Report</p>
          <div class="hero-mode">{report_mode}</div>
        </div>
        <h1>{escape(str(report.get("headline", "")))}</h1>
        <p>{escape(str(report.get("summary", "")))}</p>
        <div class="meta">
          <div class="card">
            <span>Session</span>
            <strong>{escape(session_label)}</strong>
          </div>
          <div class="card">
            <span>Mode</span>
            <strong>{escape(str(report.get("mode", "unknown")))}</strong>
            <p>{escape(mode_copy)}</p>
          </div>
        </div>
        <div class="concepts">
          <div class="card">
            <span>Problem</span>
            <strong>The unlock alone is not enough.</strong>
            <p>{escape(problem_copy)}</p>
          </div>
          <div class="card">
            <span>Mechanism</span>
            <strong>sig_nonce, key_nonce, sig_puzzle.</strong>
            <p>{escape(mechanism_copy)}</p>
          </div>
        </div>
        <div class="architecture">
          <div class="card">
            <span>Coprocessing</span>
            <strong>{escape(str(architecture.get("headline", "")))}</strong>
            <p>{escape(str((architecture.get("flows") or [""])[0]))}</p>
          </div>
          <div class="meta">
            {''.join(
                f'''
                <div class="card">
                  <span>{escape(str(role.get("boundary", "")))}</span>
                  <strong>{escape(str(role.get("label", "")))}</strong>
                  <p>{escape(str(role.get("detail", "")))}</p>
                  <p>{escape(str(role.get("never_sees", "")))}</p>
                </div>
                '''
                for role in architecture.get("roles") or []
            )}
          </div>
        </div>
        <div class="takeaway">
          <span>Takeaway</span>
          <strong>{escape(str(takeaway))}</strong>
        </div>
      </section>
      <p class="section-label">Authorization chain</p>
      <section class="steps">
        {''.join(steps)}
      </section>
      {'<p class="section-label">Mutation proof</p>' if mutation_html else ''}
      {mutation_html}
    </div>
  </body>
</html>
"""


def render_frontier_report_html(report: dict[str, Any], session_label: str) -> str:
    def fmt_hours(value: float | None) -> str:
        if value is None:
            return "—"
        if value < 1:
            return f"{value * 60:.0f}m"
        if value < 48:
            return f"{value:.1f}h" if value < 10 else f"{value:.0f}h"
        days = value / 24
        return f"{days:.1f}d" if days < 10 else f"{days:.0f}d"

    def fmt_money(value: float | None) -> str:
        if value is None:
            return "—"
        return f"${value:,.0f}" if value >= 100 else f"${value:,.2f}"

    selection = report.get("selection")
    profiles = report.get("profiles") or []
    profile_cards = []
    for profile in profiles:
        estimates = []
        bytes_vs_a = "same" if profile.get("delta_script_vs_a") == 0 else f"{profile.get('delta_script_vs_a'):+}B"
        for estimate in profile.get("runtime_estimates") or []:
            estimates.append(
                f"""
                <div class="estimate">
                  <div class="estimate-head">
                    <strong>{escape(str(estimate.get("label", "")))}</strong>
                    <span class="chip {'ok' if estimate.get('kind') == 'session' else 'warn'}">{escape(str(estimate.get("kind", "")))}</span>
                  </div>
                  <p>{escape(str(estimate.get("note", "")))}</p>
                  <div class="metric-grid compact">
                    <div class="metric"><span>Wall time</span><strong>{fmt_hours(estimate.get("total_hours"))}</strong></div>
                    <div class="metric"><span>Bottleneck</span><strong>{escape(str(estimate.get("bottleneck") or "—"))}</strong></div>
                    <div class="metric"><span>Pin / R1 / R2</span><strong>{escape(f"{fmt_hours(estimate.get('pin_hours'))} · {fmt_hours(estimate.get('round1_hours'))} · {fmt_hours(estimate.get('round2_hours'))}")}</strong></div>
                    <div class="metric"><span>Cost</span><strong>{fmt_money(estimate.get("total_cost_usd"))}</strong></div>
                  </div>
                </div>
                """
            )
        profile_cards.append(
            f"""
            <section class="profile {'current' if profile.get('selected') else ''} {escape(str(profile.get('status', '')))}">
              <div class="profile-head">
                <div>
                  <p class="mini">{escape(str(profile.get("kind", "")))}</p>
                  <h3>{escape(str(profile.get("label", "")))}</h3>
                </div>
                <div class="chip-row">
                  <span class="chip {'ok' if profile.get('status') == 'balanced' else 'warn' if profile.get('status') in ('knife-edge', 'mismatch') else 'bad'}">{escape(str(profile.get('status', '')).replace('-', ' '))}</span>
                  {'<span class="chip ok">current session</span>' if profile.get('selected') else ''}
                </div>
              </div>
              <p>{escape(str(profile.get("notes", "")))}</p>
              <p class="takeaway">{escape(str(profile.get("takeaway", "")))}</p>
              <div class="metric-grid">
                <div class="metric"><span>Profile</span><strong>n={escape(str(profile.get("n")))} · r1 {escape(str(profile.get("t1")))} · r2 {escape(str(profile.get("t2")))}</strong></div>
                <div class="metric"><span>Dominant constraint</span><strong>{escape(str(profile.get("dominant_constraint", {}).get("label", "—")))}</strong></div>
                <div class="metric"><span>Tx regrounds</span><strong>{profile.get("tx_grinds", 0):.1f}×</strong></div>
                <div class="metric"><span>Dominant phase</span><strong>{escape(str(profile.get("dominant_phase", "—")))}</strong></div>
                <div class="metric"><span>Raw work vs A</span><strong>{profile.get("relative_work_vs_a", 0):.1f}×</strong></div>
                <div class="metric"><span>Opcode</span><strong>{escape(str(profile.get("opcode_used")))} / 201 ({'+' if (profile.get('opcode_headroom') or 0) >= 0 else ''}{escape(str(profile.get("opcode_headroom")))})</strong></div>
                <div class="metric"><span>Script bytes</span><strong>{escape(str(profile.get("script_bytes")))} / 10000 ({'+' if (profile.get('script_headroom') or 0) >= 0 else ''}{escape(str(profile.get("script_headroom")))})</strong></div>
                <div class="metric"><span>R1 / R2 gap</span><strong>{format_bits(profile.get("round1_gap_bits"))} · {format_bits(profile.get("round2_gap_bits"))}</strong></div>
                <div class="metric"><span>Digest</span><strong>{format_bits(profile.get("digest_bits"))}</strong></div>
                <div class="metric"><span>Pre-image</span><strong>{format_bits(profile.get("preimage_bits"))}</strong></div>
                <div class="metric"><span>Collision</span><strong>{format_bits(profile.get("collision_bits"))}</strong></div>
                <div class="metric"><span>Bytes vs A</span><strong>{bytes_vs_a}</strong></div>
              </div>
              <p class="detail">{escape(str(profile.get("dominant_constraint", {}).get("detail", "")))}</p>
              <div class="estimates">{''.join(estimates)}</div>
            </section>
            """
        )

    assumptions = "".join(f"<li>{escape(str(item))}</li>" for item in (report.get("assumptions") or []))
    insights = "".join(f"<li>{escape(str(item))}</li>" for item in (report.get("insights") or []))
    selection_block = (
        f"""
        <section class="callout">
          <p class="mini">Current session</p>
          <strong>{escape(str(selection.get("label", "")))}</strong>
          <p>{escape(str(selection.get("detail", "")))}</p>
        </section>
        """
        if selection
        else ""
    )
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>QSB Frontier Report · {escape(session_label)}</title>
    <style>
      :root {{
        --bg: #0c0a18;
        --bg-alt: #151225;
        --card: rgba(30, 26, 48, 0.9);
        --line: rgba(196, 136, 61, 0.22);
        --text: #ffffff;
        --text-soft: #b0acc0;
        --text-dim: #7a7490;
        --accent: #e86a2d;
        --accent-soft: #c4883d;
        --ok: #00c853;
        --warn: #ffb300;
        --bad: #f07a3d;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        min-height: 100vh;
        color: var(--text);
        font-family: "IBM Plex Sans", sans-serif;
        background:
          radial-gradient(circle at top right, rgba(232, 106, 45, 0.16), transparent 24%),
          linear-gradient(135deg, #090712, #0c0a18 42%, #151225 100%);
      }}
      .wrap {{ max-width: 1120px; margin: 0 auto; padding: 48px 24px 72px; }}
      .hero, .panel, .profile {{
        display: grid;
        gap: 18px;
        padding: 28px;
        border: 1px solid var(--line);
        border-radius: 28px;
        background: var(--card);
        box-shadow: 0 26px 80px rgba(0, 0, 0, 0.28);
      }}
      .hero h1, h2, h3 {{ margin: 0; font-family: Georgia, serif; }}
      .hero h1 {{ font-size: clamp(2.1rem, 5vw, 3.7rem); line-height: 0.98; max-width: 14ch; }}
      .hero p, .panel p, .profile p, li {{ color: var(--text-soft); line-height: 1.6; }}
      .eyebrow, .mini {{
        margin: 0;
        text-transform: uppercase;
        letter-spacing: 0.16em;
        font-size: 0.72rem;
        color: var(--accent-soft);
      }}
      .hero-top, .profile-head, .estimate-head {{
        display: flex;
        align-items: start;
        justify-content: space-between;
        gap: 14px;
      }}
      .hero-mode, .chip {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 10px 14px;
        border-radius: 999px;
        border: 1px solid var(--line);
        background: rgba(255, 255, 255, 0.04);
        font-size: 0.78rem;
      }}
      .chip-row {{ display: flex; flex-wrap: wrap; gap: 10px; }}
      .chip.ok {{ border-color: rgba(0, 200, 83, 0.35); color: var(--ok); }}
      .chip.warn {{ border-color: rgba(255, 179, 0, 0.35); color: var(--warn); }}
      .chip.bad {{ border-color: rgba(240, 122, 61, 0.35); color: var(--bad); }}
      .section-grid {{ display: grid; grid-template-columns: 1.1fr 0.9fr; gap: 18px; margin-top: 18px; }}
      .panel ul {{ margin: 0; padding-left: 18px; }}
      .callout {{
        display: grid;
        gap: 8px;
        padding: 18px;
        border-radius: 18px;
        border: 1px solid rgba(0, 200, 83, 0.25);
        background: radial-gradient(circle at top right, rgba(0, 200, 83, 0.12), transparent 38%), rgba(255,255,255,0.02);
      }}
      .stack {{ display: grid; gap: 16px; margin-top: 18px; }}
      .profile {{ position: relative; overflow: hidden; }}
      .profile::before {{
        content: "";
        position: absolute;
        inset: 0 auto 0 0;
        width: 4px;
        background: rgba(196, 136, 61, 0.65);
      }}
      .profile.balanced::before {{ background: rgba(0, 200, 83, 0.7); }}
      .profile.knife-edge::before, .profile.mismatch::before {{ background: rgba(255, 179, 0, 0.8); }}
      .profile.over-limit::before, .profile.mismatch-heavy::before {{ background: rgba(240, 122, 61, 0.9); }}
      .profile.current {{ box-shadow: inset 0 0 0 1px rgba(0, 200, 83, 0.3), 0 26px 80px rgba(0, 0, 0, 0.28); }}
      .takeaway {{ color: var(--text); font-weight: 600; }}
      .detail {{ color: var(--text-soft); }}
      .metric-grid {{
        display: grid;
        gap: 10px;
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }}
      .metric-grid.compact {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .metric {{
        display: grid;
        gap: 6px;
        padding: 10px 12px;
        border-radius: 14px;
        border: 1px solid rgba(255,255,255,0.06);
        background: rgba(255,255,255,0.02);
      }}
      .metric span {{ color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.08em; font-size: 0.72rem; }}
      .metric strong {{ font-size: 0.95rem; line-height: 1.45; }}
      .estimates {{ display: grid; gap: 10px; }}
      .estimate {{
        display: grid;
        gap: 10px;
        padding: 12px;
        border-radius: 16px;
        border: 1px solid rgba(255,255,255,0.06);
        background: rgba(255,255,255,0.02);
      }}
      .footnote {{ color: var(--text-dim); font-size: 0.85rem; }}
      @media (max-width: 840px) {{
        .section-grid, .metric-grid, .metric-grid.compact {{ grid-template-columns: 1fr; }}
      }}
    </style>
  </head>
  <body>
    <div class="wrap">
      <section class="hero">
        <div class="hero-top">
          <div>
            <p class="eyebrow">qsb frontier report</p>
            <h1>{escape(str(report.get("headline", "")))}</h1>
          </div>
          <div class="hero-mode">generated for {escape(session_label)}</div>
        </div>
        <p>{escape(str(report.get("summary", "")))}</p>
      </section>
      <div class="section-grid">
        <section class="panel">
          <h2>what the lab says</h2>
          <ul>{insights}</ul>
        </section>
        <section class="panel">
          <h2>assumptions</h2>
          <ul>{assumptions}</ul>
          {selection_block}
        </section>
      </div>
      <div class="stack">
        {''.join(profile_cards)}
      </div>
    </div>
  </body>
</html>
"""


def sync_binding_report_artifacts(session_id: str) -> None:
    session_dir = SESSIONS_DIR / session_id
    session_meta_path = session_dir / "session.json"
    session_meta = read_json(session_meta_path) if session_meta_path.exists() else {}
    json_artifacts = {}
    for name in ARTIFACT_JSON:
        path = session_dir / name
        if path.exists():
            json_artifacts[name] = {"name": name, "data": read_json(path)}
    report = build_binding_report(json_artifacts)
    json_path = session_dir / "binding_report.json"
    html_path = session_dir / "binding_report.html"
    if not report:
        if json_path.exists():
            json_path.unlink()
        if html_path.exists():
            html_path.unlink()
        return

    json_payload = json.dumps(report, indent=2)
    html_payload = render_binding_report_html(report, session_meta.get("label", session_id))
    if not json_path.exists() or json_path.read_text() != json_payload:
        json_path.write_text(json_payload)
    if not html_path.exists() or html_path.read_text() != html_payload:
        html_path.write_text(html_payload)


def sync_frontier_report_artifacts(session_id: str) -> None:
    session_dir = SESSIONS_DIR / session_id
    session_meta_path = session_dir / "session.json"
    session_meta = read_json(session_meta_path) if session_meta_path.exists() else {}
    json_artifacts = {}
    for name in ARTIFACT_JSON:
        path = session_dir / name
        if path.exists():
            json_artifacts[name] = {"name": name, "data": read_json(path)}
    report = build_frontier_report(json_artifacts)
    json_path = session_dir / "frontier_report.json"
    html_path = session_dir / "frontier_report.html"
    if not report:
        if json_path.exists():
            json_path.unlink()
        if html_path.exists():
            html_path.unlink()
        return

    json_payload = json.dumps(report, indent=2)
    html_payload = render_frontier_report_html(report, session_meta.get("label", session_id))
    if not json_path.exists() or json_path.read_text() != json_payload:
        json_path.write_text(json_payload)
    if not html_path.exists() or html_path.read_text() != html_payload:
        html_path.write_text(html_payload)


def artifact_snapshot(path: Path) -> dict[str, Any]:
    base = {
        "name": path.name,
        "size": path.stat().st_size,
        "updated_at": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(),
    }
    if path.name in ARTIFACT_JSON:
        data = read_json(path)
        base["kind"] = "json"
        base["data"] = data
        if path.name == "qsb_state.json":
            base["summary"] = summarize_state(data)
        elif path.name == "qsb_solution.json":
            base["summary"] = summarize_solution(data)
        elif path.name == "benchmark_results.json":
            base["summary"] = summarize_benchmark(data)
        elif path.name in {"pinning_import.json", "digest_r1_import.json", "digest_r2_import.json"}:
            base["summary"] = summarize_import(data)
        elif path.name == "qsb_vast_package.json":
            base["summary"] = summarize_package(data)
        elif path.name == "qsb_fleet_status.json":
            base["summary"] = summarize_fleet(data)
        elif path.name == "binding_report.json":
            base["summary"] = summarize_binding_report(data)
        elif path.name == "frontier_report.json":
            base["summary"] = summarize_frontier_report(data)
        else:
            base["summary"] = {
                key: data.get(key)
                for key in (
                    "type",
                    "round",
                    "sequence",
                    "locktime",
                    "helper_input_index",
                    "qsb_input_index",
                    "output_count",
                    "total_preimage_len",
                    "suffix_template_len",
                    "tail_section_len",
                    "dummy_sig_len",
                    "midstate_blocks",
                )
                if key in data
            }
        return base

    if path.name in ARTIFACT_TEXT:
        base["kind"] = "text"
        content = path.read_text()
        base["content"] = truncate(content, 10000)
        return base

    if path.name in ARTIFACT_BINARY:
        base["kind"] = "binary"
        return base

    base["kind"] = "unknown"
    return base


def build_workspace_overview(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    by_name = {artifact["name"]: artifact for artifact in artifacts}
    state = by_name.get("qsb_state.json", {}).get("data", {})
    benchmark = by_name.get("benchmark_results.json", {}).get("data", {})
    fleet = by_name.get("qsb_fleet_status.json", {}).get("data", {})
    binding = build_binding_report(by_name)
    stages = [
        {
            "key": "setup",
            "label": "Setup",
            "status": "complete" if "qsb_state.json" in by_name else "pending",
            "detail": f"{state.get('funding_mode', 'unknown')} funding" if state else "Generate the QSB script + funding surface",
        },
        {
            "key": "pinning",
            "label": "Pinning",
            "status": "complete" if "pinning_import.json" in by_name else "active" if fleet.get("stage") == "pinning" else "ready" if "pinning.bin" in by_name else "pending",
            "detail": "sequence / locktime resolved" if "pinning_import.json" in by_name else "Export pinning.bin and search",
        },
        {
            "key": "digest",
            "label": "Digest",
            "status": "complete" if "digest_r1_import.json" in by_name and "digest_r2_import.json" in by_name else "active" if str(fleet.get("stage", "")).startswith("digest") else "ready" if "digest_r1.bin" in by_name and "digest_r2.bin" in by_name else "pending",
            "detail": "round indices resolved" if "digest_r1_import.json" in by_name and "digest_r2_import.json" in by_name else "Export round 1 / round 2 digests",
        },
        {
            "key": "assemble",
            "label": "Assemble",
            "status": "complete" if "qsb_solution.json" in by_name or "qsb_raw_tx.hex" in by_name else "ready" if "digest_r1_import.json" in by_name and "digest_r2_import.json" in by_name else "pending",
            "detail": "final spend built" if "qsb_raw_tx.hex" in by_name else "Build the spend and inspect the tx",
        },
    ]
    return {
        "funding_mode": state.get("funding_mode"),
        "script_size": len(bytes.fromhex(state["full_script_hex"])) if state.get("full_script_hex") else None,
        "config": state.get("config"),
        "benchmark_hours": benchmark.get("estimated_total_hours"),
        "benchmark_cost_usd": benchmark.get("estimated_cost_usd"),
        "constraints": build_constraints_summary(state, benchmark),
        "architecture": build_architecture_summary(),
        "frontier": build_frontier_summary(state, benchmark),
        "lineage": build_lineage_summary(),
        "landscape": build_landscape_summary(),
        "research_status": build_research_status_summary(),
        "fleet": summarize_fleet(fleet) if fleet else None,
        "binding": binding,
        "stages": stages,
    }


def workspace_snapshot(session_id: str) -> dict[str, Any]:
    sync_workspace_artifacts(session_id)
    sync_binding_report_artifacts(session_id)
    sync_frontier_report_artifacts(session_id)
    session_dir = SESSIONS_DIR / session_id
    meta_path = session_dir / "session.json"
    meta = read_json(meta_path) if meta_path.exists() else {}
    artifacts = []
    for name in sorted(KNOWN_ARTIFACTS):
        path = session_dir / name
        if path.exists():
            artifacts.append(artifact_snapshot(path))
    overview = build_workspace_overview(artifacts)
    return {
        "id": session_id,
        "label": meta.get("label", session_id),
        "created_at": meta.get("created_at"),
        "updated_at": meta.get("updated_at"),
        "workspace": str(session_dir),
        "artifacts": artifacts,
        "overview": overview,
    }


def list_sessions() -> list[dict[str, Any]]:
    if not SESSIONS_DIR.exists():
        return []
    sessions = []
    for path in sorted(SESSIONS_DIR.iterdir(), key=lambda item: item.stat().st_mtime, reverse=True):
        if not path.is_dir():
            continue
        sessions.append(workspace_snapshot(path.name))
    return sessions


def ensure_session(label: str | None = None) -> dict[str, Any]:
    safe = slugify(label or "qsb-session")
    suffix = datetime.now().strftime("%Y%m%d-%H%M%S")
    session_id = f"{safe}-{suffix}"
    session_dir = SESSIONS_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=False)
    meta = {
        "id": session_id,
        "label": label or session_id,
        "created_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
    }
    with (session_dir / "session.json").open("w") as handle:
        json.dump(meta, handle, indent=2)
    return workspace_snapshot(session_id)


def clone_session(source_session_id: str, label: str | None = None) -> dict[str, Any]:
    source_dir = SESSIONS_DIR / source_session_id
    if not source_dir.exists():
        raise ValueError("Unknown session")
    source_meta = read_json(source_dir / "session.json")
    clone = ensure_session(label or f"{source_meta.get('label', source_session_id)} copy")
    clone_dir = Path(clone["workspace"])
    for path in source_dir.iterdir():
        if path.name == "session.json":
            continue
        target = clone_dir / path.name
        if path.is_dir():
            shutil.copytree(path, target)
        else:
            shutil.copy2(path, target)
    clone_meta_path = clone_dir / "session.json"
    clone_meta = read_json(clone_meta_path)
    clone_meta["cloned_from"] = source_session_id
    clone_meta["updated_at"] = utc_now_iso()
    with clone_meta_path.open("w") as handle:
        json.dump(clone_meta, handle, indent=2)
    return workspace_snapshot(clone["id"])


def touch_session(session_id: str) -> None:
    meta_path = SESSIONS_DIR / session_id / "session.json"
    if not meta_path.exists():
        return
    meta = read_json(meta_path)
    meta["updated_at"] = utc_now_iso()
    with meta_path.open("w") as handle:
        json.dump(meta, handle, indent=2)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    with path.open("w") as handle:
        json.dump(payload, handle, indent=2)


def maybe_import_hit(session_dir: Path, hit_name: str, import_name: str, round_name: str | None = None) -> bool:
    hit_path = session_dir / hit_name
    import_path = session_dir / import_name
    if not hit_path.exists():
        return False
    if import_path.exists() and import_path.stat().st_mtime >= hit_path.stat().st_mtime:
        return False

    content = hit_path.read_text()
    if round_name is None:
        payload = decode_pinning_hit(content)
        payload["source_name"] = hit_name
    else:
        digest_params_path = session_dir / f"gpu_digest_r{round_name}_params.json"
        if not digest_params_path.exists():
            return False
        payload = decode_digest_hit(content, read_json(digest_params_path), round_name)
        payload["source_name"] = hit_name
    write_json(import_path, payload)
    return True


def sync_workspace_artifacts(session_id: str) -> None:
    session_dir = SESSIONS_DIR / session_id
    changed = False
    changed |= maybe_import_hit(session_dir, "pinning_hit.txt", "pinning_import.json")
    changed |= maybe_import_hit(session_dir, "digest_r1_hit.txt", "digest_r1_import.json", "1")
    changed |= maybe_import_hit(session_dir, "digest_r2_hit.txt", "digest_r2_import.json", "2")
    if changed:
        touch_session(session_id)


def command_artifact_name(command: str, args: dict[str, str]) -> str | None:
    if command == "import-pinning-hit":
        return "pinning_import.json"
    if command == "import-digest-hit":
        round_name = args.get("round", "1")
        return f"digest_r{round_name}_import.json"
    if command in {"vast-pinning-run", "vast-digest-run"}:
        return "qsb_vast_package.json"
    if command == "vast-sync":
        return "qsb_fleet_status.json"
    return None


def parse_hit_pairs(content: str, expected_keys: tuple[str, ...]) -> dict[str, list[str]]:
    parsed = {key: [] for key in expected_keys}
    for line in content.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in parsed:
            parsed[key].append(value.strip())
    return parsed


def decode_pinning_hit(content: str) -> dict[str, Any]:
    parsed = parse_hit_pairs(content, ("sequence", "locktime"))
    if not parsed["sequence"] or not parsed["locktime"]:
        raise ValueError("Pinning hit file must include sequence= and locktime=")
    pairs = []
    for seq, lt in zip(parsed["sequence"], parsed["locktime"]):
        pairs.append({"sequence": int(seq), "locktime": int(lt)})
    selected = pairs[0]
    return {
        "type": "pinning-hit",
        "sequence": selected["sequence"],
        "locktime": selected["locktime"],
        "pairs": pairs,
        "selected": 0,
        "raw": content,
    }


def nth_combination_fixed_first(n_pool: int, t_sel: int, first: int, ordinal: int) -> list[int]:
    if t_sel < 1:
        raise ValueError("t must be positive")
    if not (0 <= first < n_pool):
        raise ValueError("first index out of range")
    if t_sel == 1:
        if ordinal != 0:
            raise ValueError("ordinal out of range")
        return [first]
    remaining = n_pool - first - 1
    pick = t_sel - 1
    total = math.comb(remaining, pick)
    if ordinal < 0 or ordinal >= total:
        raise ValueError("ordinal out of range for first index")
    combo = [first]
    next_value = first + 1
    for slot in range(pick):
        for candidate in range(next_value, n_pool):
            count = math.comb(n_pool - candidate - 1, pick - slot - 1)
            if ordinal < count:
                combo.append(candidate)
                next_value = candidate + 1
                break
            ordinal -= count
    return combo


def decode_digest_hit(content: str, digest_params: dict[str, Any], round_name: str) -> dict[str, Any]:
    parsed = parse_hit_pairs(content, ("first", "first_offset", "batch_idx"))
    if not parsed["first"] or not parsed["first_offset"] or not parsed["batch_idx"]:
        raise ValueError("Digest hit file must include first=, first_offset=, and batch_idx=")
    first = int(parsed["first"][0])
    first_offset = int(parsed["first_offset"][0])
    n_pool = int(digest_params["n"])
    t_sel = int(digest_params["t"])
    resolved = []
    for idx_text in parsed["batch_idx"]:
        batch_idx = int(idx_text)
        ordinal = first_offset + batch_idx
        resolved.append(
            {
                "batch_idx": batch_idx,
                "ordinal": ordinal,
                "indices": nth_combination_fixed_first(n_pool, t_sel, first, ordinal),
            }
        )
    return {
        "type": "digest-hit",
        "round": round_name,
        "first": first,
        "first_offset": first_offset,
        "selected": 0,
        "selected_indices": resolved[0]["indices"],
        "candidates": resolved,
        "raw": content,
    }


def build_qsb_package(session_dir: Path, params_name: str, mode: str) -> dict[str, Any]:
    params_path = session_dir / params_name
    if not params_path.exists():
        raise ValueError(f"Missing params file in session: {params_name}")
    zip_path = session_dir / "qsb.zip"
    if zip_path.exists():
        zip_path.unlink()

    included = 0
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in PACKAGE_INCLUDE:
            source = REPO_DIR / entry
            if source.is_dir():
                for path in source.rglob("*"):
                    if path.is_dir():
                        continue
                    rel = path.relative_to(REPO_DIR)
                    archive.write(path, rel.as_posix())
                    included += 1
            else:
                archive.write(source, source.name)
                included += 1
        archive.write(params_path, params_name)
        included += 1

    payload = {
        "type": "vast-package",
        "mode": mode,
        "params_name": params_name,
        "zip_name": zip_path.name,
        "size_bytes": zip_path.stat().st_size,
        "included_files": included,
        "created_at": utc_now_iso(),
    }
    write_json(session_dir / "qsb_vast_package.json", payload)
    return payload


def has_binary(name: str) -> bool:
    return shutil.which(name) is not None


def vast_api_key_present() -> bool:
    if os.environ.get("VASTAI_API_KEY"):
        return True
    config_path = Path.home() / ".config" / "vastai" / "vast_api_key"
    return config_path.exists() and bool(config_path.read_text().strip())


def build_command(command: str, args: dict[str, str]) -> list[str]:
    if command in INTERNAL_COMMANDS:
        return [command]

    if command == "setup":
        argv = [PYTHON_BIN, "-u", str(PIPELINE_SCRIPT), "setup"]
        if args.get("config"):
            argv.extend(["--config", args["config"]])
        if args.get("seed"):
            argv.extend(["--seed", args["seed"]])
        if args.get("funding_mode"):
            argv.extend(["--funding-mode", args["funding_mode"]])
        return argv

    if command == "export":
        required = ("funding_txid", "funding_vout", "funding_value", "dest_address")
        argv = [PYTHON_BIN, "-u", str(PIPELINE_SCRIPT), "export"]
        for key in required:
            argv.extend([f"--{key.replace('_', '-')}", args[key]])
        if args.get("helper_txid"):
            argv.extend(["--helper-txid", args["helper_txid"]])
        if args.get("helper_vout") is not None:
            argv.extend(["--helper-vout", args["helper_vout"]])
        return argv

    if command == "export-digest":
        required = ("sequence", "locktime", "funding_txid", "funding_vout", "funding_value", "dest_address")
        argv = [PYTHON_BIN, "-u", str(PIPELINE_SCRIPT), "export-digest"]
        for key in required:
            argv.extend([f"--{key.replace('_', '-')}", args[key]])
        if args.get("helper_txid"):
            argv.extend(["--helper-txid", args["helper_txid"]])
        if args.get("helper_vout") is not None:
            argv.extend(["--helper-vout", args["helper_vout"]])
        return argv

    if command == "assemble":
        required = (
            "sequence",
            "locktime",
            "round1",
            "round2",
            "funding_txid",
            "funding_vout",
            "funding_value",
            "dest_address",
        )
        argv = [PYTHON_BIN, "-u", str(PIPELINE_SCRIPT), "assemble"]
        for key in required:
            argv.extend([f"--{key.replace('_', '-')}", args[key]])
        if args.get("helper_txid"):
            argv.extend(["--helper-txid", args["helper_txid"]])
        if args.get("helper_vout") is not None:
            argv.extend(["--helper-vout", args["helper_vout"]])
        if args.get("helper_script_sig_hex"):
            argv.extend(["--helper-script-sig-hex", args["helper_script_sig_hex"]])
        return argv

    if command == "test":
        return [PYTHON_BIN, "-u", str(PIPELINE_SCRIPT), "test"]

    if command == "benchmark":
        argv = [PYTHON_BIN, "-u", str(BENCHMARK_SCRIPT)]
        if args.get("bench_only") == "true":
            argv.append("--bench-only")
        if args.get("test_only") == "true":
            argv.append("--test-only")
        return argv

    raise ValueError(f"Unknown command: {command}")


def prepare_vast_command(session_id: str, command: str, args: dict[str, str]) -> tuple[list[str], dict[str, str], dict[str, Any]]:
    session_dir = SESSIONS_DIR / session_id
    if not has_binary("vastai"):
        raise ValueError("`vastai` CLI is not installed or not on PATH")
    if not vast_api_key_present():
        raise ValueError("VASTAI_API_KEY is not set and ~/.config/vastai/vast_api_key was not found")
    if command == "vast-cleanup":
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        return [
            PYTHON_BIN,
            "-u",
            str(QSB_RUN_SCRIPT),
            "cleanup",
            "--state-file",
            "qsb_fleet_state.json",
            "--status-file",
            "qsb_fleet_status.json",
        ], env, {}
    if command == "vast-sync":
        if not (session_dir / "qsb_fleet_state.json").exists():
            raise ValueError("No active fleet state found in this session")
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        argv = [
            PYTHON_BIN,
            "-u",
            str(QSB_RUN_SCRIPT),
            "sync",
            "--state-file",
            "qsb_fleet_state.json",
            "--status-file",
            "qsb_fleet_status.json",
            "--cleanup-on-hit",
        ]
        return argv, env, {}

    if command == "vast-pinning-run":
        params_name = "pinning.bin"
        mode = "pinning"
    elif command == "vast-digest-run":
        round_name = args.get("round", "1")
        params_name = f"digest_r{round_name}.bin"
        mode = "digest"
    else:
        raise ValueError(f"Unsupported Vast command: {command}")

    package_info = build_qsb_package(session_dir, params_name, mode)
    argv = [
        PYTHON_BIN,
        "-u",
        str(QSB_RUN_SCRIPT),
        "run",
        "--mode",
        mode,
        "--params",
        params_name,
        "--gpus",
        args.get("gpus", "64"),
        "--max-price",
        args.get("max_price", "6.0"),
        "--budget",
        args.get("budget", "200"),
        "--max-machines",
        args.get("max_machines", "20"),
        "--state-file",
        "qsb_fleet_state.json",
        "--status-file",
        "qsb_fleet_status.json",
    ]
    if args.get("easy") == "true":
        argv.append("--easy")
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["QSB_ZIP"] = str(session_dir / "qsb.zip")
    return argv, env, package_info


def execute_internal_command(session_id: str, command: str, args: dict[str, str]) -> dict[str, Any]:
    session_dir = SESSIONS_DIR / session_id
    if command == "import-pinning-hit":
        payload = decode_pinning_hit(args["content"])
        payload["source_name"] = args.get("source_name", "pinning_hit.txt")
        write_json(session_dir / "pinning_import.json", payload)
        return payload

    if command == "import-digest-hit":
        round_name = args.get("round", "1")
        digest_params_path = session_dir / f"gpu_digest_r{round_name}_params.json"
        if not digest_params_path.exists():
            raise ValueError(f"Missing digest params for round {round_name}: {digest_params_path.name}")
        payload = decode_digest_hit(args["content"], read_json(digest_params_path), round_name)
        payload["source_name"] = args.get("source_name", f"digest_r{round_name}_hit.txt")
        write_json(session_dir / f"digest_r{round_name}_import.json", payload)
        return payload

    raise ValueError(f"Unknown internal command: {command}")


@dataclass
class Task:
    id: str
    session_id: str
    command: str
    args: dict[str, str]
    status: str = "queued"
    created_at: str = field(default_factory=utc_now_iso)
    started_at: str | None = None
    finished_at: str | None = None
    exit_code: int | None = None
    logs: list[str] = field(default_factory=list)
    error: str | None = None
    argv: list[str] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "command": self.command,
            "args": self.args,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "logs": self.logs[-500:],
            "error": self.error,
            "argv": self.argv,
        }


TASKS: dict[str, Task] = {}
TASK_LOCK = threading.Lock()


def register_task(session_id: str, command: str, args: dict[str, str]) -> Task:
    task_id = f"{command}-{int(time.time() * 1000)}"
    task = Task(id=task_id, session_id=session_id, command=command, args=args)
    with TASK_LOCK:
        TASKS[task_id] = task
    return task


def session_tasks(session_id: str) -> list[dict[str, Any]]:
    with TASK_LOCK:
        tasks = [task.snapshot() for task in TASKS.values() if task.session_id == session_id]
    return sorted(tasks, key=lambda item: item["created_at"], reverse=True)


def run_task(task: Task) -> None:
    session_dir = SESSIONS_DIR / task.session_id
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    try:
        task.status = "running"
        task.started_at = utc_now_iso()
        touch_session(task.session_id)
        if task.command in {"import-pinning-hit", "import-digest-hit"}:
            result = execute_internal_command(task.session_id, task.command, task.args)
            task.logs.append(json.dumps(result, indent=2))
            task.exit_code = 0
            task.status = "completed"
        else:
            if task.command.startswith("vast-"):
                task.argv, env, package_info = prepare_vast_command(task.session_id, task.command, task.args)
                task.logs.append(f"Prepared {package_info['zip_name']} ({package_info['size_bytes']} bytes)")
            else:
                task.argv = build_command(task.command, task.args)
            process = subprocess.Popen(
                task.argv,
                cwd=session_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )
            assert process.stdout is not None
            for line in process.stdout:
                task.logs.append(line.rstrip())
            process.wait()
            task.exit_code = process.returncode
            task.status = "completed" if process.returncode == 0 else "failed"
    except Exception as exc:  # pragma: no cover - defensive
        task.status = "failed"
        if isinstance(exc, ValueError):
            task.error = str(exc)
            task.logs.append(task.error)
        else:
            task.error = f"{exc}\n{traceback.format_exc()}"
            task.logs.append(task.error)
    finally:
        sync_workspace_artifacts(task.session_id)
        task.finished_at = utc_now_iso()
        touch_session(task.session_id)


def spawn_task(session_id: str, command: str, args: dict[str, str]) -> Task:
    task = register_task(session_id, command, args)
    thread = threading.Thread(target=run_task, args=(task,), daemon=True)
    thread.start()
    return task


def parse_json_body(handler: SimpleHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length else b"{}"
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


class StudioHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, message: str, status: int = 400) -> None:
        self._json({"error": message}, status=status)

    def _send_file(self, path: Path) -> None:
        if not path.exists():
            self._error("Artifact not found", 404)
            return
        mime, _ = mimetypes.guess_type(path.name)
        payload = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/overview":
            self._json(
                {
                    "repo_dir": str(REPO_DIR),
                    "python": PYTHON_BIN,
                    "vastai_installed": has_binary("vastai"),
                    "vast_api_key_present": vast_api_key_present(),
                    "sessions": list_sessions(),
                }
            )
            return

        if parsed.path == "/api/sessions":
            self._json({"sessions": list_sessions()})
            return

        if parsed.path.startswith("/api/sessions/"):
            parts = parsed.path.strip("/").split("/")
            session_id = parts[2]
            session_dir = SESSIONS_DIR / session_id
            if not session_dir.exists():
                self._error("Unknown session", 404)
                return
            if len(parts) == 5 and parts[3] == "artifacts":
                artifact_name = parts[4]
                if artifact_name not in KNOWN_ARTIFACTS:
                    self._error("Unknown artifact", 404)
                    return
                self._send_file(session_dir / artifact_name)
                return
            snapshot = workspace_snapshot(session_id)
            snapshot["tasks"] = session_tasks(session_id)
            self._json(snapshot)
            return

        if parsed.path.startswith("/api/tasks/"):
            task_id = parsed.path.split("/")[3]
            with TASK_LOCK:
                task = TASKS.get(task_id)
            if task is None:
                self._error("Unknown task", 404)
                return
            payload = task.snapshot()
            payload["session"] = workspace_snapshot(task.session_id)
            self._json(payload)
            return

        if parsed.path == "/" or parsed.path == "":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            payload = parse_json_body(self)
        except json.JSONDecodeError:
            self._error("Invalid JSON", 400)
            return

        if parsed.path == "/api/sessions":
            session = ensure_session(payload.get("label"))
            self._json(session, status=201)
            return

        if parsed.path.startswith("/api/sessions/") and parsed.path.endswith("/clone"):
            parts = parsed.path.strip("/").split("/")
            if len(parts) != 4:
                self._error("Bad session clone path", 404)
                return
            session_id = parts[2]
            try:
                session = clone_session(session_id, payload.get("label"))
            except ValueError as exc:
                self._error(str(exc), 404)
                return
            self._json(session, status=201)
            return

        if parsed.path.startswith("/api/sessions/") and parsed.path.endswith("/commands"):
            parts = parsed.path.strip("/").split("/")
            if len(parts) != 4:
                self._error("Bad command route", 404)
                return
            session_id = parts[2]
            if not (SESSIONS_DIR / session_id).exists():
                self._error("Unknown session", 404)
                return
            command = payload.get("command")
            if not isinstance(command, str):
                self._error("Missing command")
                return
            args = decode_args(payload.get("args"))
            try:
                build_command(command, args)
            except KeyError as exc:
                self._error(f"Missing argument: {exc.args[0]}")
                return
            except ValueError as exc:
                self._error(str(exc))
                return
            task = spawn_task(session_id, command, args)
            self._json(task.snapshot(), status=202)
            return

        self._error("Unknown route", 404)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


def print_banner(port: int) -> None:
    print("╔══════════════════════════════════════════════════════════╗")
    print("║                   QSB Studio                            ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║  Repo:   {str(REPO_DIR)[:49]:49} ║")
    print(f"║  Python: {PYTHON_BIN[:49]:49} ║")
    print(f"║  URL:    http://127.0.0.1:{port:<34}║")
    print("╚══════════════════════════════════════════════════════════╝")


def main() -> None:
    port = int(os.environ.get("QSB_STUDIO_PORT", "8421"))
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    mimetypes.add_type("application/javascript", ".js")
    server = ThreadingHTTPServer(("127.0.0.1", port), StudioHandler)
    print_banner(port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down QSB Studio.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
