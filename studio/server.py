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
PIPELINE_SCRIPT = REPO_DIR / "pipeline" / "qsb_pipeline.py"
BENCHMARK_SCRIPT = REPO_DIR / "pipeline" / "benchmark.py"
QSB_RUN_SCRIPT = REPO_DIR / "pipeline" / "qsb_run.py"
LAUNCH_MULTI_GPU_SCRIPT = REPO_DIR / "gpu" / "launch_multi_gpu.sh"
VENV_PYTHON = REPO_DIR / ".venv" / "bin" / "python"
PYTHON_BIN = str(VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable))

ARTIFACT_TEXT = {
    "qsb_raw_tx.hex",
    "pinning_hit.txt",
    "digest_r1_hit.txt",
    "digest_r2_hit.txt",
    "pinning_result.txt",
    "digest_result.txt",
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
        "fleet": summarize_fleet(fleet) if fleet else None,
        "stages": stages,
    }


def workspace_snapshot(session_id: str) -> dict[str, Any]:
    sync_workspace_artifacts(session_id)
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
