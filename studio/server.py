#!/usr/bin/env python3
"""Local-first operator UI for the QSB pipeline."""

from __future__ import annotations

import json
import mimetypes
import os
import re
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
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
VENV_PYTHON = REPO_DIR / ".venv" / "bin" / "python"
PYTHON_BIN = str(VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable))

ARTIFACT_TEXT = {
    "qsb_raw_tx.hex",
}

ARTIFACT_JSON = {
    "qsb_state.json",
    "gpu_pinning_params.json",
    "gpu_digest_r1_params.json",
    "gpu_digest_r2_params.json",
    "qsb_solution.json",
    "benchmark_results.json",
}

ARTIFACT_BINARY = {
    "pinning.bin",
    "digest_r1.bin",
    "digest_r2.bin",
}

KNOWN_ARTIFACTS = ARTIFACT_JSON | ARTIFACT_TEXT | ARTIFACT_BINARY


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


def workspace_snapshot(session_id: str) -> dict[str, Any]:
    session_dir = SESSIONS_DIR / session_id
    meta_path = session_dir / "session.json"
    meta = read_json(meta_path) if meta_path.exists() else {}
    artifacts = []
    for name in sorted(KNOWN_ARTIFACTS):
        path = session_dir / name
        if path.exists():
            artifacts.append(artifact_snapshot(path))
    return {
        "id": session_id,
        "label": meta.get("label", session_id),
        "created_at": meta.get("created_at"),
        "updated_at": meta.get("updated_at"),
        "workspace": str(session_dir),
        "artifacts": artifacts,
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


def touch_session(session_id: str) -> None:
    meta_path = SESSIONS_DIR / session_id / "session.json"
    if not meta_path.exists():
        return
    meta = read_json(meta_path)
    meta["updated_at"] = utc_now_iso()
    with meta_path.open("w") as handle:
        json.dump(meta, handle, indent=2)


def build_command(command: str, args: dict[str, str]) -> list[str]:
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
        task.argv = build_command(task.command, task.args)
        task.status = "running"
        task.started_at = utc_now_iso()
        touch_session(task.session_id)
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
        task.error = f"{exc}\n{traceback.format_exc()}"
        task.logs.append(task.error)
    finally:
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

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/overview":
            self._json(
                {
                    "repo_dir": str(REPO_DIR),
                    "python": PYTHON_BIN,
                    "sessions": list_sessions(),
                }
            )
            return

        if parsed.path == "/api/sessions":
            self._json({"sessions": list_sessions()})
            return

        if parsed.path.startswith("/api/sessions/"):
            session_id = parsed.path.split("/")[3]
            session_dir = SESSIONS_DIR / session_id
            if not session_dir.exists():
                self._error("Unknown session", 404)
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
