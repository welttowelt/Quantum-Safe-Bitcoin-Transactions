#!/usr/bin/env python3
"""
qsb_run.py — One-command QSB search across vast.ai fleet

Setup (once):
  pip install vastai
  # Get your API key from https://cloud.vast.ai/account/
  export VASTAI_API_KEY="your_key_here"

Usage:
  python3 qsb_run.py run --mode pinning --gpus 64 --budget 200
  python3 qsb_run.py run --mode digest --params digest_r1.bin --gpus 64 --budget 200
  python3 qsb_run.py sync --cleanup-on-hit
  python3 qsb_run.py cleanup

It will:
  1. Find cheapest multi-GPU machines on vast.ai
  2. Rent them
  3. Upload code and build
  4. Start the requested search stage on all GPUs
  5. Monitor for hits (prints live progress)
  6. Download results and destroy all instances when done
"""

import os
import sys
import json
import time
import subprocess
import argparse
import threading
from pathlib import Path
import struct

API_KEY = os.environ.get("VASTAI_API_KEY", "")
if not API_KEY:
    # Try reading from vastai CLI config
    config_path = os.path.expanduser("~/.config/vastai/vast_api_key")
    if os.path.exists(config_path):
        API_KEY = open(config_path).read().strip()
API_URL = "https://console.vast.ai/api/v0"
QSB_ZIP = os.environ.get("QSB_ZIP", "") or None  # Set path to qsb.zip, or auto-detect
DEFAULT_STATE_FILE = "qsb_fleet_state.json"
DEFAULT_STATUS_FILE = "qsb_fleet_status.json"

# ============================================================
# vast.ai API helpers
# ============================================================

def api_request(method, endpoint, data=None):
    """Make vast.ai API request."""
    import urllib.request
    url = f"{API_URL}/{endpoint}?api_key={API_KEY}"
    headers = {"Content-Type": "application/json"}
    
    if data:
        req = urllib.request.Request(url, json.dumps(data).encode(), headers, method=method)
    else:
        req = urllib.request.Request(url, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  API error: {e}")
        return None


def write_json(path, payload):
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as handle:
        json.dump(payload, handle, indent=2)
    os.replace(tmp_path, path)


def stage_name(mode, params_name):
    base = os.path.splitext(os.path.basename(params_name))[0]
    if mode == "pinning":
        return "pinning"
    if base == "digest_r1":
        return "digest-r1"
    if base == "digest_r2":
        return "digest-r2"
    return "digest"


def hit_output_name(mode, params_name):
    if mode == "pinning":
        return "pinning_hit.txt"
    base = os.path.splitext(os.path.basename(params_name))[0]
    if base in {"digest_r1", "digest_r2"}:
        return f"{base}_hit.txt"
    return "digest_hit.txt"


def parse_rate(progress_text):
    if not progress_text or "M/s" not in progress_text:
        return None
    try:
        return progress_text.split("M/s")[0].split(",")[-1].strip() + "M/s"
    except Exception:
        return None

def search_offers(min_gpus=8, max_price=10.0):
    """Find available GPU machines, sorted by best value for integer workloads."""
    query = f"num_gpus>={min_gpus} dph_total<={max_price} cuda_max_good>=12.0 reliability>0.95 verified=true rentable=true"
    cmd = ["vastai", "search", "offers", "--raw", "-o", "dph_total", query]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  Error: {result.stderr}")
        return []
    
    try:
        offers = json.loads(result.stdout)
    except:
        print("Failed to parse offers")
        return []
    
    # Estimated pinning rate (M/s) by GPU model based on SM count
    # Our workload is pure integer — scales linearly with SMs
    GPU_RATES = {
        'RTX PRO 6000': 238,   # 188 SMs, measured
        'RTX 5090': 215,       # 170 SMs
        'RTX 4090': 170,       # 128 SMs
        'RTX 4080': 130,       # 76 SMs
        'RTX 4070': 88,        # 56 SMs, measured
        'RTX 3090': 85,        # 82 SMs (older arch, ~same as 4070S)
        'H100': 170,           # 132 SMs (overkill for us)
        'H200': 180,           # 132 SMs + faster
        'A100': 130,           # 108 SMs
        'A6000': 100,          # 84 SMs
        'L40': 140,            # 142 SMs
        'L40S': 140,           # 142 SMs
    }
    
    good = []
    for o in offers:
        gpus = o.get('num_gpus', 0)
        price = o.get('dph_total', 999)
        cuda = o.get('cuda_max_good', 0)
        reliability = o.get('reliability2', 0)
        gpu_name = o.get('gpu_name', '')
        
        if (gpus < min_gpus or price > max_price or 
            cuda < 12.0 or reliability < 0.95):
            continue
        
        # Estimate rate for this machine
        rate_per_gpu = 100  # default conservative estimate
        for model, rate in GPU_RATES.items():
            if model.lower() in gpu_name.lower():
                rate_per_gpu = rate
                break
        
        total_rate = rate_per_gpu * gpus  # M/s for whole machine
        # Cost to search 2^46.4 candidates (in dollars)
        target = 9.3e13  # 2^46.4
        hours_needed = target / (total_rate * 1e6) / 3600
        total_cost = hours_needed * price
        
        o['_est_rate'] = total_rate
        o['_est_hours'] = hours_needed
        o['_est_cost'] = total_cost
        o['_rate_per_gpu'] = rate_per_gpu
        good.append(o)
    
    # Sort by estimated total cost (best value first)
    good.sort(key=lambda o: o['_est_cost'])
    return good

def create_instance(offer_id, image="nvidia/cuda:12.4.0-devel-ubuntu22.04", disk=20):
    """Rent a machine."""
    cmd = f"vastai create instance {offer_id} --image {image} --disk {disk} --raw"
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    if result.returncode != 0:
        return None
    try:
        data = json.loads(result.stdout)
        return data.get('new_contract')
    except:
        return None

def get_instance_info(instance_id):
    """Get instance details."""
    cmd = f"vastai show instance {instance_id} --raw"
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except:
        return None

def get_ssh_url(instance_id):
    """Get SSH connection details."""
    cmd = f"vastai ssh-url {instance_id}"
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return result.stdout.strip()

def destroy_instance(instance_id):
    """Destroy an instance."""
    cmd = f"vastai destroy instance {instance_id}"
    subprocess.run(cmd.split(), capture_output=True)

def ssh_exec(instance_id, command, timeout=600):
    """Execute command on instance via SSH."""
    # Get SSH URL (format: ssh://root@ssh8.vast.ai:20466)
    cmd = f"vastai ssh-url {instance_id}"
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    if result.returncode != 0:
        return f"ssh-url failed: {result.stderr}", 1
    
    ssh_url = result.stdout.strip()
    # Parse ssh://user@host:port
    url = ssh_url.replace("ssh://", "")
    if ":" in url:
        user_host, port = url.rsplit(":", 1)
    else:
        user_host, port = url, "22"
    
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=30",
               "-p", port, user_host, command]
    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "timeout", 1
    except Exception as e:
        return str(e), 1

def scp_to(instance_id, local_path, remote_path):
    """Copy file to instance using vastai copy."""
    cmd = ["vastai", "copy", local_path, f"{instance_id}:{remote_path}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.returncode == 0
    except:
        return False

# ============================================================
# Fleet management
# ============================================================

def find_qsb_zip():
    """Find qsb.zip in common locations."""
    candidates = [
        "qsb.zip",
        "./qsb.zip",
        "../qsb.zip",
        os.path.expanduser("~/Downloads/qsb.zip"),
        os.path.expanduser("~/Desktop/qsb.zip"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None

def deploy_and_start(instance_id, machine_id, zip_path, mode, launch_args):
    """Deploy code and start search on one machine."""
    tag = f"[M{machine_id}]"
    
    # Wait for instance to be running
    print(f"  {tag} Waiting for instance {instance_id} to boot...")
    for attempt in range(60):
        info = get_instance_info(instance_id)
        if info and info.get('actual_status') == 'running':
            break
        if info and info.get('actual_status') == 'error':
            print(f"  {tag} Instance failed!")
            return False
        time.sleep(10)
    else:
        print(f"  {tag} Timeout waiting for boot")
        return False
    
    n_gpus = info.get('num_gpus', '?')
    gpu_name = info.get('gpu_name', '?')
    print(f"  {tag} Running: {n_gpus}× {gpu_name}")
    
    # Upload code
    print(f"  {tag} Uploading qsb.zip...")
    if not scp_to(instance_id, zip_path, "/workspace/qsb.zip"):
        print(f"  {tag} Upload failed, retrying...")
        time.sleep(10)
        if not scp_to(instance_id, zip_path, "/workspace/qsb.zip"):
            print(f"  {tag} Upload failed!")
            return False
    
    # Build and start
    print(f"  {tag} Building and starting search...")
    if mode == "pinning":
        start_search_cmd = f"./run_pinning.sh {launch_args['machine_slot']}"
    elif mode == "digest":
        start_search_cmd = (
            f"./launch_multi_gpu.sh digest ../{launch_args['params_name']} "
            f"{launch_args['easy_flag']} {launch_args['first_start']} {launch_args['first_end']}"
        ).strip()
    else:
        print(f"  {tag} Unknown mode: {mode}")
        return False

    setup_cmd = (
        "cd / && rm -rf qsb && unzip -o /workspace/qsb.zip && "
        f"test -f /qsb/{launch_args['params_name']} && "
        "cd /qsb/gpu && "
        "apt-get install -y -qq libssl-dev 2>/dev/null && "
        "make clean && make >/tmp/qsb_build.log 2>&1 && tail -1 /tmp/qsb_build.log && "
        "chmod +x run_pinning.sh launch_multi_gpu.sh && mkdir -p results && "
        f"nohup bash -c 'cd /qsb/gpu && {start_search_cmd}' "
        "> /workspace/qsb_output.log 2>&1 &"
    )
    
    out, rc = ssh_exec(instance_id, setup_cmd, timeout=600)
    if rc != 0:
        print(f"  {tag} Setup failed: {out[:200]}")
        return False
    
    print(f"  {tag} Search started!")
    return True

def check_for_hit(instance_id, machine_id, mode):
    """Check if this machine found a hit."""
    hit_name = "pinning_hit.txt" if mode == "pinning" else "digest_hit.txt"
    marker = "sequence=" if mode == "pinning" else "first="
    out, rc = ssh_exec(instance_id, 
        f"cat /qsb/gpu/results/{hit_name} 2>/dev/null || echo __NOHIT__",
        timeout=30)
    if "__NOHIT__" not in out and marker in out:
        return out.strip()
    return None

def get_progress(instance_id, machine_id, mode):
    """Get search progress from one machine."""
    pattern = "log_m*_gpu0.txt" if mode == "pinning" else "log_dig_gpu0.txt"
    out, rc = ssh_exec(instance_id,
        f"tail -1 /qsb/gpu/results/{pattern} 2>/dev/null || echo 'starting...'",
        timeout=15)
    return out.strip()


def load_digest_span(params_path):
    """Return the total number of first-index choices for a digest params file."""
    with open(params_path, "rb") as handle:
        n = struct.unpack("<I", handle.read(4))[0]
        t = struct.unpack("<I", handle.read(4))[0]
    return n, t, n - t + 1


def assign_digest_ranges(instances, params_name):
    """Assign first-index ranges across machines proportional to GPU count."""
    params_path = Path(params_name)
    n, t, span = load_digest_span(params_path)
    total_gpus = sum(offer["num_gpus"] for _, _, offer in instances)
    assignments = []
    cursor = 0
    accumulated = 0
    for idx, (_, mid, offer) in enumerate(instances):
        accumulated += offer["num_gpus"]
        if idx == len(instances) - 1:
            end = span
        else:
            end = (span * accumulated) // total_gpus
        if end < cursor:
            end = cursor
        assignments.append(
            {
                "machine_id": mid,
                "first_start": cursor,
                "first_end": end,
                "n": n,
                "t": t,
            }
        )
        cursor = end
    return assignments


def normalize_instances(state):
    normalized = []
    for item in state.get("instances", []):
        if isinstance(item, dict):
            normalized.append(item)
        else:
            instance_id, machine_id = item
            normalized.append(
                {
                    "instance_id": instance_id,
                    "machine_id": machine_id,
                }
            )
    return normalized


def collect_fleet_status(state):
    mode = state["mode"]
    params_name = state["params_name"]
    instances = normalize_instances(state)
    elapsed_h = max(0.0, (time.time() - state.get("started", time.time())) / 3600.0)
    fleet_hourly = float(state.get("selected_hourly", 0.0))
    cost_so_far = elapsed_h * fleet_hourly
    hit = None
    statuses = []
    for item in instances:
        iid = item["instance_id"]
        mid = item["machine_id"]
        progress = get_progress(iid, mid, mode)
        remote_hit = check_for_hit(iid, mid, mode)
        status = "running"
        if remote_hit:
            status = "hit"
        elif progress == "starting...":
            status = "starting"
        statuses.append(
            {
                "instance_id": iid,
                "machine_id": mid,
                "gpu_name": item.get("gpu_name"),
                "num_gpus": item.get("num_gpus"),
                "hourly_price": item.get("hourly_price"),
                "first_start": item.get("first_start"),
                "first_end": item.get("first_end"),
                "status": status,
                "progress": progress,
                "rate": parse_rate(progress),
            }
        )
        if remote_hit and hit is None:
            hit = {
                "machine_id": mid,
                "instance_id": iid,
                "content": remote_hit,
                "output_name": hit_output_name(mode, params_name),
            }
    return {
        "mode": mode,
        "stage": stage_name(mode, params_name),
        "params_name": params_name,
        "phase": "hit" if hit else "monitoring",
        "started": state.get("started"),
        "elapsed_hours": elapsed_h,
        "budget": state.get("budget"),
        "cost_so_far": cost_so_far,
        "fleet_hourly": fleet_hourly,
        "fleet_rate_est_mhs": state.get("selected_rate_mhs"),
        "active_instances": len(instances),
        "instances": statuses,
        "hit": hit,
        "updated_at": time.time(),
    }


def save_status(status_file, payload):
    write_json(status_file, payload)


def write_local_hit(state, status_payload):
    hit = status_payload.get("hit")
    if not hit:
        return None
    output_name = hit["output_name"]
    with open(output_name, "w") as handle:
        handle.write(hit["content"])
    if state["mode"] == "digest":
        with open("digest_result.txt", "w") as handle:
            handle.write(hit["content"])
    else:
        with open("pinning_result.txt", "w") as handle:
            handle.write(hit["content"])
    status_payload["hit_file"] = output_name
    return output_name

# ============================================================
# Main orchestration
# ============================================================

def run_fleet(mode, params_name, target_gpus, max_price, budget, max_machines, easy, state_file, status_file):
    if not API_KEY:
        print("ERROR: Set VASTAI_API_KEY environment variable")
        print("  export VASTAI_API_KEY='your_key_here'")
        print("  Get your key from: https://cloud.vast.ai/account/")
        sys.exit(1)
    
    zip_path = QSB_ZIP or find_qsb_zip()
    if not zip_path:
        print("ERROR: qsb.zip not found. Place it in current directory.")
        sys.exit(1)
    if not os.path.exists(params_name):
        print(f"ERROR: Params file not found: {params_name}")
        sys.exit(1)
    
    print(f"╔════════════════════════════════════════════╗")
    print(f"║  QSB Fleet — {mode.capitalize():<28}║")
    print(f"╚════════════════════════════════════════════╝")
    print(f"  Target GPUs: {target_gpus}")
    print(f"  Max price: ${max_price}/hr per machine")
    print(f"  Max machines: {max_machines}")
    print(f"  Budget: ${budget}")
    print(f"  Params: {params_name}")
    print(f"  Code: {zip_path}")
    print()
    
    # Step 1: Find offers
    print("  [1/5] Searching for GPU machines...")
    offers = search_offers(min_gpus=4, max_price=max_price)
    if not offers:
        print(f"  No offers found under ${max_price}/hr. Try higher --max-price")
        return
    
    # Greedy selection: pick machines by best cost-efficiency until we reach target GPUs
    selected = []
    total_gpus = 0
    for o in offers:
        if len(selected) >= max_machines:
            break
        if total_gpus >= target_gpus:
            break
        selected.append(o)
        total_gpus += o['num_gpus']
    
    n_machines = len(selected)
    
    total_hourly = sum(o['dph_total'] for o in selected)
    total_rate = sum(o['_est_rate'] for o in selected)
    est_hours = 9.3e13 / (total_rate * 1e6) / 3600
    est_cost = est_hours * total_hourly
    
    print(f"  Found {len(offers)} offers. Selected {n_machines} machines ({total_gpus} GPUs):")
    for i, o in enumerate(selected):
        print(f"    M{i}: {o['num_gpus']}× {o.get('gpu_name','?'):>20s} "
              f"${o['dph_total']:>5.2f}/hr  ~{o['_est_rate']:>5.0f}M/s  "
              f"(est ${o['_est_cost']:.0f} alone)")
    print(f"  Fleet: {total_gpus} GPUs, ${total_hourly:.2f}/hr, ~{total_rate:.0f}M/s")
    print(f"  Expected: {est_hours:.1f}h, ~${est_cost:.0f}")
    if total_gpus < target_gpus:
        print(f"  WARNING: Only {total_gpus}/{target_gpus} GPUs found. "
              f"Try --max-price {max_price*1.5:.1f}")
    print()
    
    # Step 2: Rent machines
    print("  [2/5] Renting machines...")
    instances = []  # (instance_id, machine_id, offer)
    for i, offer in enumerate(selected):
        oid = offer['id']
        price = offer['dph_total']
        gpus = offer['num_gpus']
        gpu_name = offer.get('gpu_name', '?')
        
        print(f"    M{i}: {gpus}× {gpu_name} @ ${price:.2f}/hr ... ", end="", flush=True)
        iid = create_instance(oid)
        if iid:
            instances.append((iid, i, offer))
            print(f"OK (instance {iid})")
        else:
            print(f"FAILED")
    
    if not instances:
        print("  No instances created!")
        return
    
    # Save state for recovery
    assignments = None
    if mode == "digest":
        assignments = {item["machine_id"]: item for item in assign_digest_ranges(instances, params_name)}
        print("  Digest sharding:")
        for item in assignments.values():
            print(
                f"    M{item['machine_id']}: first [{item['first_start']},{item['first_end']}) "
                f"(n={item['n']} t={item['t']})"
            )
        print()

    state = {
        'mode': mode,
        'stage': stage_name(mode, params_name),
        'params_name': params_name,
        'instances': [],
        'started': time.time(),
        'target_gpus': target_gpus,
        'budget': budget,
        'selected_hourly': total_hourly,
        'selected_rate_mhs': total_rate,
        'state_file': state_file,
        'status_file': status_file,
        'easy': easy,
    }
    for iid, mid, offer in instances:
        item = {
            'instance_id': iid,
            'machine_id': mid,
            'gpu_name': offer.get('gpu_name', '?'),
            'num_gpus': offer.get('num_gpus', 0),
            'hourly_price': offer.get('dph_total', 0),
        }
        if mode == "digest" and assignments is not None:
            item.update(assignments[mid])
        state['instances'].append(item)
    write_json(state_file, state)
    save_status(
        status_file,
        {
            'mode': mode,
            'stage': state['stage'],
            'params_name': params_name,
            'phase': 'renting',
            'target_gpus': target_gpus,
            'budget': budget,
            'fleet_hourly': total_hourly,
            'fleet_rate_est_mhs': total_rate,
            'active_instances': len(instances),
            'instances': state['instances'],
            'updated_at': time.time(),
        },
    )
    
    print(f"\n  {len(instances)} machines rented. Deploying...")
    print()
    
    # Step 3: Deploy and start (parallel)
    print("  [3/5] Deploying code and starting search...")
    threads = []
    results = {}
    
    params_base = os.path.basename(params_name)

    def deploy_worker(iid, mid):
        launch_args = {
            "params_name": params_base,
            "easy_flag": "easy" if easy else "",
            "machine_slot": mid,
            "first_start": 0,
            "first_end": 0,
        }
        if mode == "digest":
            launch_args["first_start"] = assignments[mid]["first_start"]
            launch_args["first_end"] = assignments[mid]["first_end"]
            if launch_args["first_start"] >= launch_args["first_end"]:
                print(f"  [M{mid}] Skipping empty digest shard")
                results[mid] = False
                return
        results[mid] = deploy_and_start(iid, mid, zip_path, mode, launch_args)
    
    for iid, mid, _ in instances:
        t = threading.Thread(target=deploy_worker, args=(iid, mid))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join(timeout=700)
    
    active = sum(1 for v in results.values() if v)
    print(f"\n  {active}/{len(instances)} machines active.")
    deploy_status = {
        "mode": mode,
        "stage": state["stage"],
        "params_name": params_name,
        "phase": "running" if active else "deploy_failed",
        "target_gpus": target_gpus,
        "budget": budget,
        "fleet_hourly": total_hourly,
        "fleet_rate_est_mhs": total_rate,
        "active_instances": active,
        "instances": [],
        "updated_at": time.time(),
    }
    for item in state["instances"]:
        deploy_status["instances"].append(
            {
                **item,
                "status": "running" if results.get(item["machine_id"]) else "deploy_failed",
            }
        )
    save_status(status_file, deploy_status)
    
    if active == 0:
        print("  All deployments failed! Cleaning up...")
        for iid, _, _ in instances:
            destroy_instance(iid)
        if os.path.exists(state_file):
            os.remove(state_file)
        return
    
    # Step 4: Monitor
    print()
    print("  [4/5] Monitoring for hits...")
    print("  Press Ctrl+C to stop and destroy all instances")
    print()
    
    start_time = time.time()
    cost_so_far = 0.0
    stop_reason = None
    
    try:
        while True:
            elapsed_h = (time.time() - start_time) / 3600
            cost_so_far = elapsed_h * total_hourly
            
            if cost_so_far > budget:
                print(f"\n  Budget limit (${budget}) reached. Stopping.")
                status_payload = collect_fleet_status(state)
                status_payload["phase"] = "budget_exhausted"
                save_status(status_file, status_payload)
                stop_reason = "budget"
                break

            status_payload = collect_fleet_status(state)
            save_status(status_file, status_payload)
            if status_payload.get("hit"):
                hit = status_payload["hit"]
                print(f"\n  {'='*50}")
                print(f"  HIT FOUND on Machine {hit['machine_id']}!")
                print(f"  {'='*50}")
                print(f"  {hit['content']}")
                print(f"  {'='*50}")
                print(f"  Time: {elapsed_h:.1f}h, Cost: ${cost_so_far:.2f}")

                result_name = write_local_hit(state, status_payload)
                print(f"  Saved to {result_name}")
                save_status(status_file, status_payload)

                print(f"\n  [5/5] Destroying all instances...")
                for iid2, _, _ in instances:
                    destroy_instance(iid2)
                if os.path.exists(state_file):
                    os.remove(state_file)
                status_payload["phase"] = "completed"
                status_payload["active_instances"] = 0
                save_status(status_file, status_payload)
                print(f"  Done!")
                return
            
            # Progress
            print(f"  [{time.strftime('%H:%M:%S')}] "
                  f"{elapsed_h:.1f}h elapsed, ${cost_so_far:.1f} spent  ", end="")
            
            for entry in status_payload["instances"][:4]:
                print(f" M{entry['machine_id']}:{entry.get('rate') or '?'}", end="")
            print()
            
            time.sleep(60)
    
    except KeyboardInterrupt:
        print(f"\n\n  Interrupted! Destroying all instances...")
        for iid, _, _ in instances:
            destroy_instance(iid)
        if os.path.exists(state_file):
            os.remove(state_file)
        interrupted = collect_fleet_status(state)
        interrupted["phase"] = "interrupted"
        interrupted["active_instances"] = 0
        save_status(status_file, interrupted)
        print(f"  All instances destroyed. Cost: ${cost_so_far:.2f}")
        return

    if stop_reason == "budget":
        print(f"\n  [5/5] Destroying all instances after budget stop...")
        for iid, _, _ in instances:
            destroy_instance(iid)
        if os.path.exists(state_file):
            os.remove(state_file)
        final_status = collect_fleet_status(state)
        final_status["phase"] = "budget_exhausted"
        final_status["active_instances"] = 0
        save_status(status_file, final_status)

def sync_fleet(state_file, status_file, cleanup_on_hit=False):
    """Refresh fleet progress, fetch hits, and optionally cleanup when done."""
    if not os.path.exists(state_file):
        print("No fleet state found.")
        return 1

    with open(state_file) as handle:
        state = json.load(handle)

    payload = collect_fleet_status(state)
    save_status(status_file, payload)

    hit = payload.get("hit")
    if hit:
        result_name = write_local_hit(state, payload)
        print(f"HIT FOUND on Machine {hit['machine_id']}")
        print(hit["content"])
        print(f"Saved to {result_name}")
        save_status(status_file, payload)
        if cleanup_on_hit:
            print("Destroying all instances after hit...")
            for item in normalize_instances(state):
                destroy_instance(item["instance_id"])
            if os.path.exists(state_file):
                os.remove(state_file)
            payload["phase"] = "completed"
            payload["active_instances"] = 0
            save_status(status_file, payload)
        return 0

    print(
        f"Fleet {payload['stage']} — {payload['active_instances']} instances · "
        f"{payload['elapsed_hours']:.2f}h · ${payload['cost_so_far']:.2f}"
    )
    for entry in payload["instances"]:
        shard = ""
        if entry.get("first_start") is not None and entry.get("first_end") is not None:
            shard = f" first[{entry['first_start']},{entry['first_end']})"
        print(
            f"  M{entry['machine_id']} {entry.get('gpu_name') or '?'} "
            f"{entry.get('rate') or entry.get('status')}{shard}"
        )
    return 0


def cleanup(state_file=DEFAULT_STATE_FILE, status_file=DEFAULT_STATUS_FILE):
    """Destroy any remaining fleet instances."""
    try:
        with open(state_file) as f:
            state = json.load(f)
    except FileNotFoundError:
        print("No fleet state found.")
        return

    print("Destroying fleet instances...")
    for item in normalize_instances(state):
        iid = item["instance_id"]
        mid = item["machine_id"]
        print(f"  Instance {iid} (M{mid})... ", end="")
        destroy_instance(iid)
        print("destroyed")
    if os.path.exists(state_file):
        os.remove(state_file)
    payload = {
        "mode": state.get("mode"),
        "stage": state.get("stage"),
        "params_name": state.get("params_name"),
        "phase": "cleaned_up",
        "active_instances": 0,
        "updated_at": time.time(),
        "instances": normalize_instances(state),
    }
    save_status(status_file, payload)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='QSB Fleet — One-command GPU search')
    sub = parser.add_subparsers(dest='cmd')
    
    run_p = sub.add_parser('run', help='Launch fleet and search')
    run_p.add_argument('--mode', choices=['pinning', 'digest'], default='pinning',
                       help='Search stage to run')
    run_p.add_argument('--params', default=None,
                       help='Params file to ship inside qsb.zip (defaults: pinning.bin or digest_r1.bin)')
    run_p.add_argument('--gpus', type=int, default=64, help='Target total GPU count')
    run_p.add_argument('--max-price', type=float, default=6.0, help='Max $/hr per machine')
    run_p.add_argument('--budget', type=float, default=200, help='Total budget in $')
    run_p.add_argument('--max-machines', type=int, default=20, help='Max machines to rent')
    run_p.add_argument('--easy', action='store_true', help='Run in easy mode')
    run_p.add_argument('--state-file', default=DEFAULT_STATE_FILE, help='Path to fleet state JSON')
    run_p.add_argument('--status-file', default=DEFAULT_STATUS_FILE, help='Path to fleet status JSON')

    sync_p = sub.add_parser('sync', help='Refresh fleet status and fetch hits')
    sync_p.add_argument('--state-file', default=DEFAULT_STATE_FILE, help='Path to fleet state JSON')
    sync_p.add_argument('--status-file', default=DEFAULT_STATUS_FILE, help='Path to fleet status JSON')
    sync_p.add_argument('--cleanup-on-hit', action='store_true', help='Destroy instances after a hit is fetched')
    
    cleanup_p = sub.add_parser('cleanup', help='Destroy all fleet instances')
    cleanup_p.add_argument('--state-file', default=DEFAULT_STATE_FILE, help='Path to fleet state JSON')
    cleanup_p.add_argument('--status-file', default=DEFAULT_STATUS_FILE, help='Path to fleet status JSON')
    
    args = parser.parse_args()
    
    if args.cmd == 'run':
        default_params = 'pinning.bin' if args.mode == 'pinning' else 'digest_r1.bin'
        run_fleet(
            args.mode,
            args.params or default_params,
            args.gpus,
            args.max_price,
            args.budget,
            args.max_machines,
            args.easy,
            args.state_file,
            args.status_file,
        )
    elif args.cmd == 'sync':
        sys.exit(sync_fleet(args.state_file, args.status_file, cleanup_on_hit=args.cleanup_on_hit))
    elif args.cmd == 'cleanup':
        cleanup(args.state_file, args.status_file)
    else:
        parser.print_help()
        print("\nExamples:")
        print("  export VASTAI_API_KEY='your_key'")
        print("  python3 qsb_run.py run --mode pinning --gpus 64 --budget 200")
        print("  python3 qsb_run.py run --mode digest --params digest_r1.bin --gpus 32 --budget 100")
        print("  python3 qsb_run.py run --mode pinning --gpus 32 --max-price 4")
        print("  python3 qsb_run.py sync --cleanup-on-hit")
        print("  python3 qsb_run.py cleanup                            # Destroy all instances")
