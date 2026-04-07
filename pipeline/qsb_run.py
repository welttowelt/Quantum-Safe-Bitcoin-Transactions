#!/usr/bin/env python3
"""
qsb_run.py — One-command QSB pinning search across vast.ai fleet

Setup (once):
  pip install paramiko
  # Get your API key from https://cloud.vast.ai/account/
  export VASTAI_API_KEY="your_key_here"

Usage:
  python3 qsb_run.py run --gpus 64 --budget 200
  python3 qsb_run.py run --gpus 100 --max-price 5.0
  python3 qsb_run.py cleanup

It will:
  1. Find cheapest multi-GPU machines on vast.ai
  2. Rent them
  3. Upload code and build
  4. Start pinning search on all GPUs
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
import tempfile
from pathlib import Path

API_KEY = os.environ.get("VASTAI_API_KEY", "")
if not API_KEY:
    # Try reading from vastai CLI config
    config_path = os.path.expanduser("~/.config/vastai/vast_api_key")
    if os.path.exists(config_path):
        API_KEY = open(config_path).read().strip()
API_URL = "https://console.vast.ai/api/v0"
QSB_ZIP = None  # Set path to qsb.zip, or auto-detect

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

def deploy_and_start(instance_id, machine_id, zip_path):
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
    setup_cmd = (
        "cd / && rm -rf qsb && unzip -o /workspace/qsb.zip && "
        "cd /qsb/gpu && "
        "apt-get install -y -qq libssl-dev 2>/dev/null && "
        "nvcc -O3 -o qsb_allgpu qsb_allgpu.cu -lcrypto -lm 2>&1 | tail -1 && "
        "chmod +x run_pinning.sh && "
        f"nohup bash -c 'cd /qsb/gpu && ./run_pinning.sh {machine_id}' "
        "> /workspace/qsb_output.log 2>&1 &"
    )
    
    out, rc = ssh_exec(instance_id, setup_cmd, timeout=600)
    if rc != 0:
        print(f"  {tag} Setup failed: {out[:200]}")
        return False
    
    print(f"  {tag} Search started!")
    return True

def check_for_hit(instance_id, machine_id):
    """Check if this machine found a hit."""
    out, rc = ssh_exec(instance_id, 
        "cat /qsb/gpu/results/pinning_hit.txt 2>/dev/null || echo __NOHIT__",
        timeout=30)
    if "__NOHIT__" not in out and "sequence=" in out:
        return out.strip()
    return None

def get_progress(instance_id, machine_id):
    """Get search progress from one machine."""
    out, rc = ssh_exec(instance_id,
        "tail -1 /qsb/gpu/results/log_m*_gpu0.txt 2>/dev/null || echo 'starting...'",
        timeout=15)
    return out.strip()

# ============================================================
# Main orchestration
# ============================================================

def run_fleet(target_gpus, max_price, budget, max_machines):
    if not API_KEY:
        print("ERROR: Set VASTAI_API_KEY environment variable")
        print("  export VASTAI_API_KEY='your_key_here'")
        print("  Get your key from: https://cloud.vast.ai/account/")
        sys.exit(1)
    
    zip_path = QSB_ZIP or find_qsb_zip()
    if not zip_path:
        print("ERROR: qsb.zip not found. Place it in current directory.")
        sys.exit(1)
    
    print(f"╔════════════════════════════════════════════╗")
    print(f"║  QSB Fleet — Pinning Search               ║")
    print(f"╚════════════════════════════════════════════╝")
    print(f"  Target GPUs: {target_gpus}")
    print(f"  Max price: ${max_price}/hr per machine")
    print(f"  Max machines: {max_machines}")
    print(f"  Budget: ${budget}")
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
    state = {
        'instances': [(iid, mid) for iid, mid, _ in instances],
        'started': time.time(),
    }
    with open('.qsb_fleet_state.json', 'w') as f:
        json.dump(state, f)
    
    print(f"\n  {len(instances)} machines rented. Deploying...")
    print()
    
    # Step 3: Deploy and start (parallel)
    print("  [3/5] Deploying code and starting search...")
    threads = []
    results = {}
    
    def deploy_worker(iid, mid):
        results[mid] = deploy_and_start(iid, mid, zip_path)
    
    for iid, mid, _ in instances:
        t = threading.Thread(target=deploy_worker, args=(iid, mid))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join(timeout=700)
    
    active = sum(1 for v in results.values() if v)
    print(f"\n  {active}/{len(instances)} machines active.")
    
    if active == 0:
        print("  All deployments failed! Cleaning up...")
        for iid, _, _ in instances:
            destroy_instance(iid)
        return
    
    # Step 4: Monitor
    print()
    print("  [4/5] Monitoring for hits...")
    print("  Press Ctrl+C to stop and destroy all instances")
    print()
    
    start_time = time.time()
    
    try:
        while True:
            elapsed_h = (time.time() - start_time) / 3600
            cost_so_far = elapsed_h * total_hourly
            
            if cost_so_far > budget:
                print(f"\n  Budget limit (${budget}) reached. Stopping.")
                break
            
            # Check for hits
            for iid, mid, _ in instances:
                hit = check_for_hit(iid, mid)
                if hit:
                    print(f"\n  {'='*50}")
                    print(f"  HIT FOUND on Machine {mid}!")
                    print(f"  {'='*50}")
                    print(f"  {hit}")
                    print(f"  {'='*50}")
                    print(f"  Time: {elapsed_h:.1f}h, Cost: ${cost_so_far:.2f}")
                    
                    # Save result
                    with open('pinning_result.txt', 'w') as f:
                        f.write(hit)
                    print(f"  Saved to pinning_result.txt")
                    
                    # Cleanup
                    print(f"\n  [5/5] Destroying all instances...")
                    for iid2, _, _ in instances:
                        destroy_instance(iid2)
                    print(f"  Done!")
                    return
            
            # Progress
            print(f"  [{time.strftime('%H:%M:%S')}] "
                  f"{elapsed_h:.1f}h elapsed, ${cost_so_far:.1f} spent  ", end="")
            
            for iid, mid, _ in instances[:4]:  # Show first 4
                prog = get_progress(iid, mid)
                rate = ""
                if "M/s" in prog:
                    rate = prog.split("M/s")[0].split(",")[-1].strip() + "M/s"
                print(f" M{mid}:{rate or '?'}", end="")
            print()
            
            time.sleep(60)
    
    except KeyboardInterrupt:
        print(f"\n\n  Interrupted! Destroying all instances...")
        for iid, _, _ in instances:
            destroy_instance(iid)
        print(f"  All instances destroyed. Cost: ${cost_so_far:.2f}")

def cleanup():
    """Destroy any remaining fleet instances."""
    try:
        with open('.qsb_fleet_state.json') as f:
            state = json.load(f)
    except FileNotFoundError:
        print("No fleet state found.")
        return
    
    print("Destroying fleet instances...")
    for iid, mid in state['instances']:
        print(f"  Instance {iid} (M{mid})... ", end="")
        destroy_instance(iid)
        print("destroyed")
    os.remove('.qsb_fleet_state.json')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='QSB Fleet — One-command GPU search')
    sub = parser.add_subparsers(dest='cmd')
    
    run_p = sub.add_parser('run', help='Launch fleet and search')
    run_p.add_argument('--gpus', type=int, default=64, help='Target total GPU count')
    run_p.add_argument('--max-price', type=float, default=6.0, help='Max $/hr per machine')
    run_p.add_argument('--budget', type=float, default=200, help='Total budget in $')
    run_p.add_argument('--max-machines', type=int, default=20, help='Max machines to rent')
    
    sub.add_parser('cleanup', help='Destroy all fleet instances')
    
    args = parser.parse_args()
    
    if args.cmd == 'run':
        run_fleet(args.gpus, args.max_price, args.budget, args.max_machines)
    elif args.cmd == 'cleanup':
        cleanup()
    else:
        parser.print_help()
        print("\nExamples:")
        print("  export VASTAI_API_KEY='your_key'")
        print("  python3 qsb_run.py run --gpus 64 --budget 200         # ~1.7h, ~$145")
        print("  python3 qsb_run.py run --gpus 100 --budget 100        # ~1h, ~$50")
        print("  python3 qsb_run.py run --gpus 32 --max-price 4        # Cheap machines only")
        print("  python3 qsb_run.py cleanup                            # Destroy all instances")
