# QSB GPU Search

CUDA implementation of the QSB off-chain search: transaction pinning and digest round solving.

## Build

```bash
apt-get install -y -qq libssl-dev
make
```

## Quick Start

### Full pipeline on a vast.ai instance:

```bash
# 1. Build
cd gpu && make && cd ..

# 2. Setup (generates keys, builds script)
cd pipeline
python3 qsb_pipeline.py setup --config A

# 3. Export GPU params (after funding the P2SH address)
python3 qsb_pipeline.py export \
    --funding-txid <txid> --funding-vout 0 \
    --funding-value <sats> --dest-address <pubkeyhash_hex>

# 4. Run pinning search (all GPUs)
cd ../gpu && chmod +x launch_multi_gpu.sh run_pinning.sh
./launch_multi_gpu.sh pinning

# 5. Run digest search (after pinning hit)
./launch_multi_gpu.sh digest ../digest_r1.bin
./launch_multi_gpu.sh digest ../digest_r2.bin

# 6. Assemble spending transaction
cd ../pipeline
python3 qsb_pipeline.py assemble \
    --locktime <lt> --sequence <seq> \
    --round1 <indices> --round2 <indices> \
    --funding-txid <txid> --funding-vout 0 \
    --funding-value <sats> --dest-address <pubkeyhash_hex>
```

### Multi-machine fleet (from your local machine):

```bash
pip install vastai
vastai set api-key <YOUR_KEY>
cd pipeline
python3 qsb_run.py run --gpus 64 --budget 200
```

## Files

| File | Description |
|------|-------------|
| `qsb_allgpu.cu` | Pinning search — SHA-256d + EC recovery, 238M/s on RTX PRO 6000 |
| `qsb_digest_gpu.cu` | Digest search — subset enumeration + EC recovery |
| `qsb_search.cu` | Production search binary (reads binary params from pipeline) |
| `qsb_params.h` | Binary parameter file reader |
| `GPUMath.h` | secp256k1 field arithmetic (from CudaBrainSecp, GPL-3.0) |
| `GPUHash.h` | SHA-256 / RIPEMD-160 on GPU (from CudaBrainSecp, GPL-3.0) |
| `launch_multi_gpu.sh` | Multi-GPU launcher — splits work across all available GPUs |
| `run_pinning.sh` | Per-machine pinning search with GTable caching |

## Benchmarks

Run on the current instance:

```bash
# Pinning benchmark (easy mode)
./qsb_allgpu bench

# Pinning search (real DER, single sequence)
./qsb_allgpu search 0 1
```

## Measured Performance

| GPU | Pinning rate | Notes |
|-----|-------------|-------|
| RTX 4070 SUPER | 88 M/s | $0.089/hr on vast.ai |
| RTX PRO 6000 (Blackwell, 188 SMs) | 238 M/s | $10.69/hr on vast.ai |

**Important**: Do NOT use `-maxrregcount=64` — it halves performance on Blackwell GPUs.

## Multi-GPU

The search is embarrassingly parallel. Each GPU searches independent sequence ranges (pinning) or first-index ranges (digest).

```bash
# Launch all GPUs on one machine
chmod +x launch_multi_gpu.sh run_pinning.sh
./launch_multi_gpu.sh pinning

# Or use run_pinning.sh for multi-machine (each machine gets a unique ID)
./run_pinning.sh 0   # Machine 0
./run_pinning.sh 1   # Machine 1 (on a different instance)
```

Monitor progress:
```bash
# Check all GPUs
for i in $(seq 0 7); do echo -n "GPU $i: "; tail -1 results/log_pin_gpu$i.txt; done

# Check for hits
cat results/pinning_hit.txt 2>/dev/null || echo "No hit yet"
```
