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

# 3. Export GPU params (after funding the QSB output)
python3 qsb_pipeline.py export \
    --helper-txid <aux_txid> --helper-vout <aux_vout> \
    --funding-txid <txid> --funding-vout 0 \
    --funding-value <sats> --dest-address <pubkeyhash_hex>

# 4. Run pinning search (all GPUs)
cd ../gpu && chmod +x launch_multi_gpu.sh run_pinning.sh
./launch_multi_gpu.sh pinning ../pinning.bin

# 5. Export digest params after pinning returns sequence + locktime
cd ../pipeline
python3 qsb_pipeline.py export-digest \
    --sequence <seq> --locktime <lt> \
    --helper-txid <aux_txid> --helper-vout <aux_vout> \
    --funding-txid <txid> --funding-vout 0 \
    --funding-value <sats> --dest-address <pubkeyhash_hex>

# 6. Run digest search
cd ../gpu
./launch_multi_gpu.sh digest ../digest_r1.bin
./launch_multi_gpu.sh digest ../digest_r2.bin

# 7. Assemble spending transaction
cd ../pipeline
python3 qsb_pipeline.py assemble \
    --sequence <seq> --locktime <lt> \
    --round1 <indices> --round2 <indices> \
    --helper-txid <aux_txid> --helper-vout <aux_vout> \
    --helper-script-sig-hex <aux_script_sig_hex> \
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
| `qsb_allgpu.cu` | Older pinning benchmark/search prototype |
| `qsb_digest_gpu.cu` | Older digest benchmark/search prototype |
| `qsb_search.cu` | Production search binary (reads binary params from pipeline) |
| `qsb_params.h` | Binary parameter file reader |
| `GPUMath.h` | secp256k1 field arithmetic (from CudaBrainSecp, GPL-3.0) |
| `GPUHash.h` | SHA-256 / RIPEMD-160 on GPU (from CudaBrainSecp, GPL-3.0) |
| `launch_multi_gpu.sh` | Multi-GPU launcher — splits work across all available GPUs |
| `run_pinning.sh` | Per-machine pinning search with GTable caching |

## Benchmarks

Run on the current instance:

```bash
# Pinning benchmark
./qsb_search bench_pinning

# Digest benchmark
./qsb_search bench_digest
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
./launch_multi_gpu.sh pinning ../pinning.bin

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
