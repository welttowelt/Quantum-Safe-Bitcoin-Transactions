# QSB GPU Search

Fast QSB search using libsecp256k1 (C) + OpenMP for multi-core parallelism.

## Architecture

```
Python (orchestrator)                    C program (qsb_search)
─────────────────────                    ───────────────────────
Build script + transaction               EC recovery (libsecp256k1)
Compute sighash values (FindAndDelete)   RIPEMD-160
                     ──── z values ────► DER check
                     ◄─── hits ────────  OpenMP parallel
```

- **Pinning**: C program iterates locktimes, computes sighash + EC recovery + RIPEMD + DER check
- **Digest**: Python computes sighash per subset (FindAndDelete), C program does batch EC recovery

## Quick Start on vast.ai

```bash
# 1. Rent a CPU instance (many cores, no GPU needed for this version)
# 2. Upload and setup
scp -P <port> qsb.zip root@<ip>:/root/
ssh -p <port> root@<ip>
cd /root && unzip qsb.zip && cd qsb/gpu
bash setup_gpu.sh

# 3. Benchmark (measure EC recovery rate)
./qsb_search bench

# 4. Easy pinning test
python3 run_search.py pin --diff 16 --count 100000

# 5. Full pipeline test
python3 run_search.py full --diff 16

# 6. Harder test
python3 run_search.py full --diff 256 --max-subsets 100000
```

## Expected Performance

libsecp256k1 EC recovery: ~100K/s per core

| Machine | Cores | Recovery rate | Pinning 2^46 | Cost estimate |
|---------|-------|---------------|-------------|---------------|
| 8-core | 8 | ~800K/s | ~1000 days | — |
| 64-core | 64 | ~6.4M/s | ~127 days | ~$450 |
| 10x 64-core | 640 | ~64M/s | ~13 days | ~$450 |

Note: digest search adds CPU sighash overhead (~17ms per subset).
True GPU implementation would be 10-100x faster on EC recovery.

## Files

| File | Description |
|------|-------------|
| `qsb_search.c` | C implementation (libsecp256k1 + OpenMP) |
| `run_search.py` | Python orchestrator |
| `Makefile` | Build the C program |
| `setup_gpu.sh` | vast.ai setup script |
