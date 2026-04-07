# Quantum Safe Bitcoin (QSB)

The first quantum-safe Bitcoin transaction scheme using only existing consensus rules.

QSB replaces Binohash's signature-size puzzle (broken by Shor's algorithm) with a hash-to-signature puzzle whose security depends only on the pre-image resistance of RIPEMD-160. The scheme achieves ~118-bit second pre-image resistance under the Shor threat model, at an estimated off-chain GPU cost of a few hundred dollars.

## Paper

See [`paper/article.pdf`](paper/article.pdf) for the full technical description.

## Repository Structure

```
├── paper/
│   ├── article.tex          # LaTeX source
│   └── article.pdf          # Compiled paper
├── gpu/                     # CUDA GPU search code
│   ├── qsb_allgpu.cu       # Pinning search (SHA-256d + EC recovery)
│   ├── qsb_digest_gpu.cu   # Digest search (subset enumeration + EC)
│   ├── qsb_search.cu       # Production search (reads binary params)
│   ├── qsb_params.h        # Binary param file reader
│   ├── GPUMath.h            # secp256k1 field arithmetic (CudaBrainSecp)
│   ├── GPUHash.h            # SHA-256 / RIPEMD-160 on GPU
│   ├── Makefile
│   ├── launch_multi_gpu.sh  # Multi-GPU launcher
│   └── run_pinning.sh       # Per-machine pinning search
├── pipeline/                # Python pipeline and orchestration
│   ├── qsb_pipeline.py     # Full pipeline: setup → export → search → assemble
│   ├── bitcoin_tx.py        # Transaction construction, sighash, FindAndDelete
│   ├── secp256k1.py         # EC math, ECDSA sign/recover, DER encode/parse
│   ├── secp256k1_fast.py    # Fast EC math using coincurve
│   ├── benchmark.py         # Benchmarking and graduated tests
│   ├── qsb_run.py          # vast.ai fleet orchestration (multi-machine)
│   └── run_qsb.sh          # All-in-one run script for vast.ai
└── README.md
```

## Quick Start

### On a vast.ai GPU instance:

```bash
# Build
cd gpu && apt-get install -y -qq libssl-dev && make && cd ..

# Setup (generates keys, builds script)
cd pipeline
python3 qsb_pipeline.py setup --config A

# Export GPU params (after funding the P2SH address)
python3 qsb_pipeline.py export \
    --funding-txid <txid> --funding-vout 0 \
    --funding-value <sats> --dest-address <pubkeyhash_hex>

# Run pinning search (all GPUs)
cd ../gpu && chmod +x launch_multi_gpu.sh run_pinning.sh
./launch_multi_gpu.sh pinning

# Run digest search (after pinning hit)
./launch_multi_gpu.sh digest ../digest_r1.bin
./launch_multi_gpu.sh digest ../digest_r2.bin

# Assemble spending transaction
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

## Configuration

| Config | n | t1 | t2 | Opcodes | Digest | Pre-image | Cost |
|--------|---|----|----|---------|--------|-----------|------|
| Baseline | 150 | 8 | 8 | 197 | 84.5b | 2^138 | ~$75-150 |
| **Config A** | **150** | **8+1b** | **7+2b** | **201** | **80.4b** | **2^118** | **~$75-150** |

## Measured Performance

| GPU | Pinning rate | Digest rate |
|-----|-------------|-------------|
| RTX 4070 SUPER | 88 M/s | 82 M/s |
| RTX PRO 6000 (Blackwell) | 238 M/s | ~160 M/s (est.) |

## Cost Breakdown (Config A)

| Phase | Candidates | Est. cost |
|-------|-----------|-----------|
| Pinning | ~2^46.4 | $25–$50 |
| Digest round 1 | C(150,9) ≈ 2^46.2 | $25–$50 |
| Digest round 2 | C(150,9) ≈ 2^46.2 | $25–$50 |
| **Total** | | **$75–$150** |

The computation is embarrassingly parallel — wall-clock time scales inversely with the number of GPUs.

## Key Technical Details

- **DER probability**: 2^-46.4 at consensus level (sighash byte unconstrained; `SCRIPT_VERIFY_STRICTENC` is policy-only)
- **Search space**: sequence (32 bits) × locktime (32 bits) = 2^64 candidates for pinning
- **Midstate trick**: SHA-256 precomputation over ~5KB fixed scriptCode prefix reduces per-candidate cost to 2-3 SHA-256 blocks
- **EC recovery**: CudaBrainSecp precomputed GTable (16 chunks × 65536 points) for fast scalar multiplication on GPU

## License

MIT
