# Quantum Safe Bitcoin (QSB)

A quantum-safe Bitcoin transaction scheme using only existing consensus rules.

📄 **Paper**: [Quantum-Safe Bitcoin Transactions Without Softforks](https://github.com/avihu28/Quantum-Safe-Bitcoin-Transactions/blob/main/paper/QSB.pdf)

## Overview

Quantum Safe Bitcoin (QSB) enables signing Bitcoin transactions in a way that remains secure even against an adversary with a large-scale quantum computer running Shor's algorithm. The scheme requires **no changes to the Bitcoin protocol** — it operates entirely within the existing legacy script constraints (201 opcodes, 10,000 bytes).

### The Problem

Standard Bitcoin transactions rely on ECDSA signatures over the secp256k1 curve. Shor's algorithm can efficiently compute discrete logarithms, allowing a quantum adversary to forge ECDSA signatures — breaking the fundamental security assumption that protects Bitcoin transactions.

### Our Approach

QSB builds on [Binohash](https://robinlinus.com/binohash.pdf) (Linus, 2026), a legacy-script transaction introspection scheme for BitVM-style use cases. Binohash uses a HORS-like one-time signature scheme embedded in Bitcoin Script and achieves transaction integrity through a proof-of-work puzzle based on signature sizes (`OP_SIZE`). However, that puzzle relies on the assumption that the smallest known ECDSA `r`-value cannot be improved. A quantum adversary running Shor's algorithm could compute the discrete logarithm of `r = 1`, breaking the puzzle entirely.

QSB replaces this with a **hash-to-signature puzzle**: the script hashes a transaction-bound public key via `OP_RIPEMD160` and interprets the 20-byte output as a DER-encoded ECDSA signature. A random 20-byte string satisfies the DER structural constraints with probability ~2^-46 — providing the proof-of-work target. Since this puzzle depends only on the pre-image resistance of RIPEMD-160 (not on any elliptic curve assumption), it is **fully resistant to Shor's algorithm**.

### What QSB keeps from Binohash

QSB is not a fresh design from zero. It keeps the parts of Binohash that already work well inside legacy Script:

- **HORS / Lamport-style digest signing** via hash commitments and revealed preimages
- **Dummy signatures + FindAndDelete** so subset choices change the `scriptCode` and therefore the sighash
- **The `SIGHASH_SINGLE` bug trick** to precompute reusable 9-byte dummy signatures with `z = 1`
- **Legacy-only execution** under the 201-opcode / 10,000-byte limits

QSB replaces the parts of Binohash that matter for standalone quantum safety:

- **Pinning puzzle**: `OP_SIZE`-based signature-size grinding becomes a `RIPEMD160(pubkey) -> valid DER` hash-to-sig puzzle
- **Digest-round puzzle**: same replacement inside each round, so the proof-of-work no longer depends on small-`r` elliptic-curve structure
- **Sighash control**: QSB hardcodes `SIGHASH_ALL` in the hash-to-sig puzzle path, instead of relying on Binohash's broader multi-sighash pinning construction

### Key Properties

- **Quantum safe**: Security relies on hash pre-image resistance, not ECDSA. ~118-bit second pre-image resistance under Shor; ~59-bit under Grover.
- **No protocol changes**: Uses only existing Bitcoin consensus rules (legacy bare-script transactions; the paper-compatible path is non-standard).
- **Practical cost**: ~$75–$150 in cloud GPU compute for the off-chain search, with embarrassingly parallel scaling.
- **Non-standard transaction**: Requires submission via a miner-direct service (e.g., Slipstream) since the transaction exceeds standard relay policy limits.
- **Auxiliary input**: The current prototype uses a helper input to realize the `SIGHASH_SINGLE` bug path for dummy signatures. The pipeline defaults to a placeholder helper for testing; real runs should provide a valid auxiliary input and its scriptSig.

### How It Works

```
  TRANSACTION PINNING              DIGEST ROUND (×2)

  Hardcoded signature              Choose t of n dummy sigs
  commits to SIGHASH_ALL           (= the digest)
           |                                |
           v                                v
  Changing the tx changes          Verify Lamport signature
  the derived key                  (HORS preimages)
           |                                |
           v                                v
  +----------------------+        Subset determines sighash
  | Hash the key — must  |        (via FindAndDelete)
  | produce a valid sig  |                  |
  | (~2^46 work)         |                  v
  +----------------------+        +----------------------------+
                                  | Derive key, hash it —      |
  Any tx modification             | must produce valid sig     |
  requires new puzzle solve       | (hash-to-sig puzzle)       |
                                  +----------------------------+
```

The spending process has four phases in the current repo:

1. **Setup**: Generate the HORS keys and script, then fund the resulting bare legacy output.

2. **Transaction pinning**: Export `pinning.bin`, then search over `(sequence, locktime)` pairs until the recovered public key's RIPEMD-160 hash is a valid DER signature. This pins the transaction to a specific set of parameters (~2^46 work).

3. **Digest rounds (×2)**: Once pinning yields `(sequence, locktime)`, export `digest_r1.bin` / `digest_r2.bin`. Each round searches over subsets of dummy signatures. Each subset produces a different `scriptCode` (via `FindAndDelete`), yielding a different sighash and thus a different recovered public key. Find a subset whose recovered key hashes to a valid DER signature (~2^46 candidates per round).

4. **Assembly**: Recover all public keys, extract HORS preimages, and construct the final spending transaction with the full unlocking stack.

The indices of the selected dummy signatures in each round form a **digest** — a compact, collision-resistant identifier of the transaction, analogous to a hash-based signature.

### Why Is This Quantum Safe?

The security of standard Bitcoin transactions rests on ECDSA — broken by Shor's algorithm. QSB replaces every security-critical component with hash-based alternatives:

- **Transaction pinning** depends on RIPEMD-160 pre-image resistance, not ECDSA hardness. A quantum adversary gains no advantage from Shor's algorithm; only Grover's quadratic speedup applies.
- **The Lamport signature** (HORS) uses hash commitments — the spender reveals preimages of committed hashes, which a quantum computer cannot forge.
- **ECDSA is used only as a vehicle**, not as a security assumption. The scheme exploits the fact that Bitcoin Script can verify ECDSA signatures (`OP_CHECKSIG`), but the *hardness* comes from hashing, not from the elliptic curve.

The result: ~118-bit pre-image security under Shor (roughly halved under Grover), compared to 0-bit security for standard ECDSA transactions.

### The Hash-to-Signature Puzzle

The core innovation is the hash-to-signature puzzle. A DER-encoded ECDSA signature has rigid structural constraints — specific tag bytes (`0x30`, `0x02`), internally consistent length fields, and positive integer values. A random 20-byte string satisfies all of these with probability ~2^-46.

The puzzle works as follows: the locking script contains a hardcoded ECDSA signature `sig_nonce` with a known `(r, s)`. When the spender provides a public key `key_nonce`, the script:

1. Verifies `(sig_nonce, key_nonce)` via `OP_CHECKSIGVERIFY` — this binds `key_nonce` to the current transaction's sighash.
2. Computes `OP_RIPEMD160(key_nonce)` — producing a 20-byte hash.
3. Interprets this hash as a signature `sig_puzzle` and verifies it via another `OP_CHECKSIGVERIFY`.

Step 3 succeeds only if the hash happens to be valid DER — a ~2^-46 event. Since `key_nonce` is determined by the transaction (via step 1), modifying any part of the transaction changes `key_nonce`, changes the hash, and almost certainly breaks step 3. This is the proof-of-work: finding a transaction whose derived key hashes to valid DER.

### Constraints and Tradeoffs

The scheme operates under Bitcoin's tightest constraints:

- **201 non-push opcodes** — every opcode counts, limiting the number of signature selections per round.
- **10,000 byte script size** — must fit ~150 dummy signatures, ~150 hash commitments, and all verification logic across two rounds.
- **Bare script output** — the script exceeds P2SH's 520-byte redeem script limit, so it must be placed directly in the scriptPubKey.
- **Non-standard transaction** — exceeds default relay policy, requiring miner-direct submission (e.g., via Slipstream).

These constraints force careful parameter tuning. The "bonus key" optimization adds cheap subset selections (3 opcodes each vs. 9 for full selections) to match the combinatorial search space to the fixed ~2^46 puzzle target — eliminating grinding overhead while staying within the opcode budget.

## Repository Structure

```
├── paper/
│   ├── QSB.tex              # LaTeX source
│   └── QSB.pdf              # Compiled paper
├── gpu/                     # CUDA GPU search code
│   ├── qsb_allgpu.cu       # Older pinning benchmark/search prototype
│   ├── qsb_digest_gpu.cu   # Older digest benchmark/search prototype
│   ├── qsb_search.cu       # Current production search (reads binary params)
│   ├── qsb_params.h        # Binary param file reader
│   ├── GPUMath.h            # secp256k1 field arithmetic (CudaBrainSecp)
│   ├── GPUHash.h            # SHA-256 / RIPEMD-160 on GPU
│   ├── Makefile
│   ├── launch_multi_gpu.sh  # Multi-GPU launcher
│   └── run_pinning.sh       # Per-machine pinning search
├── pipeline/                # Python pipeline and orchestration
│   ├── qsb_pipeline.py     # Full pipeline: setup → export pinning → export digest → assemble
│   ├── bitcoin_tx.py        # Transaction construction, sighash, FindAndDelete
│   ├── secp256k1.py         # EC math, ECDSA sign/recover, DER encode/parse
│   ├── secp256k1_fast.py    # Fast EC math using coincurve
│   ├── benchmark.py         # Benchmarking and graduated tests
│   ├── qsb_run.py          # vast.ai fleet orchestration (multi-machine)
│   └── run_qsb.sh          # All-in-one run script for vast.ai
├── studio/                  # Local-first operator UI for the repaired pipeline
│   ├── server.py           # Background task runner + JSON API
│   ├── static/             # Browser UI
│   └── README.md           # Studio usage
├── script/                  # Full generated Bitcoin Scripts
└── README.md
```

## QSB Studio

For a browser-based operator surface over the repaired repo, run:

```bash
./.venv/bin/python -m studio.server
```

Then open `http://127.0.0.1:8421`.

`QSB Studio` keeps each run in its own workspace under `studio/sessions/` and wraps the real `setup → export → export-digest → assemble` flow with artifact inspection, automatic hit ingestion, session cloning, an authorization-binding trace, a multi-scenario mutation lab, a secure-signer / gpu-grinder / on-chain-verifier architecture view, a deeper frontier lab that models published and repo-only profiles against the 201-op / 10kb walls, phase-by-phase grind economics, and real hardware references, downloadable binding and frontier reports, operational-limit summaries, a built-in QSB/Binohash and three-layer landscape explainer, and Vast fleet orchestration/status tracking. See [`studio/README.md`](studio/README.md) for details.

## Status

This is a work in progress. The current implementation covers:

- ✅ **Paper**: Full technical description of the QSB scheme
- ✅ **Script generation**: Complete Bitcoin Script for all configurations
- ✅ **GPU pinning search**: Implemented and tested on cloud GPUs (238M/s on RTX PRO 6000). Successfully found a real DER hit at `sequence=151205, locktime=656535577` after ~6 hours on 8 GPUs.
- ⬜ **GPU digest search**: Implemented, export-aligned, and exercised in the local harness, but not yet tested end-to-end with a real GPU hit
- 🟨 **Transaction assembly**: Pipeline/test harness completes locally; real helper-input funding and on-chain broadcast are still unproven
- ⬜ **On-chain broadcast**: Not yet attempted

See [`gpu/README.md`](gpu/README.md) for build instructions and usage.

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

## References

- [Binohash: Transaction Introspection Without Softforks](https://robinlinus.com/binohash.pdf) — Robin Linus, 2026
- [Signing a Bitcoin Transaction with Lamport Signatures (no OP_CAT)](https://groups.google.com/g/bitcoindev/c/mR53go5gHIk) — Ethan Heilman, 2024

## License

MIT — see [LICENSE](LICENSE).

Note: `gpu/GPUMath.h` and `gpu/GPUHash.h` are from [CudaBrainSecp](https://github.com/nicecash/CudaBrainSecp) (Jean Luc PONS / VanitySearch) and are licensed under GPL-3.0. All other files in this repository are MIT licensed.
