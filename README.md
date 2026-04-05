# Quantum-Safe Bitcoin Transactions Today

**Avihu Mordechai Levy ([@avihu28](https://github.com/avihu28))**
**avihu@starkware.co**

To the best of our knowledge, this is the first scheme that enables quantum-safe Bitcoin transactions using only existing consensus rules. No protocol changes required.

## Overview

This scheme adapts [Binohash](https://robinlinus.com/binohash.pdf) (Robin Linus, 2026) to be quantum-safe by replacing the OP_SIZE signature puzzle — which relies on an assumption that does not hold under quantum computing — with a RIPEMD-160 hash-to-signature puzzle that depends only on hash function security.

### Key Idea

The locking script contains a hardcoded signature `sig_nonce` (with `SIGHASH_ALL`). The spender derives `key_nonce` via ECDSA key recovery from `(sig_nonce, sighash)`. The script computes `RIPEMD160(key_nonce)` and verifies the result is a valid DER signature via `CHECKSIGVERIFY`. Finding a transaction where this holds requires ~2^46 hash grinding — quantum-safe.

### Quantum-Safe Signature Chain

```
sig_nonce (hardcoded, SIGHASH_ALL)
    → key_nonce (ECDSA recovery, bound to tx)
        → RIPEMD160(key_nonce) = sig_puzzle
            → key_puzzle (proves sig_puzzle is valid DER)
```

### What's Changed from Binohash

| | Binohash | QSB (This Scheme) |
|---|----------|-------------|
| **Puzzle check** | OP_SIZE (ECDSA PoW) | RIPEMD160 hash-to-sig |
| **Quantum safe** | No | Yes |
| **Sighash control** | Cannot enforce flag | Hardcoded SIGHASH_ALL |
| **Pinning** | 13 ops (4 puzzle sigs) | 5 ops (RIPEMD160 chain) |
| **Net extra ops** | — | 0 (pinning savings offset round overhead) |

## Security (Config A: t=8+1b, 7+2b)

| Property | Value |
|----------|-------|
| Non-push opcodes | **201 / 201** |
| Digest (signed only) | 80.4 bits |
| Pre-image resistance | ~2^118 |
| Collision resistance | ~2^78 |
| Honest work | ~2^47.7 |
| Estimated GPU cost | ~$200–$500 |

## Operational Architecture

The search for puzzle solutions is outsourced to untrusted GPU hardware. All secrets (HORS preimages) remain on the spender's secure device. See the [article](docs/article.pdf) Section 3.5 for details.

## Files

```
├── docs/
│   ├── article.pdf         # Full paper (24 pages)
│   └── article.tex         # LaTeX source
├── src/
│   ├── qsb_fast_search.py  # Main search entry point
│   ├── benchmark.py         # Benchmarking tool
│   ├── bitcoin_tx.py        # Transaction serialization, sighash, FindAndDelete
│   ├── secp256k1.py         # Pure Python EC (fallback)
│   ├── secp256k1_fast.py    # coincurve adapter (fast)
│   └── search_v2.py         # Precomputed recovery utilities
├── gpu/
│   ├── qsb_search.c         # C search program (libsecp256k1 + OpenMP)
│   ├── run_search.py         # Python orchestrator for C program
│   ├── Makefile              # Build the C program
│   ├── setup_gpu.sh          # vast.ai setup script
│   └── README.md             # GPU deployment guide
├── requirements.txt
├── setup.sh                  # Python-only setup
└── README.md
```

## Quick Start (Python, easy mode)

```bash
pip install coincurve
cd src
python3 qsb_fast_search.py --config tiny --easy     # seconds
python3 qsb_fast_search.py --config small --easy    # ~10 seconds
python3 qsb_fast_search.py --config A --easy        # minutes
```

## Fast Search (C + OpenMP)

```bash
cd gpu
bash setup_gpu.sh    # installs libsecp256k1, builds, benchmarks
python3 run_search.py bench
python3 run_search.py pin --diff 16 --count 100000
python3 run_search.py full --diff 16
```

## Constraints

- **Legacy script only**: Requires ECDSA, FindAndDelete (removed in SegWit), and SIGHASH_SINGLE bug
- **Non-standard transaction**: Requires direct submission to a mining pool (e.g., via [Slipstream](https://ir.mara.com/news-events/press-releases/detail/1343/marathon-digital-holdings-launches-slipstream))
- **201 opcode limit**: All non-push opcodes count
- **10,000 byte script limit**: Config A fits at ~9,887 bytes

## Related Work

- **[Binohash](https://robinlinus.com/binohash.pdf)** (Robin Linus, 2026): Our direct foundation
- **[SHA-2 ECDSA](https://github.com/RobinLinus/sha2-ecdsa)** (Robin Linus, 2024): Hash-to-signature concept
- **[Signing Bitcoin Transactions with Lamport Signatures](https://groups.google.com/g/bitcoindev/c/mR53go5gHIk)** (Ethan Heilman, 2024): Pioneering hash-based Bitcoin signatures

## License

MIT
