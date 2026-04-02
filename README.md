# Quantum-Safe Bitcoin Transactions Today
## Using Quantum Safe Binohash (QSB)

**Avihu Mordechai Levy ([@avihu28](https://github.com/avihu28))**
**avihu@starkware.co**

A quantum-safe Bitcoin spending scheme using only legacy (pre-taproot) opcodes and hash-based security. No consensus changes required.

## Overview

This scheme adapts [Binohash](https://robinlinus.com/binohash.pdf) (Robin Linus, 2025) to be quantum-safe by replacing the OP_SIZE signature puzzle — which relies on ECDSA grinding and breaks under quantum computing — with a RIPEMD160 hash-to-signature puzzle that depends only on hash function security.

### Key Idea

In Binohash, the spender grinds for an ECDSA signature with a small `s` value, verified via `OP_SIZE`. A quantum computer could trivially produce small signatures, breaking this check.

Our modification: the locking script contains a hardcoded signature `sig_nonce` (with `SIGHASH_ALL`). The spender derives `key_nonce` via ECDSA key recovery from `(sig_nonce, sighash)`. The script verifies `key_nonce` via `CHECKSIGVERIFY`, then computes `RIPEMD160(key_nonce)` to produce `sig_puzzle`. A separate `CHECKSIGVERIFY` verifies that `sig_puzzle` is a valid DER signature (using `key_puzzle` from the witness). Since `key_nonce` is bound to the transaction, and the attacker cannot control RIPEMD160 outputs, forging requires ~2^46 hash grinding — quantum-safe.

### Quantum-Safe Signature Chain

```
sig_nonce (hardcoded, SIGHASH_ALL)
    → key_nonce (ECDSA recovery, bound to tx)
        → RIPEMD160(key_nonce) = sig_puzzle
            → key_puzzle (proves sig_puzzle is valid DER)
```

### What's Preserved from Binohash

- FindAndDelete nonce extraction for controllable sighash variation
- HORS (Lamport) subset signatures for BitVM-importable digests
- 9-byte minimum-size dummy signatures via SIGHASH_SINGLE bug
- OP_ROLL + CHECKMULTISIG framework (no IF/ELSE branching)

### What's Changed

| | Binohash | QSB (This Scheme) |
|---|----------|-------------|
| **Puzzle check** | OP_SIZE (ECDSA PoW) | RIPEMD160 hash-to-sig |
| **Quantum safe** | No (small-r attack) | Yes (hash-based) |
| **Sighash control** | Cannot enforce flag | Hardcoded SIGHASH_ALL |
| **Pinning** | 13 ops (4 puzzle sigs) | 5 ops (RIPEMD160 chain) |
| **Per-round overhead** | 11t + 4 | 11t + 8 |
| **Net extra ops** | — | 0 (pinning savings cancel round overhead) |

## Scheme Architecture

### Pinning (5 ops)

```
// Witness: <key_puzzle> <key_nonce>
<sig_nonce>            // hardcoded, SIGHASH_ALL
OP_OVER                // copy key_nonce
OP_CHECKSIGVERIFY      // verify (sig_nonce, key_nonce) — tx binding
OP_RIPEMD160           // key_nonce -> sig_puzzle
OP_SWAP                // get key_puzzle on top
OP_CHECKSIGVERIFY      // verify (sig_puzzle, key_puzzle) — proves valid DER
```

### Per-Round Structure

Each digest round embeds n=150 dummy sigs and n HORS commitments. The round proceeds in three stages:

**Stage 1: Subset selection + Lamport verification** (9t ops)
The spender provides t indices selecting dummy sigs from the pool. HORS preimages are verified for each.

**Stage 2: Puzzle signature derivation** (3 ops)
```
{pos} OP_ROLL          // roll key_nonce from witness
OP_DUP                 // copy (one for RIPEMD, one for pubkey)
OP_RIPEMD160           // key_nonce -> sig_puzzle
```

**Stage 3: Verification** (2t + 5 ops)
`sig_puzzle` is verified via a separate `CHECKSIGVERIFY` (not inside CHECKMULTISIG — to avoid circular dependency). Then a `(t+1)-of-(t+1) CHECKMULTISIG` verifies the t selected dummies + `sig_nonce` against their public keys. `key_nonce` serves as the public key for `sig_nonce` inside CHECKMULTISIG.

### Bonus Keys

An optimization: "bonus" selections go through FindAndDelete (increasing C(n,t) and reducing grinding cost) but skip HORS verification. Cost: 3 ops per bonus vs 9 per signed selection.

## Configurations

### Config A: t1=8+1bonus, t2=7+2bonus (201 ops — fits)

| Property | Value |
|----------|-------|
| Non-push opcodes | **201 / 201** |
| Script size | ~9,660 / 10,000 |
| Digest (signed only) | 80.4 bits |
| Pre-image resistance | ~2^117.5 |
| Collision resistance | ~2^77.8 |
| Honest work | ~2^46 |
| Estimated cost | ~$40 |

### Config B: t1=8+1bonus, t2=8 (202 ops — 1 over)

| Property | Value |
|----------|-------|
| Non-push opcodes | **202 / 201 (-1)** |
| Script size | ~9,650 / 10,000 |
| Digest (signed only) | 84.5 bits |
| Pre-image resistance | ~2^130.9 |
| Collision resistance | ~2^85.1 |
| Honest work | ~2^49.7 |
| Estimated cost | ~$530 |

### Baseline: t=8, t=8 (197 ops — no bonus)

| Property | Value |
|----------|-------|
| Non-push opcodes | **197 / 201 (+4 spare)** |
| Script size | ~9,650 / 10,000 |
| Digest | 84.5 bits |
| Pre-image resistance | ~2^138 |
| Collision resistance | ~2^88 |
| Honest work | ~2^53.5 |

## Opcode Budget

### Pinning: 5 ops
OVER + CHECKSIGVERIFY + RIPEMD160 + SWAP + CHECKSIGVERIFY

### Per signed selection: 9 ops
ROLL(index) + MIN + DUP + ADD + ROLL(commit) + ROLL(preimage) + HASH160 + EQUALVERIFY + ROLL(sig)

### Per bonus selection: 3 ops
ROLL(index) + MIN + ROLL(sig)

### Per round total
9×t_signed + 3×t_bonus + 2×t_total + 8

## Files

| File | Description |
|------|-------------|
| `script/script_8p1b_7p2b.txt` | Config A: t1=8+1bonus, t2=7+2bonus (201 ops, fits) |
| `script/script_8p1b_8.txt` | Config B: t1=8+1bonus, t2=8 (202 ops, 1 over) |
| `src/generate_qs_binohash.py` | Script generator for all configurations |
| `docs/article.tex` | LaTeX article (draft) |
| `docs/article.pdf` | Compiled article |

## Constraints

- **Legacy script only**: Requires ECDSA, FindAndDelete (removed in SegWit), and SIGHASH_SINGLE bug
- **Non-standard transaction**: Bare scripts require direct mining (e.g., [Slipstream](https://ir.mara.com/news-events/press-releases/detail/1343/marathon-digital-holdings-launches-slipstream))
- **201 opcode limit**: All non-push opcodes count, including in non-executed branches
- **10,000 byte script limit**: Consensus maximum for bare scripts

## Related Work

- **[Binohash](https://robinlinus.com/binohash.pdf)** (Robin Linus, 2025): Our direct foundation.
- **[SHA-2 ECDSA](https://github.com/RobinLinus/sha2-ecdsa)** (Robin Linus, 2024): Hash-to-signature concept.
- **[Signing Bitcoin Transactions with Lamport Signatures](https://groups.google.com/g/bitcoindev/c/mR53go5gHIk)** (Ethan Heilman, 2024): Pioneering hash-based Bitcoin signatures.
- **[ColliderScript](https://eprint.iacr.org/2024/1802)** (Heilman et al., 2024): Covenants via 160-bit hash collisions.

## License

MIT
