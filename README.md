# Quantum-Safe Bitcoin Transactions Today

**Avihu Mordechai Levy ([@avihu28](https://github.com/avihu28))**

A quantum-safe Bitcoin spending scheme using only legacy (pre-taproot) opcodes and hash-based security. No consensus changes required.

## Overview

This scheme adapts [Binohash](https://robinlinus.com/binohash.pdf) (Robin Linus, 2025) to be quantum-safe by replacing the OP_SIZE signature puzzle — which relies on ECDSA grinding and breaks under quantum computing — with a RIPEMD160 valid-signature check that depends only on hash function security.

The result is a Bitcoin transaction that can be created and spent **today**, on the existing Bitcoin network, with **no reliance on elliptic curve hardness** for its security properties.

### Key Idea

In Binohash, the spender grinds for an ECDSA signature with a small `s` value, verified via `OP_SIZE`. A quantum computer could trivially produce small signatures (discrete log is easy), breaking this check.

Our modification: the spender instead grinds for a 20-byte nonce whose **RIPEMD160 hash** happens to be a valid DER-encoded ECDSA signature. The script computes `OP_RIPEMD160` on the nonce and feeds the result into `OP_CHECKMULTISIG`. Since the security depends on the hash function (not on the difficulty of computing discrete logs), this is quantum-safe.

### What's Preserved from Binohash

- **FindAndDelete nonce extraction**: subset selection creates unique sighashes
- **Transaction pinning**: hardcoded signature binds to the spending transaction
- **HORS subset signatures**: Lamport-sign the digest for BitVM import
- **OP_ROLL + OP_CHECKMULTISIG only**: no IF/ELSE branching (all non-push opcodes count toward the 201 limit, even in non-executed branches)
- **9-byte minimum-size dummy signatures**: via ECDSA key recovery + SIGHASH_SINGLE bug

### What's Changed

| | Binohash | This Scheme |
|---|----------|-------------|
| **Puzzle check** | `OP_SIZE` (ECDSA grinding) | `OP_RIPEMD160` (hash grinding) |
| **Quantum safe** | No (small-r attack) | Yes (hash-based only) |
| **Target bits** | W₂ = 42 (configurable) | 46 (fixed by RIPEMD160→DER probability) |
| **Pinning** | 13 ops (4 puzzle sigs) | 1 op (single CHECKSIGVERIFY) |
| **Rounds** | Symmetric (t=8, t=8) | Asymmetric (t=9, t=8) |
| **Ops saved** | — | 1 per round (no SIZE+EQUALVERIFY) |

## Parameters

| Parameter | Value |
|-----------|-------|
| Dummy signatures per round (n) | 150 |
| Round 1 selections (t₁) | 9 |
| Round 2 selections (t₂) | 8 |
| Round 1 entropy: C(150, 9) | 2^46.2 |
| Round 2 entropy: C(150, 8) | 2^42.3 |

## Security

| Property | Bits | Notes |
|----------|------|-------|
| **Digest** | 88.5 | 46.2 + 42.3 (two rounds) |
| **Pre-image resistance** | 134.5 | 46 (RIPEMD160 grind per tx) + 88.5 (digest match) |
| **Collision resistance** | 90.2 | 46 + 88.5/2 (birthday bound on digest) |

**Pre-image attack**: Given a digest D, an attacker must find a different transaction producing the same D. Each attempt requires grinding a RIPEMD160 valid sig (~2^46 work) and the probability of matching D is 2^-88.5. Total cost: **2^134.5**.

**Collision attack**: Find any two transactions with the same digest. Birthday bound over the 88.5-bit digest, with 2^46 work per sample. Total cost: **2^90.2**.

## Cost

| Metric | Value |
|--------|-------|
| P(Round 1 hit) | 100% (C(150,9) ≥ 2^46) |
| P(Round 2 hit) | 7.5% (C(150,8) = 2^42.3 < 2^46) |
| Expected tx grinds | ~13 (2^3.7) |
| **Total honest work** | **~2^49.7 RIPEMD160 hashes** |
| Estimated time (10× RTX 4090) | ~1 hour |
| Estimated cloud cost | ~$5–15 |

Each "tx grind" modifies a transaction parameter and recomputes the FindAndDelete sighashes. The per-grind work is dominated by the RIMEMD160 puzzle search (~2^46 hashes).

## Script Resources

| Resource | Used | Limit | Spare |
|----------|------|-------|-------|
| Non-push opcodes | 196 | 201 | 5 |
| Locking script size | ~9,856 B | 10,000 B | 144 |
| Unlocking script size | ~1,009 B | — | — |

### Opcode Breakdown

| Opcode | Count | Notes |
|--------|-------|-------|
| OP_ROLL | 87 | Subset selection + pubkey positioning |
| OP_MIN | 17 | Index sanitization |
| OP_DUP | 17 | Copy index for hash lookup |
| OP_ADD | 17 | Compute commitment position |
| OP_HASH160 | 17 | Verify HORS preimages (9+8 per round) |
| OP_EQUALVERIFY | 17 | Check against commitments |
| OP_RIPEMD160 | 2 | Nonce → puzzle sig (1 per round) |
| OP_CHECKMULTISIG | 2 + 19 keys | Verify all signatures |
| OP_CHECKSIGVERIFY | 1 | Transaction pinning |
| **Total** | **196** | |

## Transaction Structure

This is a **bare script** (non-standard) legacy transaction. It requires mining via direct block submission (e.g., [Slipstream](https://ir.mara.com/news-events/press-releases/detail/1343/marathon-digital-holdings-launches-slipstream)) or mining pools willing to include non-standard transactions.

**Locking script** (in the output being protected):
1. **Pinning** (1 op): `<sig> <pubkey> OP_CHECKSIGVERIFY` — binds to the transaction via SIGHASH_ALL
2. **Round 1** (103 ops): 150 HORS commitments + 150 dummy sigs + 9-of-10 CHECKMULTISIG with FindAndDelete
3. **Round 2** (92 ops): Same structure, 8-of-9 CHECKMULTISIG

**Unlocking script** (provided by the spender):
- Per round: puzzle nonce, t recovered pubkeys, t HORS preimages, t subset indices
- The subset indices **are** the transaction digest (Binohash)

## Files

| File | Description |
|------|-------------|
| `full_script.txt` | Complete annotated Bitcoin Script (unlocking + locking) |
| `locking_script.txt` | Locking script with hex data and comments |
| `unlocking_script.txt` | Unlocking script (witness data) |
| `qs_binohash.py` | Full simulation: builds scripts, counts opcodes, computes security |
| `generate_script_text.py` | Generates the annotated script text files |

## Constraints & Assumptions

- **Legacy script only**: Requires ECDSA (not Schnorr), FindAndDelete (removed in SegWit), and SIGHASH_SINGLE bug (pre-SegWit only)
- **Non-standard transaction**: Bare scripts exceed P2SH's 520-byte redeem script limit; requires direct mining
- **No CLEANSTACK**: Legacy script does not consensus-enforce CLEANSTACK, so multiple items can remain on the stack
- **201 opcode limit**: All non-push opcodes count, including those in non-executed IF/ELSE branches. This scheme uses zero branching.
- **10,000 byte script limit**: Consensus maximum for bare scripts
- **RIPEMD160 security**: The scheme's quantum safety assumes RIPEMD160 remains pre-image resistant. Grover's algorithm reduces this from 160 bits to ~80 bits, which is sufficient.

## Relation to Prior Work

- **[Binohash](https://robinlinus.com/binohash.pdf)** (Robin Linus, 2025): Our direct foundation. We adapt the FindAndDelete + CHECKMULTISIG framework for quantum safety.
- **[Signing Bitcoin Transactions with Lamport Signatures](https://groups.google.com/g/bitcoindev/c/mR53go5gHIk)** (Ethan Heilman, 2024): Explores hash-based Bitcoin signatures; achieves ~45-bit collision resistance.
- **[ColliderScript](https://eprint.iacr.org/2024/1802)** (Heilman et al., 2024): Covenant construction via 160-bit hash collisions; impractical work requirements (~$50M).

## License

MIT
