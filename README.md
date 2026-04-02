# Quantum-Safe Bitcoin Transactions Today

**Avihu Mordechai Levy ([@avihu28](https://github.com/avihu28))**

A quantum-safe Bitcoin spending scheme using only legacy (pre-taproot) opcodes and hash-based security. No consensus changes required.

## Overview

This scheme adapts [Binohash](https://robinlinus.com/binohash.pdf) (Robin Linus, 2025) to be quantum-safe by replacing the OP_SIZE signature puzzle — which relies on ECDSA grinding and breaks under quantum computing — with a RIPEMD160-based signature chaining mechanism that depends only on hash function security.

### How It Works

The quantum-safe binding uses a two-step signature chain:

1. **sig_r_1** is hardcoded in the locking script (SIGHASH_ALL). The spender derives **key_r_1** via ECDSA key recovery from (sig_r_1, sighash). Script verifies via CHECKSIG — this binds key_r_1 to the specific transaction.

2. Script computes **RIPEMD160(key_r_1) = sig_r_2**. Since key_r_1 is bound to this transaction, sig_r_2 inherits that binding.

3. **sig_r_2** is verified as a valid ECDSA signature inside CHECKMULTISIG (with key_r_2 provided by the spender).

**Quantum safety**: A quantum attacker can derive key_r_1 for any transaction (key recovery is public), but cannot control what RIPEMD160(key_r_1) produces. Finding a transaction where the output is a valid DER signature requires ~2^46 hash grinding — a hash-based hardness assumption, not an EC one.

### What's Preserved from Binohash

- FindAndDelete nonce extraction for controllable sighash variation
- HORS (Lamport) subset signatures for BitVM-importable digests
- 9-byte minimum-size dummy signatures via SIGHASH_SINGLE bug
- OP_ROLL + CHECKMULTISIG framework (no IF/ELSE branching)

### What's Changed

| | Binohash | This Scheme |
|---|----------|-------------|
| **Puzzle check** | OP_SIZE (ECDSA PoW) | RIPEMD160 sig chain |
| **Quantum safe** | No (small-r attack) | Yes (hash-based) |
| **Pinning** | 13 ops (4 puzzle sigs) | 5 ops (RIPEMD160 chain) |
| **Per-round overhead** | 11t + 4 | 11t + 8 |
| **Net extra ops** | — | 0 (pinning savings cancel round overhead) |

## Configurations

We provide two configurations:

### Config A: t1=8+1bonus, t2=7+2bonus (201 ops — fits exactly)

The "bonus" keys go through FindAndDelete (contributing to subset entropy) but skip HORS verification, costing only 3 ops each instead of 9. This dramatically reduces honest work at the cost of some digest entropy.

| Property | Value |
|----------|-------|
| Non-push opcodes | **201 / 201** |
| Digest (signed only) | 80.4 bits |
| Pre-image resistance | ~117.5 bits |
| Collision resistance | ~77.8 bits |
| Honest work | ~2^46 |
| Estimated cost | ~$40 |

### Config B: t1=8+1bonus, t2=8 (202 ops — 1 over, needs 1 more optimization)

Better security, moderate cost. One op over the limit — may fit with further optimization (e.g., dropping OP_MIN on the bonus selection).

| Property | Value |
|----------|-------|
| Non-push opcodes | **202 / 201 (-1)** |
| Digest (signed only) | 84.5 bits |
| Pre-image resistance | ~130.9 bits |
| Collision resistance | ~85.1 bits |
| Honest work | ~2^49.7 |
| Estimated cost | ~$530 |

### Security Notes

**Bonus key freedom**: Bonus indices give the attacker extra choices, reducing security below the naive estimate:
- Pre-image: attacker gets free bonus combinations per pinned transaction (~2^13 for round with 2 bonus, ~2^7 for 1 bonus)
- Collision: attacker can assign indices to signed vs bonus slots freely (C(9,t_signed) choices per passing subset)

These penalties are accounted for in the security figures above.

## Script Structure

### Pinning (5 ops)

```
// Witness: <key2> <key1>
<sig1>              // hardcoded, SIGHASH_ALL
OP_OVER             // copy key1
OP_CHECKSIGVERIFY   // verify (sig1, key1) — tx binding
OP_RIPEMD160        // key1 -> sig2
OP_SWAP             // get key2 on top
OP_CHECKSIGVERIFY   // verify (sig2, key2) — proves valid DER
```

### Per Round

Each round has three sections:

**1. Data pushes** (0 ops): n=150 HORS commitments, 150 dummy sigs, sig_r_1

**2. Selections**: t_signed x 9 ops (full HORS verification) + t_bonus x 3 ops (no HORS check)

**3. Puzzle + CHECKMULTISIG**:
```
{pos} OP_ROLL       // roll key_r_1 from witness
OP_DUP              // copy (one for RIPEMD, one for CMS pubkey)
OP_RIPEMD160        // key_r_1 -> sig_r_2

OP_{M}              // push sig count
OP_2 OP_ROLL        // move key_r_1 to pubkey zone
{pos} OP_ROLL x t   // roll dummy pubkeys
{pos} OP_ROLL       // roll key_r_2
OP_{N}              // push key count
OP_CHECKMULTISIG    // verify all sigs
```

### Opcode Budget

| Component | Config A | Config B |
|-----------|----------|----------|
| Pinning | 5 | 5 |
| Round 1 (8+1b) | 101 | 101 |
| Round 2 (7+2b / 8) | 95 / — | — / 96 |
| **Total** | **201** | **202** |

## Files

| File | Description |
|------|-------------|
| `script/script_8_1b_7_2b.txt` | Config A: full annotated script (201 ops) |
| `script/script_8_1b_8.txt` | Config B: full annotated script (202 ops) |
| `src/generate_qs_binohash.py` | Script generator |
| `src/qs_binohash.py` | Simulation and opcode counting |
| `docs/article.tex` | LaTeX article (draft) |

## Constraints

- **Legacy script only**: Requires ECDSA, FindAndDelete (absent in SegWit), and SIGHASH_SINGLE bug
- **Non-standard transaction**: Bare scripts require direct mining (e.g., [Slipstream](https://ir.mara.com/news-events/press-releases/detail/1343/marathon-digital-holdings-launches-slipstream))
- **201 opcode limit**: All non-push opcodes count, even in non-executed branches
- **10,000 byte script limit**: Both configs fit with margin (~9,800 bytes)

## Related Work

- **[Binohash](https://robinlinus.com/binohash.pdf)** (Robin Linus, 2025): Our foundation — FindAndDelete + CHECKMULTISIG framework
- **[Lamport Signatures for Bitcoin](https://groups.google.com/g/bitcoindev/c/mR53go5gHIk)** (Ethan Heilman, 2024): Pioneering hash-based Bitcoin signatures
- **[ColliderScript](https://eprint.iacr.org/2024/1802)** (Heilman et al., 2024): Covenants via hash collisions

## License

MIT
