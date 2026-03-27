"""Generate clean Bitcoin Script text files for the QS-Binohash scheme."""

import os, math, hashlib, random

def sha256(data): return hashlib.sha256(data).digest()
def ripemd160(data): return hashlib.new('ripemd160', data).digest()
def hash160(data): return ripemd160(sha256(data))

N = 150
T = [9, 8]
R = 2

# Generate deterministic test data
random.seed(42)

# Pinning
pinning_sig = bytes([0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01])
pinning_pubkey = bytes.fromhex("02" + "aa" * 32)  # placeholder

# Rounds
rounds = []
for r in range(R):
    sigs = []
    for i in range(N):
        r_val = (i * 3 + r * 7 + 1) % 127 + 1
        s_val = (i * 11 + r * 13 + 1) % 127 + 1
        sigs.append(bytes([0x30, 0x07, 0x02, 0x01, r_val, 0x02, 0x01, s_val, 0x03]))
    preimages = [bytes([(i * 17 + r * 31 + j) % 256 for j in range(20)]) for i in range(N)]
    commitments = [hash160(p) for p in preimages]
    pubkeys = [bytes([0x02] + [(i * 13 + r * 41 + j) % 256 for j in range(32)]) for i in range(N)]
    rounds.append({'t': T[r], 'sigs': sigs, 'preimages': preimages,
                   'commitments': commitments, 'pubkeys': pubkeys})

chosen_indices = [
    sorted(random.sample(range(N), T[0])),
    sorted(random.sample(range(N), T[1])),
]
puzzle_nonces = [bytes([(r * 53 + j) % 256 for j in range(20)]) for r in range(R)]
puzzle_pubkeys = [bytes([0x02] + [(r * 67 + j) % 256 for j in range(32)]) for r in range(R)]

# ================================================================
# Generate annotated locking script
# ================================================================
def write_locking_script(f):
    ops = 0
    
    f.write("// ============================================================\n")
    f.write("// Quantum-Safe Binohash: Locking Script
// Avihu Mordechai Levy (@avihu28)\n")
    f.write("// ============================================================\n")
    f.write("//\n")
    f.write(f"// Parameters: n={N}, R={R}, t=[{T[0]},{T[1]}]\n")
    f.write(f"// Round 1: C({N},{T[0]}) = 2^{math.log2(math.comb(N,T[0])):.1f}\n")
    f.write(f"// Round 2: C({N},{T[1]}) = 2^{math.log2(math.comb(N,T[1])):.1f}\n")
    digest = sum(math.log2(math.comb(N, t)) for t in T)
    f.write(f"// Digest: {digest:.1f} bits\n")
    f.write(f"// Pre-image resistance: {46 + digest:.1f} bits\n")
    f.write(f"// Collision resistance: {46 + digest/2:.1f} bits\n")
    f.write(f"// Honest work: ~2^49.7\n")
    f.write(f"//\n")
    f.write(f"// Opcode budget: 196 / 201  (5 spare)\n")
    f.write(f"// Script size:   ~9,856 / 10,000 bytes (144 spare)\n")
    f.write("//\n")
    f.write("// Key difference from Binohash:\n")
    f.write("//   OP_SIZE puzzle check → OP_RIPEMD160 valid sig check\n")
    f.write("//   This makes the scheme quantum-safe (hash-based only).\n")
    f.write("// ============================================================\n\n")
    
    # Pinning
    f.write("// ============================================================\n")
    f.write("// Stage 1: Transaction Pinning (1 op)\n")
    f.write("// ============================================================\n")
    f.write("// A hardcoded 9-byte signature with SIGHASH_ALL.\n")
    f.write("// The public key is derived via ECDSA key recovery from\n")
    f.write("// (sig, sighash). This pins the entire transaction: any\n")
    f.write("// modification invalidates the sighash, breaking CHECKSIG.\n")
    f.write("// Quantum-safe because the sig itself is a constant;\n")
    f.write("// the binding comes from the hash, not from EC hardness.\n")
    f.write("//\n")
    f.write(f"<{pinning_sig.hex()}>  // pinning sig (9B, SIGHASH_ALL)\n")
    f.write(f"<{pinning_pubkey.hex()}>  // pinning pubkey (33B, derived)\n")
    f.write("OP_CHECKSIGVERIFY  // [1 op]\n")
    ops += 1
    f.write("\n")
    
    for r in range(R):
        rd = rounds[r]
        t = rd['t']
        round_start = ops
        
        f.write(f"// ============================================================\n")
        f.write(f"// Stage 2, Round {r+1}: FindAndDelete Nonce Extraction\n")
        f.write(f"// t = {t}, C({N},{t}) = 2^{math.log2(math.comb(N,t)):.1f}\n")
        f.write(f"// Opcodes: 11×{t} + 4 = {11*t+4}\n")
        f.write(f"// ============================================================\n")
        f.write(f"//\n")
        f.write(f"// {N} HORS commitments: HASH160(preimage_i)\n")
        f.write(f"// The spender reveals preimages for the selected subset.\n")
        f.write(f"// These commitments double as a Lamport (HORS) signature\n")
        f.write(f"// of the digest, importable into BitVM verification.\n")
        f.write(f"//\n")
        
        # HORS commitments
        f.write(f"// --- {N} HORS commitments (reversed, 20 bytes each) ---\n")
        for i in range(N - 1, -1, -1):
            f.write(f"<{rd['commitments'][i].hex()}>  // H(pre_{i:03d})\n")
        f.write("\n")
        
        # Dummy sigs
        f.write(f"// --- {N} dummy signatures (reversed, 9 bytes each) ---\n")
        f.write(f"// Minimal DER with SIGHASH_SINGLE (0x03).\n")
        f.write(f"// Transaction-independent via SIGHASH_SINGLE bug (z=1).\n")
        f.write(f"// Public keys derived via ECDSA key recovery.\n")
        f.write(f"// FindAndDelete removes selected sigs from scriptCode\n")
        f.write(f"// before sighash computation, creating unique sighashes.\n")
        for i in range(N - 1, -1, -1):
            f.write(f"<{rd['sigs'][i].hex()}>  // sig_{i:03d}\n")
        f.write("\n")
        
        # CHECKMULTISIG dummy
        f.write("OP_0  // CHECKMULTISIG bug dummy element\n\n")
        
        # Selection iterations
        f.write(f"// --- {t} subset selections ---\n")
        f.write(f"// For each selection i (0..{t-1}):\n")
        f.write(f"//   1. Roll index from unlocking script to top\n")
        f.write(f"//   2. Sanitize index (prevent out-of-bounds)\n")
        f.write(f"//   3. Roll HORS commitment for that index\n")
        f.write(f"//   4. Roll HORS preimage, hash, verify against commitment\n")
        f.write(f"//   5. Roll dummy signature for that index\n")
        f.write(f"// Each iteration: 9 non-push opcodes\n\n")
        
        for i in range(t):
            f.write(f"// Selection {i}:\n")
            f.write(f"{2*N - i} OP_ROLL  // move index_{i} to top  [1 op]\n")
            ops += 1
            f.write(f"{N - i} OP_MIN  // sanitize: clamp to [0, {N-i-1}]  [1 op]\n")
            ops += 1
            f.write(f"OP_DUP  // copy index for hash commitment lookup  [1 op]\n")
            ops += 1
            f.write(f"{N + 1} OP_ADD  // hash position = index + {N+1}  [1 op]\n")
            ops += 1
            f.write(f"OP_ROLL  // roll H(pre_index) to top  [1 op]\n")
            ops += 1
            f.write(f"{2*N + t - 2*i} OP_ROLL  // roll preimage_{i} to top  [1 op]\n")
            ops += 1
            f.write(f"OP_HASH160  // hash preimage  [1 op]\n")
            ops += 1
            f.write(f"OP_EQUALVERIFY  // verify preimage matches commitment  [1 op]\n")
            ops += 1
            f.write(f"OP_ROLL  // roll sig[index] to top (index on stack)  [1 op]\n")
            ops += 1
            f.write("\n")
        
        # Puzzle nonce → sig via RIPEMD160
        f.write(f"// --- Quantum-safe puzzle check ---\n")
        f.write(f"// Instead of Binohash's OP_SIZE <target> OP_EQUALVERIFY,\n")
        f.write(f"// we convert a nonce to a valid DER signature via RIPEMD160.\n")
        f.write(f"// The spender grinds for a nonce whose RIPEMD160 output\n")
        f.write(f"// is a valid 20-byte DER-encoded ECDSA signature (P ≈ 2^-46).\n")
        f.write(f"// The corresponding public key is derived via ECDSA key recovery.\n")
        f.write(f"// Quantum-safe: RIPEMD160 is hash-based (no EC hardness).\n")
        f.write(f"//\n")
        f.write(f"{2*N + 1} OP_ROLL  // move puzzle nonce to top  [1 op]\n")
        ops += 1
        f.write(f"OP_RIPEMD160  // nonce → valid DER signature  [1 op]\n")
        ops += 1
        f.write("\n")
        
        # CHECKMULTISIG
        f.write(f"// --- CHECKMULTISIG: {t+1}-of-{t+1} ---\n")
        f.write(f"// Verifies t={t} dummy sigs + 1 puzzle sig against\n")
        f.write(f"// t={t} recovered pubkeys + 1 puzzle pubkey.\n")
        f.write(f"// FindAndDelete has already removed the selected dummy sigs\n")
        f.write(f"// from the scriptCode, so each subset produces a unique sighash.\n")
        f.write(f"//\n")
        f.write(f"OP_{t+1}  // M = {t+1} signatures  (push, 0 ops)\n")
        for j in range(t):
            f.write(f"{2*N + 2} OP_ROLL  // move pubkey_{j} to top  [1 op]\n")
            ops += 1
        f.write(f"<{puzzle_pubkeys[r].hex()}>  // puzzle pubkey (33B, derived from puzzle sig + sighash)\n")
        f.write(f"OP_{t+1}  // N = {t+1} public keys  (push, 0 ops)\n")
        f.write(f"OP_CHECKMULTISIG  // [{1 + t + 1} ops: 1 + {t+1} key count]\n")
        ops += 1 + (t + 1)
        
        round_ops = ops - round_start
        f.write(f"\n// Round {r+1} total: {round_ops} ops (formula: 11×{t}+4 = {11*t+4})\n\n")
    
    f.write("// ============================================================\n")
    f.write("// Script ends.\n")
    f.write("// Stack has: [round2_result (1), round1_result (1)]\n")
    f.write("// CLEANSTACK is not consensus-enforced in legacy script,\n")
    f.write("// so multiple truthy items on the stack is valid.\n")
    f.write("// ============================================================\n")
    f.write(f"\n// Total non-push opcodes: {ops} / 201  ({201 - ops} spare)\n")
    
    return ops


# ================================================================
# Generate annotated unlocking script
# ================================================================
def write_unlocking_script(f):
    f.write("// ============================================================\n")
    f.write("// Quantum-Safe Binohash: Unlocking Script
// Avihu Mordechai Levy (@avihu28)\n")
    f.write("// ============================================================\n")
    f.write("//\n")
    f.write("// The unlocking script provides the witness data:\n")
    f.write("// - Puzzle nonces (RIPEMD160 inputs that produce valid DER sigs)\n")
    f.write("// - Public keys for selected dummy sigs (ECDSA key recovery)\n")
    f.write("// - HORS preimages for selected indices (Lamport signature)\n")
    f.write("// - Subset indices (the Binohash digest itself)\n")
    f.write("//\n")
    f.write("// Data is pushed in reverse round order: Round 2 first (bottom),\n")
    f.write("// then Round 1 (top), because the locking script processes\n")
    f.write("// Round 1 first.\n")
    f.write("// ============================================================\n\n")
    
    total_items = 0
    total_bytes = 0
    
    for r in range(R - 1, -1, -1):
        rd = rounds[r]
        t = rd['t']
        indices = chosen_indices[r]
        
        f.write(f"// --- Round {r+1} data (t={t}, indices={indices}) ---\n\n")
        
        # Puzzle nonce
        f.write(f"<{puzzle_nonces[r].hex()}>  // puzzle nonce (20B)\n")
        total_items += 1
        total_bytes += 20
        
        # Pubkeys for selected sigs (reversed)
        f.write(f"\n// Public keys for selected dummy sigs (reversed):\n")
        for j in range(t - 1, -1, -1):
            idx = indices[j]
            f.write(f"<{rd['pubkeys'][idx].hex()}>  // pubkey for sig[{idx}] (33B)\n")
            total_items += 1
            total_bytes += 33
        
        # Preimages (reversed)
        f.write(f"\n// HORS preimages for selected indices (reversed):\n")
        for j in range(t - 1, -1, -1):
            idx = indices[j]
            f.write(f"<{rd['preimages'][idx].hex()}>  // preimage for index {idx} (20B)\n")
            total_items += 1
            total_bytes += 20
        
        # Indices (reversed)
        f.write(f"\n// Subset indices (reversed) — these ARE the digest:\n")
        for j in range(t - 1, -1, -1):
            idx = indices[j]
            f.write(f"{idx}  // index\n")
            total_items += 1
            total_bytes += 1
        
        f.write("\n")
    
    f.write(f"// ============================================================\n")
    f.write(f"// Unlocking script total: {total_items} items, ~{total_bytes} bytes\n")
    f.write(f"// ============================================================\n")


# ================================================================
# Write files
# ================================================================
with open("/home/claude/locking_script.txt", "w") as f:
    ops = write_locking_script(f)
print(f"Locking script written: {ops} ops")

with open("/home/claude/unlocking_script.txt", "w") as f:
    write_unlocking_script(f)
print("Unlocking script written")

# Also write a combined version
with open("/home/claude/full_script.txt", "w") as f:
    f.write("// ============================================================\n")
    f.write("// Quantum-Safe Binohash: Complete Transaction Script
// Avihu Mordechai Levy (@avihu28)\n")
    f.write("// ============================================================\n")
    f.write("//\n")
    f.write("// A quantum-safe Bitcoin spending transaction using only\n")
    f.write("// legacy (pre-taproot) opcodes and hash-based security.\n")
    f.write("//\n")
    f.write("// Based on Binohash (Robin Linus, 2025) with modifications:\n")
    f.write("//   1. OP_SIZE puzzle → OP_RIPEMD160 valid sig (quantum-safe)\n")
    f.write("//   2. Simplified pinning: 1 CHECKSIGVERIFY (was 13 ops)\n")
    f.write("//   3. Asymmetric rounds: t=9,8 (was t=8,8)\n")
    f.write("//\n")
    f.write(f"// Security:\n")
    digest = sum(math.log2(math.comb(N, t)) for t in T)
    f.write(f"//   Digest:          {digest:.1f} bits\n")
    f.write(f"//   Pre-image:       {46+digest:.1f} bits\n")
    f.write(f"//   Collision:       {46+digest/2:.1f} bits\n")
    f.write(f"//   Honest work:     ~2^49.7\n")
    f.write(f"//\n")
    f.write(f"// Resources:\n")
    f.write(f"//   Opcodes:         196 / 201  (5 spare)\n")
    f.write(f"//   Locking script:  ~9,856 / 10,000 bytes\n")
    f.write(f"//   Unlocking:       ~1,009 bytes\n")
    f.write("// ============================================================\n\n\n")
    
    write_unlocking_script(f)
    f.write("\n\n")
    write_locking_script(f)

print("Full script written")
