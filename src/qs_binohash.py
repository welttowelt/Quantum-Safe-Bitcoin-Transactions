"""
Quantum-Safe Binohash — Full Simulation
Avihu Mordechai Levy (@avihu28)
=========================================
Parameters:
  - Pinning: 1 RIPEMD160 valid sig check with SIGHASH_ALL  
  - Round 1: C(150, 9) FindAndDelete
  - Round 2: C(150, 8) FindAndDelete
  - RIPEMD160 valid sig (P ≈ 2^-46) instead of OP_SIZE puzzle

Following Binohash Appendix B structure exactly.
"""

import os, math, hashlib, struct, random

# ============================================================
# Helpers
# ============================================================
def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    return hashlib.new('ripemd160', data).digest()

def hash160(data):
    return ripemd160(sha256(data))

# ============================================================
# Script representation
# ============================================================
# We represent a script as a list of items:
#   bytes  → data push (auto-prefixed with correct push opcode)
#   int    → opcode
# This lets us count non-push ops precisely and compute script size.

class ScriptBuilder:
    def __init__(self):
        self.items = []
        self.non_push_ops = 0
    
    def push_data(self, data):
        """Push raw bytes (data push — doesn't count toward op limit)."""
        self.items.append(('data', data))
    
    def push_int(self, val):
        """Push small integer (OP_0..OP_16 don't count toward op limit)."""
        if val == 0:
            self.items.append(('smallint', 0x00))
        elif 1 <= val <= 16:
            self.items.append(('smallint', 0x51 + val - 1))
        else:
            # Encode as data push (still doesn't count as op)
            if val < 0:
                raise ValueError("Negative not supported")
            result = []
            v = val
            while v > 0:
                result.append(v & 0xff)
                v >>= 8
            if result[-1] & 0x80:
                result.append(0)
            self.items.append(('data', bytes(result)))
    
    def op(self, opcode):
        """Add an opcode (counts toward 201 limit if > OP_16)."""
        self.items.append(('op', opcode))
        if opcode > 0x60:  # > OP_16
            self.non_push_ops += 1
    
    def op_checkmultisig(self, n_keys):
        """CHECKMULTISIG — counts 1 + n_keys toward op limit."""
        self.items.append(('op', 0xae))
        self.non_push_ops += 1 + n_keys
    
    def serialize(self):
        """Serialize to raw script bytes."""
        out = bytearray()
        for kind, val in self.items:
            if kind == 'data':
                n = len(val)
                if n <= 75:
                    out.append(n)
                elif n <= 255:
                    out += bytes([0x4c, n])
                else:
                    out += bytes([0x4d]) + struct.pack('<H', n)
                out += val
            elif kind == 'smallint':
                out.append(val)
            elif kind == 'op':
                out.append(val)
        return bytes(out)


# ============================================================
# Opcodes
# ============================================================
OP_0 = 0x00
OP_ROLL = 0x7a
OP_MIN = 0xa3
OP_DUP = 0x76
OP_ADD = 0x93
OP_HASH160 = 0xa9
OP_RIPEMD160 = 0xa6
OP_EQUALVERIFY = 0x88
OP_CHECKSIGVERIFY = 0xad
OP_CHECKMULTISIG = 0xae

# ============================================================
# Parameters
# ============================================================
N = 150
T = [9, 8]  # t per round
R = 2

print("=" * 65)
print("Quantum-Safe Binohash — Full Script Build")
print("=" * 65)
print(f"  n = {N}, rounds = {R}")
for r in range(R):
    b = math.log2(math.comb(N, T[r]))
    print(f"  Round {r+1}: t = {T[r]}, C({N},{T[r]}) = 2^{b:.1f}")
digest_bits = sum(math.log2(math.comb(N, t)) for t in T)
print(f"  Total digest: {digest_bits:.1f} bits")
print(f"  Pre-image: {46 + digest_bits:.1f} bits")
print(f"  Collision: {46 + digest_bits/2:.1f} bits")
print()

# ============================================================
# Generate per-round data
# ============================================================
# Each round has:
#   - n dummy 9-byte sigs (hardcoded in locking script)
#   - n HORS preimages (secret, used for signing)
#   - n HORS commitments = hash160(preimage) (in locking script)
#   - n derived pubkeys (from ECDSA key recovery on dummy sigs)

rounds = []
for r in range(R):
    # Dummy sigs: minimal 9-byte DER with SIGHASH_SINGLE (0x03)
    # Using SIGHASH_SINGLE bug: z=1 for all, so they're tx-independent
    sigs = []
    for i in range(N):
        r_val = (i * 3 + r * 7 + 1) % 127 + 1  # 1..127
        s_val = (i * 11 + r * 13 + 1) % 127 + 1
        sig = bytes([0x30, 0x07, 0x02, 0x01, r_val, 0x02, 0x01, s_val, 0x03])
        sigs.append(sig)
    
    # HORS preimages and commitments
    preimages = [os.urandom(20) for _ in range(N)]
    commitments = [hash160(p) for p in preimages]
    
    # Pubkeys for the dummy sigs (derived via ECDSA key recovery)
    # In real implementation: recover_pubkey(sig, z=1) for each
    # For simulation: placeholder 33-byte compressed pubkeys
    pubkeys = [os.urandom(33) for _ in range(N)]
    
    rounds.append({
        't': T[r],
        'sigs': sigs,
        'preimages': preimages,
        'commitments': commitments,
        'pubkeys': pubkeys,
    })

# ============================================================
# Pinning: single SIGHASH_ALL sig
# ============================================================
# Hardcoded 9-byte sig with SIGHASH_ALL (0x01)
# Derived pubkey pins to entire transaction
pinning_sig = bytes([0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01])
pinning_pubkey = os.urandom(33)

# ============================================================
# Simulate: choose subset indices for each round
# ============================================================
random.seed(42)
chosen_indices = []
for r in range(R):
    indices = sorted(random.sample(range(N), T[r]))
    chosen_indices.append(indices)
    print(f"Round {r+1} chosen indices: {indices}")

# Puzzle nonces: in real implementation, grind RIPEMD160 for valid DER
# For simulation: placeholder 20-byte nonces
puzzle_nonces = [os.urandom(20) for _ in range(R)]
# The "puzzle sig" is RIPEMD160(nonce) — would be valid DER after grinding
puzzle_sigs = [ripemd160(nonce) for nonce in puzzle_nonces]
# Puzzle pubkeys derived via ECDSA key recovery from (puzzle_sig, sighash)
puzzle_pubkeys = [os.urandom(33) for _ in range(R)]

print()

# ============================================================
# BUILD LOCKING SCRIPT
# ============================================================
print("--- Building Locking Script ---")
print()

ls = ScriptBuilder()

# --- Pinning ---
ls.push_data(pinning_sig)
ls.push_data(pinning_pubkey)
ls.op(OP_CHECKSIGVERIFY)
pin_ops = ls.non_push_ops
print(f"Pinning: {pin_ops} ops")

# --- Rounds ---
for r in range(R):
    rd = rounds[r]
    t = rd['t']
    round_start = ls.non_push_ops
    
    # Push HORS commitments in reverse order (so index 0 = top)
    for i in range(N - 1, -1, -1):
        ls.push_data(rd['commitments'][i])
    
    # Push dummy sigs in reverse order (so index 0 = top)
    for i in range(N - 1, -1, -1):
        ls.push_data(rd['sigs'][i])
    
    # OP_0 dummy element for CHECKMULTISIG bug
    ls.push_int(0)
    
    # For each of t selections (following Binohash Appendix B exactly):
    for i in range(t):
        # Move <index_i> to top of the stack
        ls.push_int(2 * N - i)
        ls.op(OP_ROLL)
        
        # Sanitize <index_i> to prevent out-of-bound reads
        ls.push_int(N - i)
        ls.op(OP_MIN)
        
        # Copy index
        ls.op(OP_DUP)
        
        # Move hash[index_i] to top: index + offset
        ls.push_int(N + 1)
        ls.op(OP_ADD)
        ls.op(OP_ROLL)
        
        # Move <preimage_i> to top of stack
        ls.push_int(2 * N + t - 2 * i)
        ls.op(OP_ROLL)
        
        # Hash the preimage and verify
        ls.op(OP_HASH160)
        ls.op(OP_EQUALVERIFY)
        
        # Move <signature[index_i]> to top (index is still on stack)
        ls.op(OP_ROLL)
    
    # Move puzzle nonce to top and convert to sig via RIPEMD160
    ls.push_int(2 * N + 1)
    ls.op(OP_ROLL)
    ls.op(OP_RIPEMD160)  # nonce → puzzle sig (valid DER after grinding)
    
    # Setup CHECKMULTISIG: (t+1) signatures with (t+1) pubkeys
    ls.push_int(t + 1)  # M = t+1 signatures
    
    # Move t pubkeys from unlocking script to top
    for _ in range(t):
        ls.push_int(2 * N + 2)
        ls.op(OP_ROLL)
    
    # Push puzzle pubkey (derived from puzzle sig + sighash)
    ls.push_data(puzzle_pubkeys[r])
    
    # N = t+1 public keys
    ls.push_int(t + 1)
    
    # CHECKMULTISIG (counts t+1 keys toward op limit)
    ls.op_checkmultisig(t + 1)
    
    round_ops = ls.non_push_ops - round_start
    print(f"Round {r+1} (t={t}): {round_ops} ops (formula: 11*{t}+4 = {11*t+4})")

total_ops = ls.non_push_ops
script_bytes = ls.serialize()
total_size = len(script_bytes)

print()
print(f"LOCKING SCRIPT:")
print(f"  Non-push opcodes: {total_ops} / 201 ({201-total_ops:+d} spare)")
print(f"  Script size: {total_size:,} / 10,000 ({10000-total_size:+d} spare)")

# ============================================================
# BUILD UNLOCKING SCRIPT
# ============================================================
print()
print("--- Building Unlocking Script ---")
print()

us = ScriptBuilder()

# Unlocking script is read bottom-to-top.
# For each round (in reverse: round 2 first, round 1 second):
# Because the locking script processes round 1 first,
# the round 1 unlocking data must be on top.

# Actually: locking processes round 1 first, expecting its data on top.
# So unlocking pushes: round 2 data (bottom), then round 1 data (top).

for r in range(R - 1, -1, -1):  # reverse order
    rd = rounds[r]
    t = rd['t']
    indices = chosen_indices[r]
    
    # Per round, unlocking provides (from Appendix B):
    # <puzzle_nonce>
    # <pubkey_t> ... <pubkey_1> (pubkeys for selected dummy sigs, reverse)
    # <preimage_t> ... <preimage_1> (HORS preimages, reverse)
    # <index_t> ... <index_1> (subset indices, reverse)
    
    # Push puzzle nonce
    us.push_data(puzzle_nonces[r])
    
    # Push pubkeys for selected dummy sigs (reverse order)
    for idx in reversed(indices):
        us.push_data(rd['pubkeys'][idx])
    
    # Push HORS preimages for selected indices (reverse order)
    for idx in reversed(indices):
        us.push_data(rd['preimages'][idx])
    
    # Push indices (reverse order)
    for idx in reversed(indices):
        us.push_int(idx)

# Pinning sig is already in the locking script (hardcoded)
# So unlocking script is just the round data

unlock_bytes = us.serialize()
unlock_size = len(unlock_bytes)

items_per_round = [1 + T[r] + T[r] + T[r] for r in range(R)]  # nonce + pubkeys + preimages + indices
total_items = sum(items_per_round)

print(f"UNLOCKING SCRIPT:")
print(f"  Size: {unlock_size:,} bytes")
print(f"  Items: {total_items} ({'+'.join(str(x) for x in items_per_round)} per round)")

# ============================================================
# SUMMARY
# ============================================================
print()
print("=" * 65)
print("SUMMARY")
print("=" * 65)
print()

# Security
digest = sum(math.log2(math.comb(N, t)) for t in T)
preimage = 46 + digest
collision = 46 + digest / 2

# Honest work
p_rounds = []
for t in T:
    p = min(1.0, math.comb(N, t) / 2**46)
    p_rounds.append(p)
p_both = 1
for p in p_rounds:
    p_both *= p
grinds = math.log2(1/p_both) if p_both < 1 else 0
honest_work = 46 + grinds

print(f"Parameters:")
print(f"  n = {N}, t = {T}, R = {R}")
print(f"  Round 1: C({N},{T[0]}) = 2^{math.log2(math.comb(N,T[0])):.1f}")
print(f"  Round 2: C({N},{T[1]}) = 2^{math.log2(math.comb(N,T[1])):.1f}")
print()
print(f"Security:")
print(f"  Digest:          {digest:.1f} bits")
print(f"  Pre-image:       {preimage:.1f} bits")
print(f"  Collision:       {collision:.1f} bits")
print()
print(f"Cost:")
print(f"  P(round 1 hit):  {p_rounds[0]:.4f}")
print(f"  P(round 2 hit):  {p_rounds[1]:.4f}")
print(f"  Tx grinds:       2^{grinds:.1f} ({1/p_both:.0f}x)")
print(f"  Honest work:     2^{honest_work:.1f}")
print()
print(f"Script:")
print(f"  Locking ops:     {total_ops} / 201 ({201-total_ops:+d} spare)")
print(f"  Locking size:    {total_size:,} / 10,000 ({10000-total_size:+d} spare)")
print(f"  Unlocking size:  {unlock_size:,} bytes")
print(f"  Total tx weight: ~{total_size + unlock_size:,} bytes (rough)")

# ============================================================
# PRINT HUMAN-READABLE BITCOIN SCRIPT
# ============================================================

OP_NAMES = {
    0x00: "OP_0", 0x76: "OP_DUP", 0x7c: "OP_SWAP", 0x7a: "OP_ROLL",
    0x79: "OP_PICK", 0x75: "OP_DROP", 0x6d: "OP_2DROP", 0x7b: "OP_ROT",
    0x78: "OP_OVER", 0x63: "OP_IF", 0x67: "OP_ELSE", 0x68: "OP_ENDIF",
    0x87: "OP_EQUAL", 0x88: "OP_EQUALVERIFY", 0x93: "OP_ADD",
    0xa3: "OP_MIN", 0xa6: "OP_RIPEMD160", 0xa8: "OP_SHA256",
    0xa9: "OP_HASH160", 0xaa: "OP_HASH256", 0xa7: "OP_SHA1",
    0xac: "OP_CHECKSIG", 0xad: "OP_CHECKSIGVERIFY",
    0xae: "OP_CHECKMULTISIG", 0xaf: "OP_CHECKMULTISIGVERIFY",
    0x6b: "OP_TOALTSTACK", 0x6c: "OP_FROMALTSTACK",
    0x82: "OP_SIZE", 0xab: "OP_CODESEPARATOR",
}
for i in range(1, 17):
    OP_NAMES[0x50 + i] = f"OP_{i}"

def script_to_asm(builder):
    """Convert ScriptBuilder items to human-readable ASM."""
    lines = []
    for kind, val in builder.items:
        if kind == 'data':
            if len(val) <= 4:
                lines.append(f"<{val.hex()}>")
            else:
                lines.append(f"<{val.hex()[:16]}..>  // {len(val)}B")
        elif kind == 'smallint':
            if val == 0x00:
                lines.append("OP_0")
            else:
                lines.append(f"OP_{val - 0x50}")
        elif kind == 'op':
            lines.append(OP_NAMES.get(val, f"0x{val:02x}"))
    return lines

print()
print("=" * 65)
print("LOCKING SCRIPT (ASM)")
print("=" * 65)
print()

# Rebuild with annotations
def print_annotated_script():
    """Print the locking script with section annotations."""
    
    # We'll rebuild the script and annotate as we go
    print("//")
    print("// Unlocking Script (provided by spender)")
    print("//")
    print()
    
    for r in range(R - 1, -1, -1):
        t = T[r]
        idx = chosen_indices[r]
        print(f"// --- Round {r+1} data ---")
        print(f"<puzzle_nonce_{r+1}>                // 20 bytes: RIPEMD160 input")
        for j in range(t-1, -1, -1):
            print(f"<pubkey_r{r+1}_{j}>                  // 33 bytes: recovered pubkey for sig[{idx[j]}]")
        for j in range(t-1, -1, -1):
            print(f"<preimage_r{r+1}_{j}>                // 20 bytes: HORS preimage for index {idx[j]}")
        for j in range(t-1, -1, -1):
            print(f"<index_r{r+1}_{j}>                   // index = {idx[j]}")
        print()
    
    print()
    print("//")
    print("// Locking Script")
    print("//")
    print()
    
    # Pinning
    print("// ============================================")
    print("// Stage 1: Transaction Pinning (1 op)")
    print("// ============================================")
    print("// Hardcoded 9-byte sig with SIGHASH_ALL pins entire tx.")
    print("// Pubkey derived via ECDSA key recovery from (sig, sighash).")
    print("// Quantum-safe: validity depends on RIPEMD160, not EC.")
    print()
    print("<pinning_sig>                        // 9 bytes, SIGHASH_ALL")
    print("<pinning_pubkey>                     // 33 bytes, derived")
    print("OP_CHECKSIGVERIFY                    // 1 op — pins transaction")
    print()
    
    for r in range(R):
        t = T[r]
        rd = rounds[r]
        
        print(f"// ============================================")
        print(f"// Stage 2, Round {r+1}: FindAndDelete (t={t})")
        print(f"// C({N},{t}) = 2^{math.log2(math.comb(N,t)):.1f} subsets")
        print(f"// Ops: 11*{t} + 4 = {11*t+4}")
        print(f"// ============================================")
        print()
        
        # Push HORS commitments
        print(f"// Push {N} HORS commitments (reversed)")
        print(f"// Each: HASH160(preimage_i), 20 bytes")
        for i in range(N - 1, -1, -1):
            if i == N-1:
                print(f"<H(pre_{N-1})>                       // commitment[{N-1}] (20B)")
            elif i == N-2:
                print(f"<H(pre_{N-2})>                       // ...")
            elif i == 1:
                print(f"<H(pre_1)>")
            elif i == 0:
                print(f"<H(pre_0)>                           // commitment[0] (20B)")
            # skip middle for brevity
        print(f"// ... ({N} commitments total)")
        print()
        
        # Push dummy sigs
        print(f"// Push {N} dummy signatures (reversed)")
        print(f"// Each: 9-byte minimal DER with SIGHASH_SINGLE (z=1 bug)")
        for i in range(N - 1, -1, -1):
            if i == N-1:
                print(f"<sig_{N-1}>                          // 9 bytes, dummy sig")
            elif i == 0:
                print(f"<sig_0>                              // 9 bytes, dummy sig")
        print(f"// ... ({N} dummy sigs total)")
        print()
        
        print("OP_0                                 // CHECKMULTISIG bug dummy")
        print()
        
        # t selection iterations
        print(f"// --- {t} selection iterations ---")
        for i in range(t):
            print(f"// Selection {i}:")
            print(f"{2*N - i} OP_ROLL                       // move index_{i} to top")
            print(f"{N - i} OP_MIN                          // sanitize index")
            print(f"OP_DUP                               // copy index for hash lookup")
            print(f"{N + 1} OP_ADD                         // compute hash position")
            print(f"OP_ROLL                              // roll hash[index_{i}] to top")
            print(f"{2*N + t - 2*i} OP_ROLL              // roll preimage_{i} to top")
            print(f"OP_HASH160                           // hash preimage")
            print(f"OP_EQUALVERIFY                       // verify against commitment")
            print(f"OP_ROLL                              // roll sig[index_{i}] (using index on stack)")
            print()
        
        # Puzzle nonce → sig
        print(f"// Puzzle: RIPEMD160 valid sig check")
        print(f"{2*N + 1} OP_ROLL                       // move puzzle nonce to top")
        print(f"OP_RIPEMD160                         // nonce → valid DER sig (after grinding)")
        print()
        
        # CHECKMULTISIG setup
        print(f"// CHECKMULTISIG: {t+1}-of-{t+1}")
        print(f"OP_{t+1}                              // M = {t+1} signatures")
        for j in range(t):
            print(f"{2*N + 2} OP_ROLL                   // move pubkey_{j} to top")
        print(f"<puzzle_pubkey_r{r+1}>                 // 33 bytes, derived from puzzle sig")
        print(f"OP_{t+1}                              // N = {t+1} pubkeys")
        print(f"OP_CHECKMULTISIG                     // verify all {t+1} sigs")
        print()
    
    print("// Script ends. Stack has: [round2_result, round1_result]")
    print("// Both must be truthy (1). CLEANSTACK not enforced in legacy.")


print_annotated_script()

# ============================================================
# COMPACT SCRIPT LISTING
# ============================================================
print()
print()
print("=" * 65)
print("LOCKING SCRIPT (compact)")
print("=" * 65)
print()

asm = script_to_asm(ls)
# Print compactly with wrapping
line = ""
for i, item in enumerate(asm):
    if len(line) + len(item) > 80:
        print(line)
        line = item
    else:
        if line:
            line += " "
        line += item
if line:
    print(line)

# ============================================================
# OPCODE COUNT VERIFICATION
# ============================================================
print()
print()
print("=" * 65)
print("OPCODE COUNT BREAKDOWN")
print("=" * 65)
print()

# Count by category
op_counts = {}
for kind, val in ls.items:
    if kind == 'op':
        name = OP_NAMES.get(val, f"0x{val:02x}")
        op_counts[name] = op_counts.get(name, 0) + 1

print(f"{'Opcode':<25} {'Count':>5} {'Per-op':>7} {'Total':>7}")
print("-" * 47)
total_verified = 0
for name, count in sorted(op_counts.items(), key=lambda x: -x[1]):
    # Does this opcode count toward limit?
    is_counted = True  # all ops > OP_16 count
    per_op = 1
    if name == "OP_CHECKMULTISIG":
        # Each CHECKMULTISIG counted its keys separately in our builder
        per_op = 1  # the base op (keys counted separately in builder)
    total = count * per_op
    total_verified += total
    print(f"{name:<25} {count:>5} × {per_op:>5} = {total:>5}")

print("-" * 47)
print(f"{'CHECKMULTISIG key pushes':<25} {'':>5} {'':>7} {sum(T[r]+1 for r in range(R)):>5}")
print(f"{'TOTAL':<25} {'':>5} {'':>7} {ls.non_push_ops:>5}")
print()
print(f"Budget: {ls.non_push_ops} / 201 ({201 - ls.non_push_ops:+d} spare)")

