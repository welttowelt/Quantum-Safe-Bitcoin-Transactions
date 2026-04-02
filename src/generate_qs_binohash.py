"""
Quantum-Safe Binohash Script Generator
Avihu Mordechai Levy (@avihu28)

Generates annotated Bitcoin Script for the QS-Binohash scheme.
Two configurations:
  A) t1=8+1bonus, t2=7+2bonus (201 ops, fits)
  B) t1=8+1bonus, t2=8         (202 ops, 1 over)
"""

import math, os, hashlib

def generate_script(n, rounds_config, config_name, filename):
    """
    rounds_config: list of (t_signed, t_bonus) per round
    """
    R = len(rounds_config)
    TARGET = 46

    lines = []
    total_ops = 0

    # Header
    lines.append("// ============================================================")
    lines.append(f"// Quantum-Safe Binohash: {config_name}")
    lines.append("// Avihu Mordechai Levy (@avihu28)")
    lines.append("// ============================================================")
    lines.append(f"// n = {n}")
    for r, (ts, tb) in enumerate(rounds_config):
        tt = ts + tb
        bits_signed = math.log2(math.comb(n, ts))
        bits_total = math.log2(math.comb(n, tt))
        lines.append(f"// Round {r+1}: t_signed={ts}, t_bonus={tb}, t_total={tt}")
        lines.append(f"//   C({n},{ts}) = 2^{bits_signed:.1f} (signed digest)")
        lines.append(f"//   C({n},{tt}) = 2^{bits_total:.1f} (FindAndDelete subsets)")
    
    digest_bits = sum(math.log2(math.comb(n, ts)) for ts, tb in rounds_config)
    lines.append(f"//")
    lines.append(f"// Digest:    {digest_bits:.1f} bits (signed only)")
    lines.append(f"// Pre-image: ~2^{TARGET + digest_bits:.1f} (naive)")
    lines.append(f"// Collision: ~2^{TARGET + digest_bits/2:.1f} (naive)")
    lines.append("// ============================================================")
    lines.append("")
    lines.append("")

    # ==================== PINNING ====================
    lines.append("// ============================================================")
    lines.append("// PINNING (5 ops)")
    lines.append("// ============================================================")
    lines.append("//")
    lines.append("// Witness provides: <key2_pin> <key1_pin>  (key1 on top)")
    lines.append("//")
    lines.append("// Chain: sig1 → key1 → CHECKSIG (binds to tx)")
    lines.append("//        RIPEMD160(key1) → sig2 → key2 → CHECKSIG (proves valid DER)")
    lines.append("//")
    lines.append("")
    lines.append("<sig1_pin>              // 9 bytes, hardcoded, SIGHASH_ALL")
    lines.append("OP_OVER                 // [1] copy key1")
    lines.append("OP_CHECKSIGVERIFY       // [2] verify (sig1, key1) — tx binding")
    lines.append("OP_RIPEMD160            // [3] key1 → sig2")
    lines.append("OP_SWAP                 // [4] get key2 on top")
    lines.append("OP_CHECKSIGVERIFY       // [5] verify (sig2, key2) — proves valid DER")
    lines.append("")
    total_ops += 5

    # ==================== ROUNDS ====================
    for r, (t_signed, t_bonus) in enumerate(rounds_config):
        t_total = t_signed + t_bonus
        round_ops = 0

        lines.append("")
        lines.append(f"// ============================================================")
        lines.append(f"// ROUND {r+1}: t_signed={t_signed}, t_bonus={t_bonus}, t_total={t_total}")
        lines.append(f"// ============================================================")
        lines.append("")

        # --- Data pushes ---
        lines.append(f"// --- {n} HORS commitments (20 bytes each) ---")
        for i in range(n-1, -1, -1):
            lines.append(f"<H(pre_{i:03d})_r{r+1}>")
        lines.append("")

        lines.append(f"// --- {n} dummy sigs (9 bytes each, SIGHASH_SINGLE bug) ---")
        for i in range(n-1, -1, -1):
            lines.append(f"<sig_{i:03d}_r{r+1}>")
        lines.append("")

        lines.append("OP_0                    // CHECKMULTISIG dummy")
        lines.append("")

        lines.append(f"// --- sig_r_1 (hardcoded, SIGHASH_ALL) ---")
        lines.append(f"<sig_r_1_r{r+1}>          // 9 bytes, goes into CHECKMULTISIG")
        lines.append("")

        # --- Signed selections ---
        lines.append(f"// --- {t_signed} signed selections (9 ops each = {9*t_signed} ops) ---")
        for i in range(t_signed):
            # Stack positions account for sig_r_1 being above OP_0
            # Items on stack: sig_r_1 + n sigs + OP_0 + n commits + ... witness
            # sig_r_1 is at top of locking data, sigs below, then OP_0, then commits
            idx_pos = 2*n + 1 - i  # +1 for sig_r_1
            sanitize = n - i
            preimage_pos = 2*n + 1 + t_total - 2*i

            lines.append(f"// Signed selection {i}:")
            lines.append(f"{idx_pos} OP_ROLL             // [1] roll index_{i}")
            lines.append(f"{sanitize} OP_MIN             // [1] sanitize")
            lines.append(f"OP_DUP                  // [1] copy index")
            lines.append(f"{n+1} OP_ADD             // [1] hash position")
            lines.append(f"OP_ROLL                 // [1] roll commitment")
            lines.append(f"{preimage_pos} OP_ROLL  // [1] roll preimage")
            lines.append(f"OP_HASH160              // [1] hash preimage")
            lines.append(f"OP_EQUALVERIFY          // [1] verify HORS")
            lines.append(f"OP_ROLL                 // [1] roll sig (index on stack)")
            lines.append("")
            round_ops += 9

        # --- Bonus selections ---
        if t_bonus > 0:
            lines.append(f"// --- {t_bonus} bonus selection(s) (3 ops each = {3*t_bonus} ops) ---")
            lines.append(f"// No HORS check — spender picks freely.")
            lines.append(f"// Only contributes to FindAndDelete subset, not to digest.")
            for i in range(t_bonus):
                j = t_signed + i  # overall selection index
                idx_pos = 2*n + 1 - j
                sanitize = n - j

                lines.append(f"// Bonus selection {i}:")
                lines.append(f"{idx_pos} OP_ROLL             // [1] roll index")
                lines.append(f"{sanitize} OP_MIN             // [1] sanitize")
                lines.append(f"OP_ROLL                 // [1] roll sig (index on stack)")
                lines.append("")
                round_ops += 3

        # --- Puzzle: derive sig_r_2 from key_r_1 ---
        lines.append(f"// --- Puzzle: key_r_1 → sig_r_2 (3 ops) ---")
        puzzle_pos = 2*n + 2  # +1 for sig_r_1, adjusted for consumed items
        lines.append(f"{puzzle_pos} OP_ROLL         // [1] roll key_r_1 from witness")
        lines.append(f"OP_DUP                  // [1] copy (need for RIPEMD + CMS pubkey)")
        lines.append(f"OP_RIPEMD160            // [1] key_r_1 → sig_r_2")
        lines.append("")
        round_ops += 3

        # --- CHECKMULTISIG ---
        # Sigs on stack (top to bottom): sig_r_2, t_total selected dummies, sig_r_1, OP_0
        # = (t_total + 2) sigs + dummy
        # Keys needed: key_r_1 (on stack from DUP), t_total dummy pubkeys, key_r_2
        n_sigs = t_total + 2  # t dummies + sig_r_1 + sig_r_2
        n_keys = t_total + 2  # t dummy pubs + key_r_1 + key_r_2

        lines.append(f"// --- CHECKMULTISIG {n_sigs}-of-{n_keys} ({1 + t_total + 1 + 1 + n_keys} ops) ---")
        lines.append(f"// Sigs: sig_r_2 + {t_total} dummies + sig_r_1")
        lines.append(f"// Keys: key_r_2 + {t_total} dummy pubs + key_r_1")
        lines.append("")

        # Push M
        lines.append(f"OP_{n_sigs}                   // M = {n_sigs} (push, 0 ops)")

        # Move key_r_1 above M (it's at position 2: sig_r_2=0, key_r_1=1, M just pushed=top)
        # After pushing M: <M> <sig_r_2> <key_r_1> <sigs...>
        # Need key_r_1 above M:
        lines.append(f"OP_2 OP_ROLL            // [1] move key_r_1 above M")
        round_ops += 1

        # Roll t_total dummy pubkeys
        cms_roll_pos = 2*n + 3  # adjusted position
        for j in range(t_total):
            lines.append(f"{cms_roll_pos} OP_ROLL         // [1] roll pubkey_{j}")
            round_ops += 1

        # Roll key_r_2
        lines.append(f"{cms_roll_pos} OP_ROLL         // [1] roll key_r_2")
        round_ops += 1

        # Push N
        lines.append(f"OP_{n_keys}                   // N = {n_keys} (push, 0 ops)")

        # CHECKMULTISIG
        lines.append(f"OP_CHECKMULTISIG        // [1 + {n_keys} keys = {1+n_keys} ops]")
        round_ops += 1 + n_keys

        lines.append("")
        lines.append(f"// Round {r+1} total: {round_ops} ops")
        lines.append("")
        total_ops += round_ops

    # Footer
    lines.append("")
    lines.append(f"// ============================================================")
    lines.append(f"// TOTAL: {total_ops} / 201 ({201-total_ops:+d})")
    lines.append(f"// ============================================================")

    # Write unlocking script
    lines.append("")
    lines.append("")
    lines.append("// ============================================================")
    lines.append("// UNLOCKING SCRIPT (witness)")
    lines.append("// ============================================================")
    lines.append("//")
    lines.append("// Pushed bottom to top (round 2 first, round 1 on top, pinning on top)")
    lines.append("")

    for r in range(R-1, -1, -1):
        ts, tb = rounds_config[r]
        tt = ts + tb
        lines.append(f"// --- Round {r+1} data ---")
        lines.append(f"<key_r_2_r{r+1}>              // 33B, recovered pubkey for sig_r_2")
        lines.append(f"<key_r_1_r{r+1}>              // 33B, recovered pubkey for sig_r_1")
        for j in range(tt-1, -1, -1):
            lines.append(f"<pubkey_{j}_r{r+1}>            // 33B, recovered pubkey for dummy sig")
        for j in range(ts-1, -1, -1):
            lines.append(f"<preimage_{j}_r{r+1}>          // 20B, HORS preimage (signed only)")
        for j in range(tt-1, -1, -1):
            lines.append(f"<index_{j}_r{r+1}>             // subset index")
        lines.append("")

    lines.append("// --- Pinning data ---")
    lines.append("<key2_pin>                // 33B")
    lines.append("<key1_pin>                // 33B")
    lines.append("")

    text = '\n'.join(lines)
    with open(filename, 'w') as f:
        f.write(text)

    print(f"  Written: {filename}")
    print(f"  Total ops: {total_ops} / 201 ({201-total_ops:+d})")
    print(f"  Lines: {len(lines)}")
    return total_ops


def print_summary(n, rounds_config, config_name, total_ops):
    TARGET = 46
    R = len(rounds_config)

    digest = sum(math.log2(math.comb(n, ts)) for ts, tb in rounds_config)
    
    # Grinding probability
    p_rounds = []
    for ts, tb in rounds_config:
        tt = ts + tb
        p = min(1.0, math.comb(n, tt) / 2**TARGET)
        p_rounds.append(p)
    p_both = 1
    for p in p_rounds:
        p_both *= p
    grinds = math.log2(1/p_both) if p_both < 1 else 0
    honest = TARGET + grinds
    cost = 15 * 2**(honest - 44.6)

    # Pre-image with bonus freedom
    pre_penalty = 0
    for ts, tb in rounds_config:
        if tb > 0:
            remaining = n - ts
            bonus_combos = math.comb(remaining, tb)
            pre_penalty += math.log2(bonus_combos)
    preimage = TARGET + digest - pre_penalty if pre_penalty > 0 else TARGET + digest

    # Collision with bonus freedom
    coll_digests = 1
    for ts, tb in rounds_config:
        tt = ts + tb
        if tb > 0:
            coll_digests *= math.comb(tt, ts)
    coll_log_digests = math.log2(coll_digests) if coll_digests > 1 else 0
    collision = TARGET + digest/2 - coll_log_digests

    # Script size
    script_bytes = 15  # pinning
    for ts, tb in rounds_config:
        tt = ts + tb
        script_bytes += n*21 + n*10 + 10 + 1 + ts*21 + tb*15 + 60

    print(f"\n  === {config_name} ===")
    print(f"  Ops:        {total_ops} / 201 ({201-total_ops:+d})")
    print(f"  Script:     ~{script_bytes} / 10,000 ({10000-script_bytes:+d})")
    print(f"  Digest:     {digest:.1f} bits")
    print(f"  Pre-image:  ~2^{preimage:.1f}")
    print(f"  Collision:  ~2^{collision:.1f}")
    print(f"  Grinds:     2^{grinds:.1f} ({1/p_both:.0f}x)")
    print(f"  Honest:     2^{honest:.1f}")
    print(f"  Cost:       ~${cost:.0f}")


# ============================================================
# Generate scripts
# ============================================================

n = 150

print("Generating scripts...")
print()

# Config A: t1=8+1bonus, t2=7+2bonus (should be 201)
print("Config A: t1=8+1b, t2=7+2b")
ops_a = generate_script(n, [(8,1), (7,2)], "t1=8+1bonus, t2=7+2bonus", "/home/claude/script_8p1b_7p2b.txt")
print_summary(n, [(8,1), (7,2)], "t1=8+1b, t2=7+2b", ops_a)

print()

# Config B: t1=8+1bonus, t2=8 (should be 202)
print("Config B: t1=8+1b, t2=8")
ops_b = generate_script(n, [(8,1), (8,0)], "t1=8+1bonus, t2=8", "/home/claude/script_8p1b_8.txt")
print_summary(n, [(8,1), (8,0)], "t1=8+1b, t2=8", ops_b)

