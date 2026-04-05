#!/usr/bin/env python3
"""
QSB Benchmark & Graduated Tests
================================
Run this on vast.ai to measure actual per-candidate costs
and extrapolate to real mode.

Usage:
  python3 benchmark.py              # Full benchmark suite
  python3 benchmark.py --bench-only # Just measure speeds
  python3 benchmark.py --test-only  # Just run graduated tests
"""

import os
import sys
import time
import math
import hashlib
import itertools
import argparse
import json

# Try fast module first
try:
    from secp256k1_fast import (
        sha256d, ripemd160, hash160,
        compress_pubkey, point_mul, point_add, G, N, P, B,
        ecdsa_sign, ecdsa_recover, ecdsa_recover_compressed,
        encode_der_sig, is_valid_der_sig, modinv,
    )
    FAST = True
except ImportError:
    from secp256k1 import (
        sha256d, ripemd160, hash160,
        compress_pubkey, point_mul, point_add, G, N, P, B,
        ecdsa_sign, ecdsa_recover, encode_der_sig, is_valid_der_sig, modinv,
    )
    FAST = False
    def ecdsa_recover_compressed(r, s, z, flag=0):
        pt = ecdsa_recover(r, s, z, flag)
        if pt is None: return None
        return compress_pubkey(pt)

from bitcoin_tx import (
    Transaction, TxIn, TxOut, QSBScriptBuilder,
    push_data, push_number, find_and_delete,
)


def make_fixed_sig(label):
    k = int.from_bytes(hashlib.sha256(f"qsb_{label}".encode()).digest(), 'big') % N
    R_pt = point_mul(k, G)
    r = R_pt[0] % N
    s = max(1, int.from_bytes(hashlib.sha256(f"qsb_{label}_s".encode()).digest()[:4], 'big') % (N // 2))
    return r, s, encode_der_sig(r, s, sighash=0x01)


# ============================================================
# DER checks at various difficulty levels
# ============================================================

def check_1_in_16(data):
    """~1/16: first nibble = 0x3"""
    return len(data) >= 9 and (data[0] >> 4) == 3

def check_1_in_256(data):
    """~1/256: first byte = 0x30"""
    return len(data) >= 9 and data[0] == 0x30

def check_1_in_65536(data):
    """~1/65536: first two bytes = 0x30 0x11"""
    return len(data) >= 9 and data[0] == 0x30 and data[1] == 0x11

def check_real(data):
    """~1/2^46: actual valid DER"""
    return is_valid_der_sig(data)

DIFFICULTIES = {
    '1/16':    (check_1_in_16,    4),
    '1/256':   (check_1_in_256,   8),
    '1/65536': (check_1_in_65536, 16),
    'real':    (check_real,       46),
}


# ============================================================
# Benchmark: measure per-candidate costs
# ============================================================

def run_benchmarks():
    print("=" * 60)
    print("  QSB BENCHMARKS")
    print(f"  Backend: {'coincurve (fast)' if FAST else 'pure Python (SLOW)'}")
    print("=" * 60)

    # 1. Raw EC recovery speed
    print("\n--- EC Recovery ---")
    privkey = int.from_bytes(os.urandom(32), 'big') % N
    z_test = int.from_bytes(hashlib.sha256(b"bench").digest(), 'big')
    r_sig, s_sig = ecdsa_sign(privkey, z_test)

    count = 50000 if FAST else 50
    t0 = time.time()
    for i in range(count):
        z = int.from_bytes(hashlib.sha256(i.to_bytes(4, 'big')).digest(), 'big')
        key = ecdsa_recover_compressed(r_sig, s_sig, z, 0)
    elapsed = time.time() - t0
    ec_rate = count / elapsed
    ec_us = elapsed / count * 1e6
    print(f"  {count} recoveries: {elapsed:.2f}s ({ec_rate:.0f}/s, {ec_us:.1f}μs each)")

    # 2. EC recovery + RIPEMD
    t0 = time.time()
    for i in range(count):
        z = int.from_bytes(hashlib.sha256(i.to_bytes(4, 'big')).digest(), 'big')
        key = ecdsa_recover_compressed(r_sig, s_sig, z, 0)
        if key:
            h = ripemd160(key)
    elapsed = time.time() - t0
    ecr_rate = count / elapsed
    ecr_us = elapsed / count * 1e6
    print(f"  {count} recover+RIPEMD: {elapsed:.2f}s ({ecr_rate:.0f}/s, {ecr_us:.1f}μs each)")

    # 3. Sighash computation at n=150
    print("\n--- Sighash (n=150 script) ---")
    builder = QSBScriptBuilder(n=150, t1_signed=8, t2_signed=8)
    builder.generate_keys()
    pin_r, pin_s, pin_sig = make_fixed_sig("pin")
    r1_r, r1_s, r1_sig = make_fixed_sig("round1")
    r2_r, r2_s, r2_sig = make_fixed_sig("round2")
    full_script = builder.build_full_script(pin_sig, r1_sig, r2_sig)
    round1_script = builder.build_round_script(0, r1_sig)
    round2_script = builder.build_round_script(1, r2_sig)

    fake_txid = hashlib.sha256(b"qsb_funding_utxo_v1").digest()
    tx = Transaction(version=1, locktime=0)
    tx.add_input(TxIn(fake_txid, 0, b'', 0xffffffff))
    tx.add_output(TxOut(49000, b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac'))

    # Pinning sighash (full script)
    sh_count = 5000 if FAST else 100
    t0 = time.time()
    for i in range(sh_count):
        tx.locktime = i
        z = tx.sighash(0, full_script, sighash_type=0x01)
    elapsed = time.time() - t0
    pin_sh_rate = sh_count / elapsed
    pin_sh_us = elapsed / sh_count * 1e6
    print(f"  Pinning sighash ({len(full_script)}B): {pin_sh_rate:.0f}/s ({pin_sh_us:.1f}μs)")

    # Digest sighash (round script + FindAndDelete)
    fad_count = 2000 if FAST else 50
    t0 = time.time()
    for i, subset in enumerate(itertools.combinations(range(150), 9)):
        if i >= fad_count:
            break
        sc = round1_script
        for idx in subset:
            sc = find_and_delete(sc, builder.dummy_sigs[0][idx])
        sc = find_and_delete(sc, r1_sig)
        z = tx.sighash(0, sc, sighash_type=0x01)
    elapsed = time.time() - t0
    dig_rate = fad_count / elapsed
    dig_us = elapsed / fad_count * 1e6
    print(f"  R1 FindAndDelete+sighash: {dig_rate:.0f}/s ({dig_us:.1f}μs)")

    # Round 2
    t0 = time.time()
    for i, subset in enumerate(itertools.combinations(range(150), 9)):
        if i >= fad_count:
            break
        sc = round2_script
        for idx in subset:
            sc = find_and_delete(sc, builder.dummy_sigs[1][idx])
        sc = find_and_delete(sc, r2_sig)
        z = tx.sighash(0, sc, sighash_type=0x01)
    elapsed = time.time() - t0
    dig2_rate = fad_count / elapsed
    dig2_us = elapsed / fad_count * 1e6
    print(f"  R2 FindAndDelete+sighash: {dig2_rate:.0f}/s ({dig2_us:.1f}μs)")

    # 4. Full candidate (FAD + sighash + EC + RIPEMD)
    print("\n--- Full Candidate (n=150, t=9) ---")
    full_count = 1000 if FAST else 20
    t0 = time.time()
    for i, subset in enumerate(itertools.combinations(range(150), 9)):
        if i >= full_count:
            break
        sc = round1_script
        for idx in subset:
            sc = find_and_delete(sc, builder.dummy_sigs[0][idx])
        sc = find_and_delete(sc, r1_sig)
        z = tx.sighash(0, sc, sighash_type=0x01)
        key = ecdsa_recover_compressed(r1_r, r1_s, z, 0)
        if key:
            h = ripemd160(key)
    elapsed = time.time() - t0
    full_rate = full_count / elapsed
    full_us = elapsed / full_count * 1e6
    print(f"  R1 full candidate: {full_rate:.0f}/s ({full_us:.1f}μs)")

    t0 = time.time()
    for i, subset in enumerate(itertools.combinations(range(150), 9)):
        if i >= full_count:
            break
        sc = round2_script
        for idx in subset:
            sc = find_and_delete(sc, builder.dummy_sigs[1][idx])
        sc = find_and_delete(sc, r2_sig)
        z = tx.sighash(0, sc, sighash_type=0x01)
        key = ecdsa_recover_compressed(r2_r, r2_s, z, 0)
        if key:
            h = ripemd160(key)
    elapsed = time.time() - t0
    full2_rate = full_count / elapsed
    full2_us = elapsed / full_count * 1e6
    print(f"  R2 full candidate: {full2_rate:.0f}/s ({full2_us:.1f}μs)")

    # Pinning full candidate
    pin_full_count = 5000 if FAST else 50
    t0 = time.time()
    for i in range(pin_full_count):
        tx.locktime = i
        z = tx.sighash(0, full_script, sighash_type=0x01)
        key = ecdsa_recover_compressed(pin_r, pin_s, z, 0)
        if key:
            h = ripemd160(key)
    elapsed = time.time() - t0
    pin_full_rate = pin_full_count / elapsed
    pin_full_us = elapsed / pin_full_count * 1e6
    print(f"  Pin full candidate: {pin_full_rate:.0f}/s ({pin_full_us:.1f}μs)")

    # 5. Extrapolation
    print("\n" + "=" * 60)
    print("  COST EXTRAPOLATION (Config A: n=150, t=9)")
    print("=" * 60)

    cn9 = math.comb(150, 9)
    target = 2**46

    # Pin: ~1 attempt since C(150,9) > 2^46
    # Each pin: iterate ~2^46 locktimes
    # R1: iterate C(150,9) subsets
    # R2: iterate C(150,9) subsets

    pin_hours = target / pin_full_rate / 3600
    r1_hours = cn9 / full_rate / 3600
    r2_hours = cn9 / full2_rate / 3600
    total_hours = pin_hours + r1_hours + r2_hours

    print(f"\n  Per-candidate rates (this machine):")
    print(f"    Pinning:  {pin_full_rate:.0f}/s ({pin_full_us:.1f}μs)")
    print(f"    Round 1:  {full_rate:.0f}/s ({full_us:.1f}μs)")
    print(f"    Round 2:  {full2_rate:.0f}/s ({full2_us:.1f}μs)")
    print(f"\n  Candidates needed (real mode):")
    print(f"    Pinning:  2^46 = {target:.2e}")
    print(f"    Round 1:  C(150,9) = 2^{math.log2(cn9):.1f} = {cn9:.2e}")
    print(f"    Round 2:  C(150,9) = 2^{math.log2(cn9):.1f} = {cn9:.2e}")
    print(f"\n  Estimated time on THIS machine:")
    print(f"    Pinning:  {pin_hours:.0f} hours")
    print(f"    Round 1:  {r1_hours:.0f} hours")
    print(f"    Round 2:  {r2_hours:.0f} hours")
    print(f"    Total:    {total_hours:.0f} hours ({total_hours/24:.0f} days)")
    print(f"\n  Estimated cost (at $0.15/machine-hr):")
    print(f"    This machine: ${total_hours * 0.15:.0f}")
    for n_machines in [10, 50, 100]:
        wall = total_hours / n_machines
        cost = total_hours * 0.15
        print(f"    {n_machines} machines: {wall:.0f}h wall time, ${cost:.0f} total")

    results = {
        'backend': 'coincurve' if FAST else 'pure_python',
        'ec_recovery_per_sec': ec_rate,
        'ec_recovery_us': ec_us,
        'pin_sighash_per_sec': pin_sh_rate,
        'pin_sighash_us': pin_sh_us,
        'r1_fad_sighash_per_sec': dig_rate,
        'r1_fad_sighash_us': dig_us,
        'r2_fad_sighash_per_sec': dig2_rate,
        'r2_fad_sighash_us': dig2_us,
        'r1_full_candidate_per_sec': full_rate,
        'r1_full_candidate_us': full_us,
        'r2_full_candidate_per_sec': full2_rate,
        'r2_full_candidate_us': full2_us,
        'pin_full_candidate_per_sec': pin_full_rate,
        'pin_full_candidate_us': pin_full_us,
        'estimated_total_hours': total_hours,
        'estimated_cost_usd': total_hours * 0.15,
    }
    return results


# ============================================================
# Graduated tests: run actual searches at various difficulties
# ============================================================

def run_graduated_tests():
    print("\n" + "=" * 60)
    print("  GRADUATED SEARCH TESTS (n=150, t=9, Config A)")
    print(f"  Backend: {'coincurve (fast)' if FAST else 'pure Python (SLOW)'}")
    print("=" * 60)

    # Build the real Config A script
    print("\nBuilding Config A (n=150, t1=8+1b, t2=7+2b)...")
    t0 = time.time()
    builder = QSBScriptBuilder(n=150, t1_signed=8, t1_bonus=1, t2_signed=7, t2_bonus=2)
    builder.generate_keys()
    print(f"  Keys generated: {time.time()-t0:.1f}s")

    pin_r, pin_s, pin_sig = make_fixed_sig("pin")
    r1_r, r1_s, r1_sig = make_fixed_sig("round1")
    r2_r, r2_s, r2_sig = make_fixed_sig("round2")

    full_script = builder.build_full_script(pin_sig, r1_sig, r2_sig)
    round1_script = builder.build_round_script(0, r1_sig)
    round2_script = builder.build_round_script(1, r2_sig)
    print(f"  Script: {len(full_script)}B")

    fake_txid = hashlib.sha256(b"qsb_funding_utxo_v1").digest()
    tx = Transaction(version=1, locktime=0)
    tx.add_input(TxIn(fake_txid, 0, b'', 0xffffffff))
    tx.add_output(TxOut(49000, b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac'))

    round_configs = [
        (8, 1, 9, r1_r, r1_s, r1_sig, round1_script, 0),
        (7, 2, 9, r2_r, r2_s, r2_sig, round2_script, 1),
    ]

    # Test at each difficulty level
    for diff_name in ['1/16', '1/256', '1/65536']:
        check_fn, bits = DIFFICULTIES[diff_name]
        max_time = 120  # seconds per test

        print(f"\n--- Difficulty: {diff_name} (~2^{bits}) ---")

        t_start = time.time()
        locktime_cursor = 0
        pin_attempts = 0
        pin_solutions = 0
        full_solutions = 0
        r2_only_solutions = 0

        while time.time() - t_start < max_time:
            # Pinning
            pin_found = None
            for lt in range(locktime_cursor, locktime_cursor + 10000):
                pin_attempts += 1
                tx.locktime = lt
                z = tx.sighash(0, full_script, sighash_type=0x01)
                for flag in [0, 1]:
                    key = ecdsa_recover_compressed(pin_r, pin_s, z, flag)
                    if key is None: continue
                    sig_puzzle = ripemd160(key)
                    if check_fn(sig_puzzle):
                        pin_found = lt
                        pin_solutions += 1
                        break
                if pin_found is not None:
                    locktime_cursor = lt + 1
                    break
            else:
                locktime_cursor += 10000
                continue

            tx.locktime = pin_found

            # Try Round 2 first (cheaper)
            r2_ok = False
            r2_tried = 0
            for subset in itertools.combinations(range(150), 9):
                r2_tried += 1
                if r2_tried > 50000:  # cap per pin
                    break
                sc = round2_script
                for idx in subset:
                    sc = find_and_delete(sc, builder.dummy_sigs[1][idx])
                sc = find_and_delete(sc, r2_sig)
                z = tx.sighash(0, sc, sighash_type=0x01)
                for flag in [0, 1]:
                    key = ecdsa_recover_compressed(r2_r, r2_s, z, flag)
                    if key is None: continue
                    if check_fn(ripemd160(key)):
                        r2_ok = True
                        break
                if r2_ok: break

            if not r2_ok:
                continue
            r2_only_solutions += 1

            # Try Round 1
            r1_ok = False
            r1_tried = 0
            for subset in itertools.combinations(range(150), 9):
                r1_tried += 1
                if r1_tried > 50000:
                    break
                sc = round1_script
                for idx in subset:
                    sc = find_and_delete(sc, builder.dummy_sigs[0][idx])
                sc = find_and_delete(sc, r1_sig)
                z = tx.sighash(0, sc, sighash_type=0x01)
                for flag in [0, 1]:
                    key = ecdsa_recover_compressed(r1_r, r1_s, z, flag)
                    if key is None: continue
                    if check_fn(ripemd160(key)):
                        r1_ok = True
                        break
                if r1_ok: break

            if r1_ok:
                full_solutions += 1
                elapsed = time.time() - t_start
                print(f"  FULL SOLUTION! locktime={pin_found}, {elapsed:.1f}s")
                print(f"    Pin attempts: {pin_attempts} ({pin_solutions} solutions)")
                print(f"    R2 subsets tried: {r2_tried}")
                print(f"    R1 subsets tried: {r1_tried}")
                break

        elapsed = time.time() - t_start
        if full_solutions == 0:
            print(f"  No full solution in {elapsed:.0f}s")
            print(f"    Pin: {pin_attempts} attempts, {pin_solutions} solutions")
            print(f"    R2-only: {r2_only_solutions}")
            print(f"    Pin rate: {pin_attempts/elapsed:.0f}/s")


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QSB Benchmark")
    parser.add_argument('--bench-only', action='store_true')
    parser.add_argument('--test-only', action='store_true')
    args = parser.parse_args()

    if not args.test_only:
        results = run_benchmarks()
        with open('benchmark_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n  Results saved to benchmark_results.json")

    if not args.bench_only:
        run_graduated_tests()

    print("\nDone!")
