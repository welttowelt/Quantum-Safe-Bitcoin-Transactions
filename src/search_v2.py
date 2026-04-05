"""
QSB Search Engine - Optimized
Uses precomputed EC points for faster key recovery.
"""

import os
import sys
import time
import struct
import itertools
import hashlib
from secp256k1 import (
    sha256d, ripemd160, hash160,
    compress_pubkey, decompress_pubkey, point_mul, point_add, point_neg,
    G, N, P, B,
    ecdsa_sign, ecdsa_recover, encode_der_sig, is_valid_der_sig,
    modinv
)
from bitcoin_tx import (
    Transaction, TxIn, TxOut, QSBScriptBuilder,
    push_data, push_number, find_and_delete,
)


def is_valid_der_easy(data):
    """Easy mode: first nibble is 0x3. Probability ~1/16."""
    if len(data) < 9:
        return False
    return (data[0] >> 4) == 3


class PrecomputedRecovery:
    """
    Precompute base point for fixed (r, s).
    Q = r^-1 * (s*R - z*G) = base + scalar(z) * G
    """
    def __init__(self, r, s, recovery_flag=0):
        self.r = r
        self.s = s
        self.recovery_flag = recovery_flag
        
        # Reconstruct R from r
        x = r % P
        y_sq = (pow(x, 3, P) + B) % P
        y = pow(y_sq, (P + 1) // 4, P)
        if pow(y, 2, P) != y_sq:
            raise ValueError(f"r={r} is not a valid x-coordinate")
        if recovery_flag == 0:
            self.R = (x, y if y % 2 == 0 else P - y)
        else:
            self.R = (x, y if y % 2 == 1 else P - y)
        
        self.r_inv = modinv(r, N)
        self.neg_r_inv = (-self.r_inv) % N
        
        # base = r_inv * s * R
        coeff = (self.r_inv * s) % N
        self.base = point_mul(coeff, self.R)
    
    def recover(self, z):
        """Recover pubkey for message hash z. Returns compressed pubkey bytes."""
        scalar = (self.neg_r_inv * z) % N
        zG = point_mul(scalar, G)
        Q = point_add(self.base, zG)
        if Q == (None, None):
            return None
        return compress_pubkey(Q)
    
    def recover_and_check(self, z, check_fn):
        """Recover key, hash it, check if valid DER. Returns (key_bytes, sig_puzzle) or None."""
        key_bytes = self.recover(z)
        if key_bytes is None:
            return None
        sig_puzzle = ripemd160(key_bytes)
        if check_fn(sig_puzzle):
            return key_bytes, sig_puzzle
        return None


def parse_der(data):
    """Parse r, s from DER sig bytes"""
    try:
        if data[0] != 0x30: return None, None
        idx = 2
        if data[idx] != 0x02: return None, None
        r_len = data[idx + 1]; idx += 2
        r = int.from_bytes(data[idx:idx + r_len], 'big'); idx += r_len
        if data[idx] != 0x02: return None, None
        s_len = data[idx + 1]; idx += 2
        s = int.from_bytes(data[idx:idx + s_len], 'big')
        return r, s
    except (IndexError, ValueError):
        return None, None


def recover_key_puzzle(sig_puzzle_bytes, z, check_fn):
    """Recover key_puzzle from sig_puzzle. Returns compressed pubkey or None."""
    sp_r, sp_s = parse_der(sig_puzzle_bytes)
    if sp_r is None:
        return None
    for flag in [0, 1]:
        try:
            pre = PrecomputedRecovery(sp_r, sp_s, flag)
            key_bytes = pre.recover(z)
            if key_bytes is not None:
                return key_bytes
        except ValueError:
            continue
    return None


class QSBSearch:
    def __init__(self, n=150, t1_signed=8, t1_bonus=0, t2_signed=8, t2_bonus=0,
                 easy_mode=False):
        self.n = n
        self.t1s = t1_signed
        self.t1b = t1_bonus
        self.t2s = t2_signed
        self.t2b = t2_bonus
        self.easy_mode = easy_mode
        self.check_fn = is_valid_der_easy if easy_mode else is_valid_der_sig
        
        self.builder = QSBScriptBuilder(n, t1_signed, t1_bonus, t2_signed, t2_bonus)
        self.builder.generate_keys()
        
        # Generate fixed sigs for pinning and rounds (hardcoded in script)
        self.pin_sig_r, self.pin_sig_s, self.pin_sig_bytes = self._make_fixed_sig("pin")
        self.round_sigs = []
        for r in range(2):
            rs = self._make_fixed_sig(f"round{r}")
            self.round_sigs.append(rs)
    
    def _make_fixed_sig(self, label):
        """Create a deterministic fixed signature"""
        k = int.from_bytes(hashlib.sha256(f"qsb_{label}".encode()).digest(), 'big') % N
        R_pt = point_mul(k, G)
        r = R_pt[0] % N
        # Pick a small s
        s = int.from_bytes(hashlib.sha256(f"qsb_{label}_s".encode()).digest()[:4], 'big')
        s = max(1, s % (N // 2))
        sig_bytes = encode_der_sig(r, s, sighash=0x01)
        return r, s, sig_bytes
    
    def run(self, max_pin_attempts=2**24, max_subsets=2**24):
        mode = "EASY" if self.easy_mode else "REAL"
        print(f"=== QSB Search ({mode}) ===")
        print(f"n={self.n}, R1=({self.t1s}+{self.t1b}), R2=({self.t2s}+{self.t2b})")
        
        # Build locking script
        full_script = self.builder.build_full_script(
            self.pin_sig_bytes, self.round_sigs[0][2], self.round_sigs[1][2]
        )
        print(f"Script: {len(full_script)} bytes")
        
        # Create transaction
        fake_txid = hashlib.sha256(b"qsb_test_utxo").digest()
        tx = Transaction(version=1, locktime=0)
        tx.add_input(TxIn(fake_txid, 0, b'', 0xffffffff))
        tx.add_output(TxOut(49000, b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac'))
        
        # === PINNING ===
        print(f"\n--- Pinning ---")
        print(f"Pin sig: {len(self.pin_sig_bytes)} bytes")
        
        # Precompute for both recovery flags
        pin_precomp = []
        for flag in [0, 1]:
            try:
                pre = PrecomputedRecovery(self.pin_sig_r, self.pin_sig_s, flag)
                pin_precomp.append(pre)
            except ValueError:
                pass
        
        pin_result = None
        t0 = time.time()
        for attempt in range(max_pin_attempts):
            tx.locktime = attempt
            z = tx.sighash(0, full_script, sighash_type=0x01)
            
            for pre in pin_precomp:
                result = pre.recover_and_check(z, self.check_fn)
                if result is not None:
                    key_nonce, sig_puzzle = result
                    elapsed = time.time() - t0
                    print(f"SOLVED! locktime={attempt}, {elapsed:.1f}s, {attempt/max(elapsed,0.001):.0f}/s")
                    
                    # Get key_puzzle
                    key_puzzle = recover_key_puzzle(sig_puzzle, z, self.check_fn)
                    if key_puzzle is None:
                        print("  key_puzzle recovery failed, continuing...")
                        continue
                    
                    pin_result = {
                        'locktime': attempt,
                        'key_nonce': key_nonce,
                        'key_puzzle': key_puzzle,
                        'sig_puzzle': sig_puzzle,
                        'z': z,
                    }
                    break
            
            if pin_result:
                break
            
            if attempt > 0 and attempt % 1000 == 0:
                elapsed = time.time() - t0
                print(f"  {attempt} attempts, {attempt/elapsed:.0f}/s")
        
        if not pin_result:
            print("FAILED: pinning not solved")
            return None
        
        tx.locktime = pin_result['locktime']
        
        # === DIGEST ROUNDS ===
        round_results = []
        for rd in range(2):
            t_signed = self.t1s if rd == 0 else self.t2s
            t_bonus = self.t1b if rd == 0 else self.t2b
            t_total = t_signed + t_bonus
            sig_r, sig_s, sig_bytes = self.round_sigs[rd]
            
            print(f"\n--- Round {rd+1} (t={t_signed}+{t_bonus}) ---")
            
            # Precompute for round sig
            round_precomp = []
            for flag in [0, 1]:
                try:
                    pre = PrecomputedRecovery(sig_r, sig_s, flag)
                    round_precomp.append(pre)
                except ValueError:
                    pass
            
            # Get round script for FindAndDelete base
            round_script = self.builder.build_round_script(rd, sig_bytes)
            
            rd_result = None
            t0 = time.time()
            tried = 0
            
            for subset in itertools.combinations(range(self.n), t_total):
                tried += 1
                if tried > max_subsets:
                    break
                
                # FindAndDelete selected dummy sigs
                sc = round_script
                for idx in subset:
                    sc = find_and_delete(sc, self.builder.dummy_sigs[rd][idx])
                sc = find_and_delete(sc, sig_bytes)
                
                z = tx.sighash(0, sc, sighash_type=0x01)
                
                for pre in round_precomp:
                    result = pre.recover_and_check(z, self.check_fn)
                    if result is not None:
                        key_nonce, sig_puzzle = result
                        elapsed = time.time() - t0
                        print(f"SOLVED! subset={subset}, {tried} tried, {elapsed:.1f}s")
                        
                        key_puzzle = recover_key_puzzle(sig_puzzle, z, self.check_fn)
                        if key_puzzle is None:
                            print("  key_puzzle failed, continuing...")
                            continue
                        
                        # Get pubkeys for dummy sigs (recovered from z=1)
                        dummy_pubkeys = []
                        for idx in subset:
                            dp_sig = self.builder.dummy_sigs[rd][idx]
                            dp_r, dp_s = parse_der(dp_sig)
                            for pf in [0, 1]:
                                dpk = ecdsa_recover(dp_r, dp_s, 1, pf)
                                if dpk is not None:
                                    dummy_pubkeys.append(compress_pubkey(dpk))
                                    break
                        
                        # HORS preimages for signed indices
                        signed_indices = list(subset[:t_signed])
                        bonus_indices = list(subset[t_signed:])
                        preimages = [self.builder.hors_secrets[rd][i] for i in signed_indices]
                        
                        rd_result = {
                            'subset': list(subset),
                            'signed_indices': signed_indices,
                            'bonus_indices': bonus_indices,
                            'key_nonce': key_nonce,
                            'key_puzzle': key_puzzle,
                            'sig_puzzle': sig_puzzle,
                            'dummy_pubkeys': dummy_pubkeys,
                            'preimages': preimages,
                        }
                        break
                
                if rd_result:
                    break
                
                if tried % 500 == 0 and tried > 0:
                    elapsed = time.time() - t0
                    print(f"  {tried} subsets, {tried/elapsed:.1f}/s")
            
            if rd_result is None:
                print(f"FAILED: round {rd+1}")
                return None
            
            round_results.append(rd_result)
        
        # === SUMMARY ===
        print(f"\n{'='*50}")
        print(f"SUCCESS!")
        print(f"{'='*50}")
        print(f"Locktime: {pin_result['locktime']}")
        print(f"Pin key_nonce: {pin_result['key_nonce'].hex()[:20]}...")
        for rd in range(2):
            rr = round_results[rd]
            print(f"Round {rd+1}: signed={rr['signed_indices']} bonus={rr['bonus_indices']}")
        
        return {
            'pinning': pin_result,
            'rounds': round_results,
            'tx': tx,
            'script': full_script,
        }


if __name__ == "__main__":
    # Small test in easy mode
    search = QSBSearch(
        n=10, t1_signed=2, t1_bonus=0, t2_signed=2, t2_bonus=0,
        easy_mode=True
    )
    results = search.run(max_pin_attempts=5000, max_subsets=5000)
    
    if results:
        print("\nWitness components ready.")
        print(f"Transaction size: {len(results['tx'].serialize())} bytes")
        print(f"Script size: {len(results['script'])} bytes")
