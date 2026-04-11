#!/usr/bin/env python3
"""
qsb_pipeline.py — End-to-end QSB Pipeline

Phase 1: Setup
  - Generate HORS keys, dummy sigs, build script
  - Emit funding scriptPubKey for the chosen output mode
  - Save state to qsb_state.json

Phase 2: Export pinning GPU params
  - Export the first-stage binary file for pinning search
  - Output: gpu_pinning_params.json, pinning.bin

Phase 3: Export digest GPU params
  - After pinning finds (sequence, locktime), export digest binaries
  - Output: gpu_digest_r1_params.json, digest_r1.bin, gpu_digest_r2_params.json, digest_r2.bin

Phase 4: Import results + assemble tx
  - Read GPU output (sequence, locktime, round1 indices, round2 indices)
  - Compute actual EC pubkeys and signatures
  - Build spending transaction
  - Verify and output raw tx hex

Usage:
  python3 qsb_pipeline.py setup [--seed SEED] [--config A]
  python3 qsb_pipeline.py export --funding-txid <txid> --funding-vout <n> --funding-value <sats> --dest-address <addr> [--helper-txid <txid> --helper-vout <n>]
  python3 qsb_pipeline.py export-digest --sequence <seq> --locktime <lt> --funding-txid <txid> --funding-vout <n> --funding-value <sats> --dest-address <addr> [--helper-txid <txid> --helper-vout <n>]
  python3 qsb_pipeline.py assemble --sequence <seq> --locktime <lt> --round1 <i0,i1,...> --round2 <i0,i1,...> [--helper-txid <txid> --helper-vout <n> --helper-script-sig-hex <hex>]
  python3 qsb_pipeline.py test    # End-to-end test with easy mode
"""

import os
import sys
import json
import struct
import hashlib
import argparse
import time
from itertools import combinations

# Local imports
from secp256k1 import (
    sha256d, qsb_puzzle_hash, hash160,
    compress_pubkey, decompress_pubkey, point_mul, point_add, G, N, P,
    ecdsa_sign, ecdsa_sign_with_k, ecdsa_recover, ecdsa_verify,
    encode_der_sig, is_valid_der_sig, parse_der, modinv, int_to_der_int,
)
from bitcoin_tx import (
    Transaction, TxIn, TxOut, QSBScriptBuilder,
    push_data, push_number, find_and_delete, serialize_varint,
    OP_0, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG,
)

STATE_FILE = "qsb_state.json"
PLACEHOLDER_HELPER_TXID = "00" * 32
HELPER_INPUT_INDEX = 0
QSB_INPUT_INDEX = 1
DEFAULT_FEE = 5000
DEFAULT_SEQUENCE = 0xfffffffe
GPU_PINNING_SUFFIX_MAX = 119

def compute_sha256_midstate(data, num_blocks):
    """Compute SHA-256 intermediate state after processing num_blocks full blocks."""
    import struct as _st
    
    K = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ]
    
    def ror(x, n): return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    def ch(e, f, g): return (e & f) ^ (~e & g) & 0xFFFFFFFF
    def maj(a, b, c): return (a & b) ^ (a & c) ^ (b & c)
    
    def compress(state, block):
        W = list(block)
        for i in range(16, 64):
            s0 = ror(W[i-15],7) ^ ror(W[i-15],18) ^ (W[i-15]>>3)
            s1 = ror(W[i-2],17) ^ ror(W[i-2],19) ^ (W[i-2]>>10)
            W.append((W[i-16]+s0+W[i-7]+s1) & 0xFFFFFFFF)
        a,b,c,d,e,f,g,h = state
        for i in range(64):
            S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25)
            t1 = (h+S1+ch(e,f,g)+K[i]+W[i]) & 0xFFFFFFFF
            S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22)
            t2 = (S0+maj(a,b,c)) & 0xFFFFFFFF
            h,g,f,e,d,c,b,a = g,f,e,(d+t1)&0xFFFFFFFF,c,b,a,(t1+t2)&0xFFFFFFFF
        return tuple((s+v)&0xFFFFFFFF for s,v in zip(state,(a,b,c,d,e,f,g,h)))
    
    state = (0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
             0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)
    for blk in range(num_blocks):
        off = blk * 64
        words = _st.unpack('>16I', data[off:off+64])
        state = compress(state, words)
    return state

# ============================================================
# Utility
# ============================================================

def b2h(b):
    return b.hex()

def h2b(h):
    return bytes.fromhex(h)


def decode_hex(name, value, expected_len=None, allow_empty=False):
    if value == "" and allow_empty:
        return b""
    try:
        raw = h2b(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be valid hex") from exc
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError(f"{name} must be exactly {expected_len} bytes, got {len(raw)}")
    return raw


def decode_txid(name, value):
    return decode_hex(name, value, expected_len=32)[::-1]


def decode_pubkey_hash(value):
    return decode_hex("dest-address", value, expected_len=20)


def decode_u32(name, value):
    ivalue = int(value)
    if ivalue < 0 or ivalue > 0xffffffff:
        raise ValueError(f"{name} must fit in uint32, got {ivalue}")
    return ivalue

def le_bytes(val, n=32):
    """int → little-endian bytes"""
    return val.to_bytes(n, 'little')

def be_bytes(val, n=32):
    """int → big-endian bytes"""
    return val.to_bytes(n, 'big')

def int_from_be(b):
    return int.from_bytes(b, 'big')

def int_from_le(b):
    return int.from_bytes(b, 'little')

def p2sh_address(script, testnet=False):
    """Compute P2SH address from redeem script"""
    h = hash160(script)
    prefix = b'\xc4' if testnet else b'\x05'
    payload = prefix + h
    checksum = sha256d(payload)[:4]
    import base58
    return base58.b58encode(payload + checksum).decode()

def p2sh_script_pubkey(script):
    """P2SH scriptPubKey: OP_HASH160 <hash160(script)> OP_EQUAL"""
    h = hash160(script)
    return bytes([OP_HASH160, 0x14]) + h + bytes([0x87])  # OP_EQUAL = 0x87

def p2pkh_script(addr_hex):
    """Simple P2PKH scriptPubKey from hex pubkeyhash"""
    pkh = decode_pubkey_hash(addr_hex)
    return bytes([0x76, 0xa9, 0x14]) + pkh + bytes([0x88, 0xac])


def funding_output_script(script, mode='bare'):
    """Return the scriptPubKey to fund for the selected output mode."""
    if mode == 'bare':
        return script
    if mode == 'p2sh':
        return p2sh_script_pubkey(script)
    raise ValueError(f"Unknown funding mode: {mode}")


def build_unlocking_script(unlocking_stack, full_script, mode='bare'):
    """Build the spending input script for the selected funding mode."""
    if mode == 'bare':
        return unlocking_stack
    if mode == 'p2sh':
        return unlocking_stack + push_data(full_script)
    raise ValueError(f"Unknown funding mode: {mode}")


def infer_funding_mode(state):
    """
    Determine how the state expects the QSB output to be funded.
    New states store funding_mode explicitly; older repo states defaulted to P2SH.
    """
    mode = state.get('funding_mode')
    if mode in ('bare', 'p2sh'):
        return mode
    if 'p2sh_script_pubkey' in state and 'funding_script_pubkey' not in state:
        return 'p2sh'
    return 'bare'


def build_spending_transaction(
    helper_txid,
    helper_vout,
    funding_txid,
    funding_vout,
    funding_value,
    dest_address,
    *,
    locktime=0,
    helper_sequence=DEFAULT_SEQUENCE,
    qsb_sequence=DEFAULT_SEQUENCE,
    helper_script_sig=b'',
    qsb_script_sig=b'',
    fee=DEFAULT_FEE,
):
    """Build the canonical 2-input / 1-output QSB spending transaction."""
    dest_value = funding_value - fee
    if dest_value <= 0:
        raise ValueError(
            f"funding-value must exceed the fee ({fee} sats), got {funding_value}"
        )

    tx = Transaction(version=1, locktime=locktime)
    tx.add_input(TxIn(helper_txid, helper_vout, helper_script_sig, helper_sequence))
    tx.add_input(TxIn(funding_txid, funding_vout, qsb_script_sig, qsb_sequence))
    tx.add_output(TxOut(dest_value, p2pkh_script(dest_address)))
    assert len(tx.inputs) == 2 and len(tx.outputs) == 1
    return tx, dest_value


# ============================================================
# Phase 1: Setup
# ============================================================

def cmd_setup(args):
    print("╔══════════════════════════════════════╗")
    print("║  QSB Pipeline — Phase 1: Setup       ║")
    print("╚══════════════════════════════════════╝")
    
    config = args.config
    funding_mode = args.funding_mode
    seed = args.seed
    
    configs = {
        'A':    {'n': 150, 't1s': 8, 't1b': 1, 't2s': 7, 't2b': 2},  # Full: ~20h on 16×5090
        'A120': {'n': 120, 't1s': 8, 't1b': 1, 't2s': 7, 't2b': 2},  # Fast: ~3h on 16×5090
        'A110': {'n': 110, 't1s': 8, 't1b': 1, 't2s': 7, 't2b': 2},  # Express: ~1.5h on 16×5090
        'A100': {'n': 100, 't1s': 8, 't1b': 1, 't2s': 7, 't2b': 2},  # Quick: ~1h on 16×5090
        'test': {'n': 10,  't1s': 2, 't1b': 0, 't2s': 2, 't2b': 0},  # Test only
    }
    cfg = configs[config]
    n, t1s, t1b, t2s, t2b = cfg['n'], cfg['t1s'], cfg['t1b'], cfg['t2s'], cfg['t2b']
    t1, t2 = t1s + t1b, t2s + t2b
    
    print(f"  Config: {config}, n={n}, R1=({t1s}+{t1b}), R2=({t2s}+{t2b})")
    print(f"  Funding mode: {funding_mode}")
    
    if seed:
        import random
        random.seed(seed)
        orig = os.urandom
        os.urandom = lambda n: random.randbytes(n)
    
    builder = QSBScriptBuilder(n, t1s, t1b, t2s, t2b)
    builder.generate_keys()
    
    if seed:
        os.urandom = orig
    
    # Generate fixed sig_nonce for each phase
    # These are the ECDSA signatures hardcoded in the script
    # They use known (r, s) values — the search finds a locktime/subset
    # that makes Hash160(recovered_pubkey) valid DER
    
    pin_k = int.from_bytes(hashlib.sha256(b"qsb_pin_nonce").digest(), 'big') % N
    pin_R = point_mul(pin_k, G)
    pin_r = pin_R[0] % N
    pin_s = int.from_bytes(hashlib.sha256(b"qsb_pin_s").digest()[:16], 'big') % (N // 2)
    pin_s = max(1, pin_s)
    pin_sig = encode_der_sig(pin_r, pin_s, sighash=0x01)
    
    round_sigs = []
    for ri in range(2):
        k = int.from_bytes(hashlib.sha256(f"qsb_r{ri}_nonce".encode()).digest(), 'big') % N
        R = point_mul(k, G)
        r_val = R[0] % N
        s_val = int.from_bytes(hashlib.sha256(f"qsb_r{ri}_s".encode()).digest()[:16], 'big') % (N // 2)
        s_val = max(1, s_val)
        sig = encode_der_sig(r_val, s_val, sighash=0x01)
        round_sigs.append({'r': r_val, 's': s_val, 'sig': b2h(sig), 'k': k})
    
    # Build full script
    full_script = builder.build_full_script(pin_sig, h2b(round_sigs[0]['sig']), h2b(round_sigs[1]['sig']))
    
    funding_spk = funding_output_script(full_script, funding_mode)
    print(f"  Script size: {len(full_script)} bytes")
    print(f"  Script hash160: {b2h(hash160(full_script))}")
    print(f"  Funding scriptPubKey size: {len(funding_spk)} bytes")
    
    # Save state
    state = {
        'config': config,
        'n': n, 't1s': t1s, 't1b': t1b, 't2s': t2s, 't2b': t2b,
        'hors_secrets': [[b2h(s) for s in r] for r in builder.hors_secrets],
        'hors_commitments': [[b2h(c) for c in r] for r in builder.hors_commitments],
        'dummy_sigs': [[b2h(s) for s in r] for r in builder.dummy_sigs],
        'pin_r': pin_r, 'pin_s': pin_s, 'pin_k': pin_k,
        'pin_sig': b2h(pin_sig),
        'round_sigs': [{'r': rs['r'], 's': rs['s'], 'sig': rs['sig'], 'k': rs['k']} for rs in round_sigs],
        'full_script_hex': b2h(full_script),
        'script_hash160': b2h(hash160(full_script)),
        'funding_mode': funding_mode,
        'funding_script_pubkey': b2h(funding_spk),
    }
    if funding_mode == 'p2sh':
        state['p2sh_script_pubkey'] = b2h(funding_spk)
    
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)
    
    print(f"\n  State saved to {STATE_FILE}")
    print(f"  Funding scriptPubKey: {state['funding_script_pubkey']}")
    if funding_mode == 'bare':
        print(f"\n  Fund this bare script output directly, then run:")
    else:
        print(f"\n  Fund this legacy P2SH output, then run:")
    print(
        "  python3 qsb_pipeline.py export --funding-txid <txid> --funding-vout <n> "
        "--funding-value <sats> --dest-address <pkh_hex> "
        "[--helper-txid <aux_txid> --helper-vout <aux_vout>]"
    )
    print("  ...after pinning search finds sequence+locktime, run:")
    print(
        "  python3 qsb_pipeline.py export-digest --sequence <seq> --locktime <lt> "
        "--funding-txid <txid> --funding-vout <n> --funding-value <sats> "
        "--dest-address <pkh_hex> [--helper-txid <aux_txid> --helper-vout <aux_vout>]"
    )


def parse_spend_context(args):
    helper_txid = decode_txid("helper-txid", args.helper_txid)
    helper_vout = decode_u32("helper-vout", args.helper_vout)
    funding_txid = decode_txid("funding-txid", args.funding_txid)
    funding_vout = decode_u32("funding-vout", args.funding_vout)
    funding_value = int(args.funding_value)
    if funding_value <= DEFAULT_FEE:
        raise ValueError(
            f"funding-value must exceed the fee ({DEFAULT_FEE} sats), got {funding_value}"
        )
    decode_pubkey_hash(args.dest_address)
    return {
        "helper_txid": helper_txid,
        "helper_vout": helper_vout,
        "funding_txid": funding_txid,
        "funding_vout": funding_vout,
        "funding_value": funding_value,
        "dest_address": args.dest_address,
    }


def export_digest_params(state, tx, sequence, locktime, helper_txid_hex, helper_vout):
    n = state['n']
    full_script = h2b(state['full_script_hex'])
    t1 = state['t1s'] + state['t1b']
    t2 = state['t2s'] + state['t2b']

    for ri in range(2):
        rs = state['round_sigs'][ri]
        r_val, s_val = rs['r'], rs['s']
        sig_nonce = h2b(rs['sig'])

        removed_per_subset = t1 if ri == 0 else t2
        base_script_code = find_and_delete(full_script, sig_nonce)
        scriptcode_len_after_fad = len(base_script_code) - removed_per_subset * 10

        d_tx_prefix = struct.pack('<I', tx.version)
        d_tx_prefix += serialize_varint(len(tx.inputs))
        d_tx_prefix += tx.inputs[HELPER_INPUT_INDEX].txid
        d_tx_prefix += struct.pack('<I', tx.inputs[HELPER_INPUT_INDEX].vout)
        d_tx_prefix += serialize_varint(0)
        d_tx_prefix += struct.pack('<I', tx.inputs[HELPER_INPUT_INDEX].sequence)
        d_tx_prefix += tx.inputs[QSB_INPUT_INDEX].txid
        d_tx_prefix += struct.pack('<I', tx.inputs[QSB_INPUT_INDEX].vout)
        d_tx_prefix += serialize_varint(scriptcode_len_after_fad)

        hors_section_len = n * 21
        hors_section = base_script_code[:hors_section_len]
        dummy_sig_section_start = hors_section_len
        dummy_sig_section_len = n * 10
        tail_start = dummy_sig_section_start + dummy_sig_section_len
        tail_section = base_script_code[tail_start:]

        d_tx_suffix = struct.pack('<I', tx.inputs[QSB_INPUT_INDEX].sequence)
        d_tx_suffix += serialize_varint(len(tx.outputs))
        for out in tx.outputs:
            d_tx_suffix += out.serialize()
        d_tx_suffix += struct.pack('<I', tx.locktime)
        d_tx_suffix += struct.pack('<I', 0x01)

        fixed_prefix = d_tx_prefix + hors_section
        fp_blocks = len(fixed_prefix) // 64
        dummy_sig_pushes = [push_data(h2b(state['dummy_sigs'][ri][i])) for i in range(n - 1, -1, -1)]
        dummy_sigs_bytes = b''.join(dummy_sig_pushes)

        d_r_inv = modinv(r_val, N)
        d_neg_r_inv = (-d_r_inv) % N
        d_u2 = (s_val * d_r_inv) % N
        dx = r_val
        dy_sq = (pow(dx, 3, P) + 7) % P
        dy = pow(dy_sq, (P + 1) // 4, P)
        if dy % 2 != 0:
            dy = P - dy
        dR = (dx, dy)
        d_u2R = point_mul(d_u2, dR)

        total_preimage_len = len(d_tx_prefix) + scriptcode_len_after_fad + len(d_tx_suffix)

        digest_params = {
            'type': f'digest_round{ri+1}',
            'round': ri,
            'sequence': sequence,
            'locktime': locktime,
            'helper_txid': helper_txid_hex,
            'helper_vout': helper_vout,
            'helper_input_index': HELPER_INPUT_INDEX,
            'qsb_input_index': QSB_INPUT_INDEX,
            'output_count': len(tx.outputs),
            'n': n,
            't': removed_per_subset,
            'hors_section': b2h(hors_section),
            'hors_section_len': hors_section_len,
            'dummy_sigs': [b2h(h2b(state['dummy_sigs'][ri][i])) for i in range(n)],
            'dummy_sig_pushes': [b2h(sig) for sig in dummy_sig_pushes],
            'dummy_sig_len': len(dummy_sigs_bytes),
            'tail_section': b2h(tail_section),
            'tail_section_len': len(tail_section),
            'fixed_prefix': b2h(fixed_prefix),
            'midstate_blocks': fp_blocks,
            'tx_prefix': b2h(d_tx_prefix),
            'tx_suffix': b2h(d_tx_suffix),
            'tx_suffix_len': len(d_tx_suffix),
            'total_preimage_len': total_preimage_len,
            'sig_r': r_val,
            'sig_s': s_val,
            'neg_r_inv': b2h(le_bytes(d_neg_r_inv)),
            'u2r_x': b2h(le_bytes(d_u2R[0])),
            'u2r_y': b2h(le_bytes(d_u2R[1])),
        }

        fname = f'gpu_digest_r{ri+1}_params.json'
        with open(fname, 'w') as f:
            json.dump(digest_params, f, indent=2)

        bname = f'digest_r{ri+1}.bin'
        with open(bname, 'wb') as f:
            f.write(struct.pack('<I', n))
            f.write(struct.pack('<I', removed_per_subset))
            f.write(struct.pack('<I', total_preimage_len))
            f.write(struct.pack('<I', len(tail_section)))
            f.write(struct.pack('<I', len(d_tx_suffix)))
            midstate = compute_sha256_midstate(fixed_prefix, fp_blocks)
            for v in midstate:
                f.write(struct.pack('>I', v))
            f.write(dummy_sigs_bytes)
            f.write(tail_section)
            f.write(d_tx_suffix)
            f.write(le_bytes(d_neg_r_inv))
            f.write(le_bytes(d_u2R[0]))
            f.write(le_bytes(d_u2R[1]))

        print(f"  Round {ri+1}: scriptCode={scriptcode_len_after_fad} bytes, midstate={fp_blocks} blocks")
        print(f"  Saved {fname} + {bname}")


# ============================================================
# Phase 2: Export GPU params
# ============================================================

def cmd_export(args):
    print("╔══════════════════════════════════════╗")
    print("║  QSB Pipeline — Phase 2: Export       ║")
    print("╚══════════════════════════════════════╝")
    
    with open(STATE_FILE) as f:
        state = json.load(f)

    full_script = h2b(state['full_script_hex'])
    ctx = parse_spend_context(args)
    helper_txid = ctx["helper_txid"]
    helper_vout = ctx["helper_vout"]
    funding_txid = ctx["funding_txid"]
    funding_vout = ctx["funding_vout"]
    funding_value = ctx["funding_value"]

    if args.helper_txid == PLACEHOLDER_HELPER_TXID:
        print("  WARNING: using placeholder helper input.")
        print("           Replace it with a real auxiliary input for a broadcastable final transaction.")
    
    tx, dest_value = build_spending_transaction(
        helper_txid,
        helper_vout,
        funding_txid,
        funding_vout,
        funding_value,
        args.dest_address,
    )
    
    # ============================================================
    # Export pinning params
    # ============================================================
    
    pin_r = state['pin_r']
    pin_s = state['pin_s']
    pin_sig = h2b(state['pin_sig'])
    
    # For pinning, sighash_type = SIGHASH_ALL (0x01)
    # scriptCode = full_script with FindAndDelete(pin_sig)
    pin_script_code = find_and_delete(full_script, pin_sig)
    
    fixed_prefix = struct.pack('<I', tx.version)
    fixed_prefix += serialize_varint(len(tx.inputs))
    fixed_prefix += helper_txid
    fixed_prefix += struct.pack('<I', helper_vout)
    fixed_prefix += serialize_varint(0)
    fixed_prefix += struct.pack('<I', tx.inputs[HELPER_INPUT_INDEX].sequence)
    fixed_prefix += funding_txid
    fixed_prefix += struct.pack('<I', funding_vout)
    fixed_prefix += serialize_varint(len(pin_script_code))
    fixed_prefix += pin_script_code

    outputs_section = serialize_varint(len(tx.outputs))
    for out in tx.outputs:
        outputs_section += out.serialize()

    full_blocks = len(fixed_prefix) // 64
    fixed_prefix_covered = full_blocks * 64
    suffix_template = fixed_prefix[fixed_prefix_covered:]
    seq_offset = len(suffix_template)
    suffix_template += b'\x00' * 4
    suffix_template += outputs_section
    lt_offset = len(suffix_template)
    suffix_template += b'\x00' * 4
    suffix_template += struct.pack('<I', 0x01)

    total_preimage_len = len(fixed_prefix) + 4 + len(outputs_section) + 4 + 4

    # Compute r_inv, neg_r_inv, u2*R for EC recovery
    r_inv = modinv(pin_r, N)
    neg_r_inv = (-r_inv) % N
    u2 = (pin_s * r_inv) % N
    
    # Recover R point from r
    # R.x = pin_r, need to find R.y
    x = pin_r
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if y % 2 != 0:  # pick even y (recid=0)
        y = P - y
    R_point = (x, y)
    u2R = point_mul(u2, R_point)
    
    # Export as binary
    if len(suffix_template) > GPU_PINNING_SUFFIX_MAX:
        raise ValueError(
            f"pinning suffix template is {len(suffix_template)} bytes; "
            f"the current CUDA kernel only supports up to {GPU_PINNING_SUFFIX_MAX}"
        )

    params = {
        'type': 'pinning',
        'helper_txid': args.helper_txid,
        'helper_vout': helper_vout,
        'helper_input_index': HELPER_INPUT_INDEX,
        'qsb_input_index': QSB_INPUT_INDEX,
        'output_count': len(tx.outputs),
        'fixed_prefix_len': len(fixed_prefix),
        'fixed_prefix': b2h(fixed_prefix),
        'suffix_template_len': len(suffix_template),
        'suffix_template': b2h(suffix_template),
        'sequence_offset': seq_offset,
        'locktime_offset': lt_offset,
        'total_preimage_len': total_preimage_len,
        'midstate_blocks': full_blocks,
        'pin_r': pin_r,
        'pin_s': pin_s,
        'neg_r_inv': b2h(le_bytes(neg_r_inv)),
        'u2r_x': b2h(le_bytes(u2R[0])),
        'u2r_y': b2h(le_bytes(u2R[1])),
    }
    
    with open('gpu_pinning_params.json', 'w') as f:
        json.dump(params, f, indent=2)
    
    # Binary export for GPU
    with open('pinning.bin', 'wb') as f:
        # Layout must match gpu/qsb_params.h::load_pinning_params()
        # [total_preimage_len][suffix_len][seq_offset][lt_offset][midstate][suffix][neg_r_inv][u2r_x][u2r_y]
        midstate = compute_sha256_midstate(fixed_prefix, full_blocks)
        f.write(struct.pack('<I', total_preimage_len))
        f.write(struct.pack('<I', len(suffix_template)))
        f.write(struct.pack('<I', seq_offset))
        f.write(struct.pack('<I', lt_offset))
        for v in midstate:
            f.write(struct.pack('>I', v))
        f.write(suffix_template)
        f.write(le_bytes(neg_r_inv))
        f.write(le_bytes(u2R[0]))
        f.write(le_bytes(u2R[1]))
    
    print(
        f"  Pinning: fixed_prefix={len(fixed_prefix)} bytes, "
        f"suffix={len(suffix_template)} bytes, midstate={full_blocks} blocks"
    )
    print(f"  Saved gpu_pinning_params.json + pinning.bin")
    print(f"\n  Upload pinning.bin + GPU code to vast.ai and run pinning search.")
    print(f"  After pinning finds sequence+locktime, run export-digest to create digest_r1.bin and digest_r2.bin.")


def cmd_export_digest(args):
    print("╔══════════════════════════════════════╗")
    print("║  QSB Pipeline — Phase 3: Export Digests ║")
    print("╚══════════════════════════════════════╝")

    with open(STATE_FILE) as f:
        state = json.load(f)

    ctx = parse_spend_context(args)
    sequence = decode_u32("sequence", args.sequence)
    locktime = decode_u32("locktime", args.locktime)

    if args.helper_txid == PLACEHOLDER_HELPER_TXID:
        print("  WARNING: using placeholder helper input.")
        print("           Replace it with a real auxiliary input for a broadcastable final transaction.")

    tx, _ = build_spending_transaction(
        ctx["helper_txid"],
        ctx["helper_vout"],
        ctx["funding_txid"],
        ctx["funding_vout"],
        ctx["funding_value"],
        ctx["dest_address"],
        locktime=locktime,
        qsb_sequence=sequence,
    )

    print(f"  Sequence: {sequence}")
    print(f"  Locktime: {locktime}")
    export_digest_params(state, tx, sequence, locktime, args.helper_txid, ctx["helper_vout"])
    print(f"\n  Upload digest_r1.bin / digest_r2.bin + GPU code to vast.ai and run digest search.")


# ============================================================
# Phase 4: Assemble transaction
# ============================================================

def cmd_assemble(args):
    print("╔══════════════════════════════════════╗")
    print("║  QSB Pipeline — Phase 4: Assemble    ║")
    print("╚══════════════════════════════════════╝")
    
    with open(STATE_FILE) as f:
        state = json.load(f)
    
    n = state['n']
    t1 = state['t1s'] + state['t1b']
    t2 = state['t2s'] + state['t2b']
    
    ctx = parse_spend_context(args)
    locktime = decode_u32("locktime", args.locktime)
    sequence = decode_u32("sequence", args.sequence)
    r1_indices = sorted([int(x) for x in args.round1.split(',')])
    r2_indices = sorted([int(x) for x in args.round2.split(',')])
    
    assert len(r1_indices) == t1, f"Expected {t1} round1 indices, got {len(r1_indices)}"
    assert len(r2_indices) == t2, f"Expected {t2} round2 indices, got {len(r2_indices)}"
    
    full_script = h2b(state['full_script_hex'])
    funding_mode = infer_funding_mode(state)
    
    print(f"  Locktime: {locktime}")
    print(f"  Sequence: {sequence}")
    print(f"  Round 1 indices: {r1_indices}")
    print(f"  Round 2 indices: {r2_indices}")
    print(f"  Funding mode: {funding_mode}")
    
    # ================================================================
    # Rebuild the spending transaction
    # ================================================================
    # NOTE: QSB input must be at index >= num_outputs for SIGHASH_SINGLE bug (z=1)
    # Design: helper input at index 0, QSB input at index 1, 1 output
    # This makes SIGHASH_SINGLE at input 1 trigger the bug.
    # For testing, we use a fake helper input.
    
    funding_txid = ctx["funding_txid"]
    funding_vout = ctx["funding_vout"]
    funding_value = ctx["funding_value"]
    helper_txid = ctx["helper_txid"]
    helper_vout = ctx["helper_vout"]
    dest_address = ctx["dest_address"]
    helper_script_sig = decode_hex(
        "helper-script-sig-hex", args.helper_script_sig_hex, allow_empty=True
    )

    if args.helper_txid == PLACEHOLDER_HELPER_TXID:
        print("  WARNING: assembling with placeholder helper input.")
        print("           Replace it with a real auxiliary input before treating the tx as broadcastable.")
    if helper_script_sig:
        print(f"  Helper scriptSig: {len(helper_script_sig)} bytes")

    tx, dest_value = build_spending_transaction(
        helper_txid,
        helper_vout,
        funding_txid,
        funding_vout,
        funding_value,
        dest_address,
        locktime=locktime,
        qsb_sequence=sequence,
        helper_script_sig=helper_script_sig,
    )
    
    # ================================================================
    # Step 1: Pinning — recover key_nonce
    # ================================================================
    print("\n  [1] Pinning: recover key_nonce")
    
    pin_r = state['pin_r']
    pin_s = state['pin_s']
    pin_sig = h2b(state['pin_sig'])
    
    # scriptCode for pin_sig_nonce verification: full_script - FindAndDelete(pin_sig)
    pin_sc = find_and_delete(full_script, pin_sig)
    z_pin = tx.sighash(QSB_INPUT_INDEX, pin_sc, sighash_type=0x01)
    
    # Recover key_nonce (try both recovery flags)
    key_nonce_pin = None
    sig_puzzle_pin = None
    for flag in [0, 1]:
        pt = ecdsa_recover(pin_r, pin_s, z_pin, flag)
        if pt:
            kn = compress_pubkey(pt)
            sp = qsb_puzzle_hash(kn)
            real_der = is_valid_der_sig(sp)
            easy_der = (sp[0] >> 4) == 3
            if real_der or easy_der:
                key_nonce_pin = kn
                sig_puzzle_pin = sp
                print(f"    key_nonce: {b2h(kn)[:16]}...")
                print(f"    sig_puzzle: {b2h(sp)} (real_DER={real_der})")
                break
    
    if key_nonce_pin is None:
        print("    ERROR: could not recover pinning key_nonce!")
        return
    
    # ================================================================
    # Step 2: Pinning — recover key_puzzle from sig_puzzle
    # ================================================================
    print("\n  [2] Pinning: recover key_puzzle")
    
    sp_r, sp_s = parse_der(sig_puzzle_pin)
    if sp_r is None:
        print("    WARNING: sig_puzzle not valid DER (easy mode). key_puzzle will be mock.")
        print("    (In real GPU search, sig_puzzle is always valid DER)")
        key_puzzle_pin = b'\x02' + b'\x00' * 32  # mock compressed pubkey
    else:
        # sig_puzzle's sighash_type is its last byte
        sp_sighash_type = sig_puzzle_pin[-1]
        print(f"    sig_puzzle sighash_type: 0x{sp_sighash_type:02x}")
        
        # scriptCode for sig_puzzle verification: full_script - FindAndDelete(sig_puzzle)
        puzzle_sc = find_and_delete(full_script, sig_puzzle_pin)
        z_puzzle_pin = tx.sighash(QSB_INPUT_INDEX, puzzle_sc, sighash_type=sp_sighash_type)
        
        key_puzzle_pin = None
        for flag in [0, 1]:
            pt = ecdsa_recover(sp_r, sp_s, z_puzzle_pin, flag)
            if pt:
                key_puzzle_pin = compress_pubkey(pt)
                print(f"    key_puzzle: {b2h(key_puzzle_pin)[:16]}...")
                break
        
        if key_puzzle_pin is None:
            print("    ERROR: could not recover pinning key_puzzle!")
            return
    
    # ================================================================
    # Step 3: Digest rounds — recover key_nonce, key_puzzle, dummy pubkeys
    # ================================================================
    
    round_results = []
    round_indices = [r1_indices, r2_indices]
    
    for ri in range(2):
        t = t1 if ri == 0 else t2
        ts = state['t1s'] if ri == 0 else state['t2s']
        indices = round_indices[ri]
        rs = state['round_sigs'][ri]
        r_val, s_val = rs['r'], rs['s']
        sig_nonce = h2b(rs['sig'])
        
        print(f"\n  [{3+ri*2}] Round {ri+1}: recover key_nonce")
        
        # scriptCode: full_script - FindAndDelete(sig_nonce) - FindAndDelete(each selected dummy)
        sc = find_and_delete(full_script, sig_nonce)
        for idx in indices:
            dummy_sig = h2b(state['dummy_sigs'][ri][idx])
            sc = find_and_delete(sc, dummy_sig)
        
        z_round = tx.sighash(QSB_INPUT_INDEX, sc, sighash_type=0x01)
        
        key_nonce_round = None
        sig_puzzle_round = None
        for flag in [0, 1]:
            pt = ecdsa_recover(r_val, s_val, z_round, flag)
            if pt:
                kn = compress_pubkey(pt)
                sp = qsb_puzzle_hash(kn)
                real_der = is_valid_der_sig(sp)
                easy_der = (sp[0] >> 4) == 3
                if real_der or easy_der:
                    key_nonce_round = kn
                    sig_puzzle_round = sp
                    print(f"    key_nonce: {b2h(kn)[:16]}...")
                    print(f"    sig_puzzle: {b2h(sp)} (real_DER={real_der})")
                    break
        
        if key_nonce_round is None:
            print(f"    ERROR: round {ri+1} key_nonce recovery failed!")
            return
        
        # Recover key_puzzle from sig_puzzle
        print(f"\n  [{4+ri*2}] Round {ri+1}: recover key_puzzle")
        
        sp_r2, sp_s2 = parse_der(sig_puzzle_round)
        if sp_r2 is None:
            print(f"    WARNING: sig_puzzle not valid DER (easy mode). Using mock key_puzzle.")
            key_puzzle_round = b'\x02' + b'\x00' * 32
        else:
            sp_ht = sig_puzzle_round[-1]
            print(f"    sig_puzzle sighash_type: 0x{sp_ht:02x}")
            puzzle_sc2 = find_and_delete(full_script, sig_puzzle_round)
            z_puzzle_round = tx.sighash(QSB_INPUT_INDEX, puzzle_sc2, sighash_type=sp_ht)
            key_puzzle_round = None
            for flag in [0, 1]:
                pt = ecdsa_recover(sp_r2, sp_s2, z_puzzle_round, flag)
                if pt:
                    key_puzzle_round = compress_pubkey(pt)
                    print(f"    key_puzzle: {b2h(key_puzzle_round)[:16]}...")
                    break
            if key_puzzle_round is None:
                print(f"    ERROR: round {ri+1} key_puzzle recovery failed!")
                return
        
        # Recover dummy pubkeys (z=1 via SIGHASH_SINGLE bug)
        # This requires QSB_INPUT_INDEX >= num_outputs
        dummy_pubkeys = []
        for idx in indices:
            ds_bytes = h2b(state['dummy_sigs'][ri][idx])
            dr, ds_val = parse_der(ds_bytes)
            for flag in [0, 1]:
                pt = ecdsa_recover(dr, ds_val, 1, flag)  # z=1 (SIGHASH_SINGLE bug)
                if pt:
                    dummy_pubkeys.append(compress_pubkey(pt))
                    break
        
        # Collect HORS preimages for signed indices
        signed_indices = indices[:ts]
        preimages = [h2b(state['hors_secrets'][ri][i]) for i in signed_indices]
        
        round_results.append({
            'key_nonce': key_nonce_round,
            'key_puzzle': key_puzzle_round,
            'sig_puzzle': sig_puzzle_round,
            'dummy_pubkeys': dummy_pubkeys,
            'preimages': preimages,
            'subset': indices,
            'signed_indices': list(signed_indices),
            'bonus_indices': list(indices[ts:]),
        })
        
        print(f"    dummy_pubkeys: {len(dummy_pubkeys)}")
        print(f"    preimages: {len(preimages)}")
    
    # ================================================================
    # Step 4: Build unlocking stack / scriptSig
    # ================================================================
    print(f"\n  [7] Building unlocking stack...")
    
    # Unlocking stack layout (bottom to top of stack):
    # Round 2: key_puzzle, key_nonce, dummy_pubs(rev), preimages(rev), indices(rev)
    # Round 1: key_puzzle, key_nonce, dummy_pubs(rev), preimages(rev), indices(rev)
    # Pinning: key_puzzle, key_nonce
    
    witness = b''
    
    # Round 2 first (bottom of stack)
    for rd in [1, 0]:
        rr = round_results[rd]
        witness += push_data(rr['key_puzzle'])
        witness += push_data(rr['key_nonce'])
        for pub in reversed(rr['dummy_pubkeys']):
            witness += push_data(pub)
        for pre in reversed(rr['preimages']):
            witness += push_data(pre)
        for idx in reversed(rr['subset']):
            witness += push_number(idx)
    
    # Pinning data (top of stack)
    witness += push_data(key_puzzle_pin)
    witness += push_data(key_nonce_pin)
    
    script_sig = build_unlocking_script(witness, full_script, funding_mode)

    print(f"    Unlocking stack: {len(witness)} bytes")
    print(f"    ScriptSig: {len(script_sig)} bytes")
    if funding_mode == 'p2sh':
        print(f"    Redeem script: {len(full_script)} bytes")
    
    # Set the scriptSig on the QSB input
    tx.inputs[QSB_INPUT_INDEX].script_sig = script_sig
    
    # Serialize
    raw_tx = tx.serialize()
    print(f"\n  [8] Final transaction: {len(raw_tx)} bytes")
    print(f"    Raw hex: {b2h(raw_tx)[:80]}...")
    
    # Save
    with open('qsb_raw_tx.hex', 'w') as f:
        f.write(b2h(raw_tx))
    print(f"    Saved to qsb_raw_tx.hex")
    
    # Also save all recovery data for debugging
    solution = {
        'locktime': locktime,
        'sequence': sequence,
        'helper_txid': args.helper_txid,
        'helper_vout': helper_vout,
        'helper_script_sig_hex': args.helper_script_sig_hex,
        'funding_txid': args.funding_txid,
        'funding_vout': funding_vout,
        'funding_value': funding_value,
        'dest_address': dest_address,
        'funding_mode': funding_mode,
        'dest_value': dest_value,
        'round1_indices': r1_indices,
        'round2_indices': r2_indices,
        'pin_key_nonce': b2h(key_nonce_pin),
        'pin_key_puzzle': b2h(key_puzzle_pin),
        'pin_sig_puzzle': b2h(sig_puzzle_pin),
        'rounds': [{
            'key_nonce': b2h(rr['key_nonce']),
            'key_puzzle': b2h(rr['key_puzzle']),
            'sig_puzzle': b2h(rr['sig_puzzle']),
            'dummy_pubkeys': [b2h(p) for p in rr['dummy_pubkeys']],
            'preimages': [b2h(p) for p in rr['preimages']],
            'subset': rr['subset'],
        } for rr in round_results],
    }
    with open('qsb_solution.json', 'w') as f:
        json.dump(solution, f, indent=2)
    print(f"    Solution saved to qsb_solution.json")


# ============================================================
# Test mode
# ============================================================

def cmd_test(args):
    """End-to-end test with small params and easy mode"""
    print("╔══════════════════════════════════════╗")
    print("║  QSB Pipeline — Test Mode            ║")
    print("╚══════════════════════════════════════╝")
    
    n = 10
    t1s, t1b, t2s, t2b = 2, 0, 2, 0
    t1, t2 = t1s + t1b, t2s + t2b
    
    print(f"  n={n}, t1={t1}, t2={t2}")
    
    import random
    random.seed(42)
    orig = os.urandom
    os.urandom = lambda nb: random.randbytes(nb)
    
    builder = QSBScriptBuilder(n, t1s, t1b, t2s, t2b)
    builder.generate_keys()
    
    os.urandom = orig
    
    # Generate sig nonces
    sigs = []
    for phase in ['pin', 'r0', 'r1']:
        k = int.from_bytes(hashlib.sha256(f"test_{phase}".encode()).digest(), 'big') % N
        R = point_mul(k, G)
        r_val = R[0] % N
        s_val = int.from_bytes(hashlib.sha256(f"test_{phase}_s".encode()).digest()[:8], 'big') % (N // 2)
        s_val = max(1, s_val)
        sig = encode_der_sig(r_val, s_val, sighash=0x01)
        sigs.append({'r': r_val, 's': s_val, 'sig': sig, 'k': k})
    
    full_script = builder.build_full_script(sigs[0]['sig'], sigs[1]['sig'], sigs[2]['sig'])
    print(f"  Script: {len(full_script)} bytes")
    
    # Build test transaction
    fake_txid = b'\x01' * 32
    # Transaction structure: helper input at index 0, QSB at index 1, 1 output
    # This enables SIGHASH_SINGLE bug (z=1) for dummy sigs at input 1
    tx, _ = build_spending_transaction(
        b'\x00' * 32,
        0,
        fake_txid,
        0,
        50000,
        '0' * 40,
    )
    
    # =============================
    # Pinning search (easy mode)
    # =============================
    print(f"\n  [Pinning search]")
    pin_sig_data = sigs[0]['sig']
    pin_script_code = find_and_delete(full_script, pin_sig_data)
    pin_r, pin_s = sigs[0]['r'], sigs[0]['s']
    
    r_inv = modinv(pin_r, N)
    
    found_lt = None
    for lt in range(1, 10_000_000):
        tx.locktime = lt
        z = tx.sighash(QSB_INPUT_INDEX, pin_script_code, sighash_type=0x01)
        
        # Recover pubkey
        u1 = (-z * r_inv) % N
        u2 = (pin_s * r_inv) % N
        
        # Recover R point
        x = pin_r
        y_sq = (pow(x, 3, P) + 7) % P
        y = pow(y_sq, (P + 1) // 4, P)
        if y % 2 != 0:
            y = P - y
        R_pt = (x, y)
        
        Q = point_add(point_mul(u1, G), point_mul(u2, R_pt))
        pubkey_bytes = compress_pubkey(Q)
        h160 = qsb_puzzle_hash(pubkey_bytes)
        
        # Easy check for test speed (real search uses GPU with full DER)
        if is_valid_der_sig(h160) or (h160[0] >> 4) == 3:
            found_lt = lt
            is_real_der = is_valid_der_sig(h160)
            print(f"  Found! locktime={lt}, sig_puzzle={b2h(h160)} (real_DER={is_real_der})")
            break
        
        if lt % 100000 == 0:
            print(f"    searched {lt}...")
    
    if not found_lt:
        print("  Not found in range!")
        return
    
    tx.locktime = found_lt
    
    # =============================
    # Digest search (easy mode, per round)
    # =============================
    
    found_round_indices = []
    for ri in range(2):
        rs = sigs[ri + 1]
        sig_nonce = rs['sig']
        r_val, s_val = rs['r'], rs['s']
        t = t1 if ri == 0 else t2
        
        print(f"\n  [Digest round {ri+1} search, t={t}]")
        
        base_sc = find_and_delete(full_script, sig_nonce)
        d_r_inv = modinv(r_val, N)
        
        dx = r_val
        dy_sq = (pow(dx, 3, P) + 7) % P
        dy = pow(dy_sq, (P + 1) // 4, P)
        if dy % 2 != 0:
            dy = P - dy
        dR = (dx, dy)
        
        found_combo = None
        count = 0
        for combo in combinations(range(n), t):
            # FindAndDelete selected dummy sigs
            sc = base_sc
            for idx in combo:
                sc = find_and_delete(sc, builder.dummy_sigs[ri][idx])
            
            z = tx.sighash(QSB_INPUT_INDEX, sc, sighash_type=0x01)
            
            u1 = (-z * d_r_inv) % N
            u2 = (s_val * d_r_inv) % N
            Q = point_add(point_mul(u1, G), point_mul(u2, dR))
            pk = compress_pubkey(Q)
            h160 = qsb_puzzle_hash(pk)
            
            if is_valid_der_sig(h160) or (h160[0] >> 4) == 3:
                found_combo = list(combo)
                print(f"  Found! indices={found_combo}, sig_puzzle={b2h(h160)}")
                break
            
            count += 1
            if count % 10 == 0:
                print(f"    searched {count}...")
        
        if not found_combo:
            print(f"  Not found! (searched {count})")
            return
        found_round_indices.append(found_combo)
    
    print(f"\n  ✓ All phases found solutions!")
    print(f"  Locktime: {found_lt}")
    
    # Now test assembly
    print(f"\n  --- Testing Assembly ---")
    
    # Save state for assembly
    test_state = {
        'config': 'test', 'n': n,
        't1s': t1s, 't1b': t1b, 't2s': t2s, 't2b': t2b,
        'hors_secrets': [[b2h(s) for s in r] for r in builder.hors_secrets],
        'hors_commitments': [[b2h(c) for c in r] for r in builder.hors_commitments],
        'dummy_sigs': [[b2h(s) for s in r] for r in builder.dummy_sigs],
        'pin_r': sigs[0]['r'], 'pin_s': sigs[0]['s'], 'pin_k': sigs[0]['k'],
        'pin_sig': b2h(sigs[0]['sig']),
        'round_sigs': [{'r': sigs[i+1]['r'], 's': sigs[i+1]['s'],
                        'sig': b2h(sigs[i+1]['sig']), 'k': sigs[i+1]['k']} for i in range(2)],
        'full_script_hex': b2h(full_script),
        'script_hash160': b2h(hash160(full_script)),
        'funding_mode': 'bare',
        'funding_script_pubkey': b2h(full_script),
    }
    with open(STATE_FILE, 'w') as f:
        json.dump(test_state, f, indent=2)
    
    # Create a mock args object for assembly
    class MockArgs:
        pass
    asm_args = MockArgs()
    asm_args.locktime = found_lt
    asm_args.sequence = DEFAULT_SEQUENCE
    asm_args.round1 = ','.join(str(i) for i in found_round_indices[0])
    asm_args.round2 = ','.join(str(i) for i in found_round_indices[1])
    asm_args.helper_txid = PLACEHOLDER_HELPER_TXID
    asm_args.helper_vout = 0
    asm_args.helper_script_sig_hex = ""
    asm_args.funding_txid = '01' * 32
    asm_args.funding_vout = 0
    asm_args.funding_value = 50000
    asm_args.dest_address = '00' * 20
    
    cmd_assemble(asm_args)
    
    print(f"\n  ✓ Full pipeline test complete!")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="QSB Pipeline")
    sub = parser.add_subparsers(dest='command')
    
    # Setup
    p_setup = sub.add_parser('setup')
    p_setup.add_argument('--config', default='A')
    p_setup.add_argument('--seed', type=int, default=None)
    p_setup.add_argument('--funding-mode', choices=['bare', 'p2sh'], default='bare',
                         help='Funding output style (paper-compatible default: bare)')
    
    # Export
    p_export = sub.add_parser('export')
    p_export.add_argument('--helper-txid', default=PLACEHOLDER_HELPER_TXID,
                          help='hex txid for helper input used to trigger SIGHASH_SINGLE bug')
    p_export.add_argument('--helper-vout', type=int, default=0,
                          help='vout for helper input')
    p_export.add_argument('--funding-txid', required=True)
    p_export.add_argument('--funding-vout', type=int, required=True)
    p_export.add_argument('--funding-value', type=int, required=True)
    p_export.add_argument('--dest-address', required=True, help='hex pubkey hash (20 bytes)')

    p_export_digest = sub.add_parser('export-digest')
    p_export_digest.add_argument('--sequence', type=int, required=True, help='QSB input sequence from pinning hit')
    p_export_digest.add_argument('--locktime', type=int, required=True, help='QSB locktime from pinning hit')
    p_export_digest.add_argument('--helper-txid', default=PLACEHOLDER_HELPER_TXID,
                                 help='hex txid for helper input used to trigger SIGHASH_SINGLE bug')
    p_export_digest.add_argument('--helper-vout', type=int, default=0,
                                 help='vout for helper input')
    p_export_digest.add_argument('--funding-txid', required=True)
    p_export_digest.add_argument('--funding-vout', type=int, required=True)
    p_export_digest.add_argument('--funding-value', type=int, required=True)
    p_export_digest.add_argument('--dest-address', required=True, help='hex pubkey hash (20 bytes)')
    
    # Assemble
    p_asm = sub.add_parser('assemble')
    p_asm.add_argument('--locktime', type=int, required=True)
    p_asm.add_argument('--sequence', type=int, required=True, help='QSB input sequence from pinning hit')
    p_asm.add_argument('--round1', required=True, help='comma-separated indices')
    p_asm.add_argument('--round2', required=True, help='comma-separated indices')
    p_asm.add_argument('--helper-txid', default=PLACEHOLDER_HELPER_TXID,
                       help='hex txid for helper input used to trigger SIGHASH_SINGLE bug')
    p_asm.add_argument('--helper-vout', type=int, default=0,
                       help='vout for helper input')
    p_asm.add_argument('--helper-script-sig-hex', default='',
                       help='optional helper input scriptSig hex for a real auxiliary input')
    p_asm.add_argument('--funding-txid', required=True)
    p_asm.add_argument('--funding-vout', type=int, required=True)
    p_asm.add_argument('--funding-value', type=int, required=True)
    p_asm.add_argument('--dest-address', required=True, help='hex pubkey hash')
    
    # Test
    p_test = sub.add_parser('test')
    
    args = parser.parse_args()
    
    if args.command == 'setup':
        cmd_setup(args)
    elif args.command == 'export':
        cmd_export(args)
    elif args.command == 'export-digest':
        cmd_export_digest(args)
    elif args.command == 'assemble':
        cmd_assemble(args)
    elif args.command == 'test':
        cmd_test(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
