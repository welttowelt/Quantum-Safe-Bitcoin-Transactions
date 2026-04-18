import os
import sys
import unittest


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PIPELINE_DIR = os.path.join(REPO_ROOT, 'pipeline')
sys.path.insert(0, PIPELINE_DIR)

from bitcoin_tx import (  # noqa: E402
    OP_CHECKMULTISIG,
    OP_CHECKSIGVERIFY,
    OP_PUSHDATA1,
    OP_PUSHDATA2,
    OP_1,
    OP_16,
    QSBScriptBuilder,
    push_data,
)
from secp256k1 import encode_der_sig  # noqa: E402


def iter_script_opcodes(script):
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if op == 0:
            continue
        if 1 <= op <= 75:
            i += op
            continue
        if op == OP_PUSHDATA1:
            size = script[i]
            i += 1 + size
            continue
        if op == OP_PUSHDATA2:
            size = int.from_bytes(script[i:i + 2], 'little')
            i += 2 + size
            continue
        if OP_1 <= op <= OP_16:
            continue
        yield op


class RoundScriptAuditTests(unittest.TestCase):
    def setUp(self):
        self._orig_urandom = os.urandom
        counter = 0

        def deterministic_urandom(n):
            nonlocal counter
            block = bytes(((counter + i) % 256 for i in range(n)))
            counter += 1
            return block

        os.urandom = deterministic_urandom
        self.builder = QSBScriptBuilder(n=10, t1_signed=2, t2_signed=2)
        self.builder.generate_keys()

    def tearDown(self):
        os.urandom = self._orig_urandom

    def test_round_script_has_one_direct_checksigverify_and_one_checkmultisig(self):
        sig_nonce = encode_der_sig(333, 444, sighash=0x01)
        script = self.builder.build_round_script(0, sig_nonce)
        opcodes = list(iter_script_opcodes(script))
        self.assertEqual(opcodes.count(OP_CHECKSIGVERIFY), 1)
        self.assertEqual(opcodes.count(OP_CHECKMULTISIG), 1)

    def test_round_script_pushes_sig_nonce_once(self):
        sig_nonce = encode_der_sig(333, 444, sighash=0x01)
        script = self.builder.build_round_script(0, sig_nonce)
        self.assertEqual(script.count(push_data(sig_nonce)), 1)

    def test_round_script_code_removes_selected_dummy_signatures_only(self):
        sig_nonce = encode_der_sig(333, 444, sighash=0x01)
        selected = [
            self.builder.dummy_sigs[0][0],
            self.builder.dummy_sigs[0][1],
        ]
        script_code = self.builder.get_round_script_code(0, sig_nonce, selected)
        self.assertIn(push_data(sig_nonce), script_code)
        for dummy_sig in selected:
            self.assertNotIn(push_data(dummy_sig), script_code)

    def test_pinning_script_still_has_two_direct_checksigverify_steps(self):
        sig_nonce = encode_der_sig(111, 222, sighash=0x01)
        script = self.builder.build_pinning_script(sig_nonce)
        self.assertEqual(script.count(bytes([OP_CHECKSIGVERIFY])), 2)
