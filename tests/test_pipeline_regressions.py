import os
import sys
import unittest


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PIPELINE_DIR = os.path.join(REPO_ROOT, 'pipeline')
sys.path.insert(0, PIPELINE_DIR)

from qsb_pipeline import (
    funding_output_script,
    build_unlocking_script,
    infer_funding_mode,
    p2sh_script_pubkey,
)
from bitcoin_tx import push_data
from secp256k1 import encode_der_sig, parse_der


class PipelineRegressionTests(unittest.TestCase):
    def test_bare_funding_output_uses_full_script_directly(self):
        full_script = bytes.fromhex('51ac')
        self.assertEqual(funding_output_script(full_script, 'bare'), full_script)

    def test_p2sh_funding_output_wraps_script_hash(self):
        full_script = bytes.fromhex('51ac')
        self.assertEqual(funding_output_script(full_script, 'p2sh'), p2sh_script_pubkey(full_script))

    def test_bare_unlocking_script_does_not_append_redeem_script(self):
        unlocking_stack = b'\x01\x02'
        full_script = b'\x51\xac'
        self.assertEqual(build_unlocking_script(unlocking_stack, full_script, 'bare'), unlocking_stack)

    def test_p2sh_unlocking_script_appends_redeem_script(self):
        unlocking_stack = b'\x01\x02'
        full_script = b'\x51\xac'
        expected = unlocking_stack + push_data(full_script)
        self.assertEqual(build_unlocking_script(unlocking_stack, full_script, 'p2sh'), expected)

    def test_infer_funding_mode_defaults_old_states_to_p2sh(self):
        legacy_state = {'p2sh_script_pubkey': 'deadbeef'}
        self.assertEqual(infer_funding_mode(legacy_state), 'p2sh')

    def test_infer_funding_mode_prefers_explicit_setting(self):
        self.assertEqual(infer_funding_mode({'funding_mode': 'bare'}), 'bare')
        self.assertEqual(infer_funding_mode({'funding_mode': 'p2sh'}), 'p2sh')

    def test_parse_der_round_trip(self):
        sig = encode_der_sig(1, 2, sighash=0x01)
        self.assertEqual(parse_der(sig), (1, 2))

    def test_parse_der_rejects_invalid_bytes(self):
        self.assertEqual(parse_der(b'\x30\x01\x00'), (None, None))


if __name__ == '__main__':
    unittest.main()
