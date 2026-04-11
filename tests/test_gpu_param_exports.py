import json
import os
import struct
import sys
import tempfile
import unittest
from types import SimpleNamespace


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PIPELINE_DIR = os.path.join(REPO_ROOT, 'pipeline')
sys.path.insert(0, PIPELINE_DIR)

from qsb_pipeline import cmd_export, cmd_setup, compute_sha256_midstate


def load_pinning_params_py(path):
    with open(path, 'rb') as f:
        total_preimage_len = struct.unpack('<I', f.read(4))[0]
        tail_data_len = struct.unpack('<I', f.read(4))[0]
        midstate = struct.unpack('>8I', f.read(32))
        tail_data = f.read(tail_data_len)
        neg_r_inv = f.read(32)
        u2r_x = f.read(32)
        u2r_y = f.read(32)
        trailing = f.read()
    return {
        'total_preimage_len': total_preimage_len,
        'tail_data_len': tail_data_len,
        'midstate': midstate,
        'tail_data': tail_data,
        'neg_r_inv': neg_r_inv,
        'u2r_x': u2r_x,
        'u2r_y': u2r_y,
        'trailing': trailing,
    }


def load_digest_params_py(path):
    with open(path, 'rb') as f:
        n = struct.unpack('<I', f.read(4))[0]
        t = struct.unpack('<I', f.read(4))[0]
        total_preimage_len = struct.unpack('<I', f.read(4))[0]
        tail_section_len = struct.unpack('<I', f.read(4))[0]
        tx_suffix_len = struct.unpack('<I', f.read(4))[0]
        midstate = struct.unpack('>8I', f.read(32))
        dummy_sigs = f.read(n * 10)
        tail_section = f.read(tail_section_len)
        tx_suffix = f.read(tx_suffix_len)
        neg_r_inv = f.read(32)
        u2r_x = f.read(32)
        u2r_y = f.read(32)
        trailing = f.read()
    return {
        'n': n,
        't': t,
        'total_preimage_len': total_preimage_len,
        'tail_section_len': tail_section_len,
        'tx_suffix_len': tx_suffix_len,
        'midstate': midstate,
        'dummy_sigs': dummy_sigs,
        'tail_section': tail_section,
        'tx_suffix': tx_suffix,
        'neg_r_inv': neg_r_inv,
        'u2r_x': u2r_x,
        'u2r_y': u2r_y,
        'trailing': trailing,
    }


class GPUParamExportTests(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self.tmpdir = tempfile.TemporaryDirectory()
        os.chdir(self.tmpdir.name)
        self.helper_txid = 'aa' * 32
        self.helper_vout = 7
        self.funding_txid = '11' * 32
        self.funding_vout = 1

        cmd_setup(SimpleNamespace(config='test', seed=1, funding_mode='bare'))
        cmd_export(
            SimpleNamespace(
                helper_txid=self.helper_txid,
                helper_vout=self.helper_vout,
                funding_txid=self.funding_txid,
                funding_vout=self.funding_vout,
                funding_value=50_000,
                dest_address='22' * 20,
            )
        )

    def tearDown(self):
        os.chdir(self._cwd)
        self.tmpdir.cleanup()

    def test_pinning_bin_matches_gpu_reader_layout(self):
        with open('gpu_pinning_params.json') as f:
            meta = json.load(f)
        parsed = load_pinning_params_py('pinning.bin')

        self.assertEqual(parsed['trailing'], b'')
        self.assertEqual(parsed['total_preimage_len'], meta['total_preimage_len'])
        self.assertEqual(parsed['tail_data_len'], meta['tail_data_len'])
        self.assertEqual(parsed['tail_data'].hex(), meta['tail_data'])
        self.assertEqual(parsed['neg_r_inv'].hex(), meta['neg_r_inv'])
        self.assertEqual(parsed['u2r_x'].hex(), meta['u2r_x'])
        self.assertEqual(parsed['u2r_y'].hex(), meta['u2r_y'])

        tx_prefix = bytes.fromhex(meta['tx_prefix'])
        expected_midstate = compute_sha256_midstate(tx_prefix, meta['midstate_blocks'])
        self.assertEqual(parsed['midstate'], expected_midstate)

        self.assertEqual(meta['helper_txid'], self.helper_txid)
        self.assertEqual(meta['helper_vout'], self.helper_vout)
        self.assertEqual(meta['helper_input_index'], 0)
        self.assertEqual(meta['qsb_input_index'], 1)
        self.assertEqual(meta['output_count'], 1)
        self.assertEqual(tx_prefix[4], 2)  # input count varint
        self.assertEqual(tx_prefix[5:37], bytes.fromhex(self.helper_txid)[::-1])

    def test_digest_bins_match_gpu_reader_layout(self):
        for round_idx in (1, 2):
            with open(f'gpu_digest_r{round_idx}_params.json') as f:
                meta = json.load(f)
            parsed = load_digest_params_py(f'digest_r{round_idx}.bin')

            self.assertEqual(parsed['trailing'], b'')
            self.assertEqual(parsed['n'], meta['n'])
            self.assertEqual(parsed['t'], meta['t'])
            self.assertEqual(parsed['total_preimage_len'], meta['total_preimage_len'])
            self.assertEqual(parsed['tail_section_len'], meta['tail_section_len'])
            self.assertEqual(parsed['tx_suffix_len'], meta['tx_suffix_len'])
            self.assertEqual(parsed['tail_section'].hex(), meta['tail_section'])
            self.assertEqual(parsed['tx_suffix'].hex(), meta['tx_suffix'])
            self.assertEqual(parsed['neg_r_inv'].hex(), meta['neg_r_inv'])
            self.assertEqual(parsed['u2r_x'].hex(), meta['u2r_x'])
            self.assertEqual(parsed['u2r_y'].hex(), meta['u2r_y'])

            expected_dummy = b''.join(bytes.fromhex(x) for x in meta['dummy_sig_pushes'])
            self.assertEqual(parsed['dummy_sigs'], expected_dummy)

            fixed_prefix = bytes.fromhex(meta['fixed_prefix'])
            expected_midstate = compute_sha256_midstate(fixed_prefix, meta['midstate_blocks'])
            self.assertEqual(parsed['midstate'], expected_midstate)
            self.assertEqual(meta['helper_txid'], self.helper_txid)
            self.assertEqual(meta['helper_vout'], self.helper_vout)
            self.assertEqual(meta['helper_input_index'], 0)
            self.assertEqual(meta['qsb_input_index'], 1)
            self.assertEqual(meta['output_count'], 1)
            self.assertEqual(bytes.fromhex(meta['tx_prefix'])[4], 2)


if __name__ == '__main__':
    unittest.main()
