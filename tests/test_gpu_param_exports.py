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

from qsb_pipeline import (
    cmd_export,
    cmd_export_digest,
    cmd_setup,
    compute_sha256_midstate,
    DEFAULT_SEQUENCE,
    build_spending_transaction,
    QSB_INPUT_INDEX,
)
from bitcoin_tx import Transaction, TxIn, find_and_delete


def load_pinning_params_py(path):
    with open(path, 'rb') as f:
        total_preimage_len = struct.unpack('<I', f.read(4))[0]
        suffix_len = struct.unpack('<I', f.read(4))[0]
        sequence_offset = struct.unpack('<I', f.read(4))[0]
        locktime_offset = struct.unpack('<I', f.read(4))[0]
        midstate = struct.unpack('>8I', f.read(32))
        suffix_template = f.read(suffix_len)
        neg_r_inv = f.read(32)
        u2r_x = f.read(32)
        u2r_y = f.read(32)
        trailing = f.read()
    return {
        'total_preimage_len': total_preimage_len,
        'suffix_len': suffix_len,
        'sequence_offset': sequence_offset,
        'locktime_offset': locktime_offset,
        'midstate': midstate,
        'suffix_template': suffix_template,
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
        self.sequence = DEFAULT_SEQUENCE
        self.locktime = 8

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
        cmd_export_digest(
            SimpleNamespace(
                sequence=self.sequence,
                locktime=self.locktime,
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
        with open('qsb_state.json') as f:
            state = json.load(f)
        parsed = load_pinning_params_py('pinning.bin')

        self.assertEqual(parsed['trailing'], b'')
        self.assertEqual(parsed['total_preimage_len'], meta['total_preimage_len'])
        self.assertEqual(parsed['suffix_len'], meta['suffix_template_len'])
        self.assertEqual(parsed['sequence_offset'], meta['sequence_offset'])
        self.assertEqual(parsed['locktime_offset'], meta['locktime_offset'])
        self.assertEqual(parsed['suffix_template'].hex(), meta['suffix_template'])
        self.assertEqual(parsed['neg_r_inv'].hex(), meta['neg_r_inv'])
        self.assertEqual(parsed['u2r_x'].hex(), meta['u2r_x'])
        self.assertEqual(parsed['u2r_y'].hex(), meta['u2r_y'])

        fixed_prefix = bytes.fromhex(meta['fixed_prefix'])
        covered_prefix_len = meta['midstate_blocks'] * 64
        covered_prefix = fixed_prefix[:covered_prefix_len]
        fixed_prefix_remainder = fixed_prefix[covered_prefix_len:]
        expected_midstate = compute_sha256_midstate(fixed_prefix, meta['midstate_blocks'])
        self.assertEqual(parsed['midstate'], expected_midstate)

        self.assertEqual(meta['helper_txid'], self.helper_txid)
        self.assertEqual(meta['helper_vout'], self.helper_vout)
        self.assertEqual(meta['helper_input_index'], 0)
        self.assertEqual(meta['qsb_input_index'], 1)
        self.assertEqual(meta['output_count'], 1)
        self.assertEqual(fixed_prefix[4], 2)  # input count varint
        self.assertEqual(fixed_prefix[5:37], bytes.fromhex(self.helper_txid)[::-1])
        self.assertLessEqual(parsed['suffix_len'], 119)
        self.assertEqual(parsed['suffix_template'][:len(fixed_prefix_remainder)], fixed_prefix_remainder)

        tx, _ = build_spending_transaction(
            bytes.fromhex(self.helper_txid)[::-1],
            self.helper_vout,
            bytes.fromhex(self.funding_txid)[::-1],
            self.funding_vout,
            50_000,
            '22' * 20,
        )
        pin_script_code = find_and_delete(bytes.fromhex(state['full_script_hex']), bytes.fromhex(state['pin_sig']))
        tx_copy = Transaction(tx.version, tx.locktime)
        for idx, inp in enumerate(tx.inputs):
            script_sig = pin_script_code if idx == QSB_INPUT_INDEX else b''
            tx_copy.add_input(TxIn(inp.txid, inp.vout, script_sig, inp.sequence))
        for out in tx.outputs:
            tx_copy.add_output(out)
        expected_preimage = tx_copy.serialize() + struct.pack('<I', 0x01)

        suffix = bytearray(parsed['suffix_template'])
        suffix[parsed['sequence_offset']:parsed['sequence_offset'] + 4] = struct.pack('<I', self.sequence)
        suffix[parsed['locktime_offset']:parsed['locktime_offset'] + 4] = struct.pack('<I', tx.locktime)
        self.assertEqual(covered_prefix + bytes(suffix), expected_preimage)
        self.assertEqual(len(expected_preimage), meta['total_preimage_len'])

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
            self.assertEqual(meta['sequence'], self.sequence)
            self.assertEqual(meta['locktime'], self.locktime)
            self.assertEqual(meta['helper_txid'], self.helper_txid)
            self.assertEqual(meta['helper_vout'], self.helper_vout)
            self.assertEqual(meta['helper_input_index'], 0)
            self.assertEqual(meta['qsb_input_index'], 1)
            self.assertEqual(meta['output_count'], 1)
            self.assertEqual(bytes.fromhex(meta['tx_prefix'])[4], 2)

            tx, _ = build_spending_transaction(
                bytes.fromhex(self.helper_txid)[::-1],
                self.helper_vout,
                bytes.fromhex(self.funding_txid)[::-1],
                self.funding_vout,
                50_000,
                '22' * 20,
                locktime=self.locktime,
                qsb_sequence=self.sequence,
            )
            removed = set(range(meta['t']))
            remaining_pushes = b''.join(
                bytes.fromhex(push)
                for idx, push in enumerate(meta['dummy_sig_pushes'])
                if idx not in removed
            )
            script_code = bytes.fromhex(meta['hors_section']) + remaining_pushes + bytes.fromhex(meta['tail_section'])
            tx_copy = Transaction(tx.version, tx.locktime)
            for idx, inp in enumerate(tx.inputs):
                script_sig = script_code if idx == QSB_INPUT_INDEX else b''
                tx_copy.add_input(TxIn(inp.txid, inp.vout, script_sig, inp.sequence))
            for out in tx.outputs:
                tx_copy.add_output(out)
            expected_preimage = tx_copy.serialize() + struct.pack('<I', 0x01)
            reconstructed = (
                bytes.fromhex(meta['fixed_prefix']) +
                remaining_pushes +
                bytes.fromhex(meta['tail_section']) +
                bytes.fromhex(meta['tx_suffix'])
            )
            self.assertEqual(reconstructed, expected_preimage)
            self.assertEqual(len(expected_preimage), meta['total_preimage_len'])


if __name__ == '__main__':
    unittest.main()
