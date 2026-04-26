import os
import sys
import unittest


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PIPELINE_DIR = os.path.join(REPO_ROOT, 'pipeline')
sys.path.insert(0, PIPELINE_DIR)

from secp256k1 import G, point_mul, compress_pubkey, qsb_puzzle_hash, hash160, ripemd160  # noqa: E402


class PubkeyHashSemanticsTests(unittest.TestCase):
    def test_qsb_puzzle_hash_uses_plain_ripemd160(self):
        pubkey = compress_pubkey(point_mul(0x12345, G))
        self.assertEqual(qsb_puzzle_hash(pubkey), ripemd160(pubkey))
        self.assertNotEqual(qsb_puzzle_hash(pubkey), hash160(pubkey))

    def test_qsb_puzzle_hash_rejects_non_compressed_length(self):
        with self.assertRaises(ValueError):
            qsb_puzzle_hash(b'\x02' + b'\x11' * 31)

    def test_qsb_puzzle_hash_rejects_invalid_prefix(self):
        with self.assertRaises(ValueError):
            qsb_puzzle_hash(b'\x04' + b'\x11' * 32)


if __name__ == '__main__':
    unittest.main()
