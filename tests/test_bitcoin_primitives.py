import os
import sys
import unittest


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PIPELINE_DIR = os.path.join(REPO_ROOT, 'pipeline')
sys.path.insert(0, PIPELINE_DIR)

from bitcoin_tx import (  # noqa: E402
    Transaction,
    TxIn,
    TxOut,
    QSBScriptBuilder,
    push_data,
    push_number,
    find_and_delete,
    serialize_varint,
    _valid_small_r_values,
)
from secp256k1 import (  # noqa: E402
    P,
    N,
    G,
    INF,
    modinv,
    point_add,
    point_mul,
    point_neg,
    compress_pubkey,
    decompress_pubkey,
    ecdsa_sign,
    ecdsa_sign_with_k,
    ecdsa_verify,
    ecdsa_recover,
    encode_der_sig,
    is_valid_der_sig,
    parse_der,
    int_to_der_int,
    sha256,
    sha256d,
    ripemd160,
    hash160,
)


class Secp256k1PrimitiveTests(unittest.TestCase):
    def test_modinv_negative_input(self):
        inv = modinv(-3, N)
        self.assertEqual((-3 * inv) % N, 1)

    def test_modinv_rejects_zero(self):
        with self.assertRaises(ValueError):
            modinv(0, N)

    def test_point_add_identity_and_inverse(self):
        self.assertEqual(point_add(G, INF), G)
        self.assertEqual(point_add(point_neg(G), G), INF)

    def test_point_mul_order_returns_infinity(self):
        self.assertEqual(point_mul(N, G), INF)

    def test_compress_decompress_round_trip(self):
        for scalar in [1, 2, 42, 999999, N - 1]:
            point = point_mul(scalar, G)
            self.assertEqual(decompress_pubkey(compress_pubkey(point)), point)

    def test_decompress_rejects_invalid_prefix(self):
        with self.assertRaises(ValueError):
            decompress_pubkey(b'\x04' + G[0].to_bytes(32, 'big'))

    def test_sign_verify_and_recover(self):
        privkey = 0xDEADBEEF
        pubkey = point_mul(privkey, G)
        z = int.from_bytes(sha256(b'primitive-signature-check'), 'big')
        r, s = ecdsa_sign(privkey, z)
        self.assertTrue(ecdsa_verify(pubkey, z, r, s))

        recovered = None
        for flag in [0, 1]:
            candidate = ecdsa_recover(r, s, z, recovery_flag=flag)
            if candidate == pubkey:
                recovered = candidate
                break
        self.assertEqual(recovered, pubkey)

    def test_sign_with_k_matches_expected_r(self):
        z = int.from_bytes(sha256(b'sign-with-k'), 'big')
        r, s = ecdsa_sign_with_k(0x12345678, z, 42)
        self.assertEqual(r, point_mul(42, G)[0] % N)
        self.assertTrue(ecdsa_verify(point_mul(0x12345678, G), z, r, s))


class DerAndHashPrimitiveTests(unittest.TestCase):
    def test_der_rejects_wrong_tag(self):
        sig = encode_der_sig(1, 1)
        self.assertFalse(is_valid_der_sig(b'\x31' + sig[1:]))

    def test_der_rejects_wrong_length(self):
        sig = encode_der_sig(1, 1)
        self.assertFalse(is_valid_der_sig(sig[:1] + bytes([sig[1] + 1]) + sig[2:]))

    def test_der_rejects_negative_integer(self):
        sig = bytes([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01, 0x01])
        self.assertFalse(is_valid_der_sig(sig))

    def test_der_rejects_unnecessary_padding(self):
        sig = bytes([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01, 0x01])
        self.assertFalse(is_valid_der_sig(sig))

    def test_int_to_der_int_padding_rules(self):
        self.assertEqual(int_to_der_int(0x80), b'\x00\x80')
        self.assertEqual(int_to_der_int(0x7F), b'\x7f')

    def test_parse_der_round_trip(self):
        for r, s in [(1, 1), (12345, 67890), (N - 1, N // 2)]:
            self.assertEqual(parse_der(encode_der_sig(r, s)), (r, s))

    def test_hash_functions_known_vectors(self):
        self.assertEqual(
            sha256(b''),
            bytes.fromhex(
                'e3b0c44298fc1c149afbf4c8996fb924'
                '27ae41e4649b934ca495991b7852b855'
            ),
        )
        self.assertEqual(
            ripemd160(b''),
            bytes.fromhex('9c1185a5c5e9fc54612808977ee8f548b2258d31'),
        )
        self.assertEqual(sha256d(b'test'), sha256(sha256(b'test')))
        self.assertEqual(hash160(b'hello'), ripemd160(sha256(b'hello')))


class TransactionAndScriptPrimitiveTests(unittest.TestCase):
    def test_serialize_varint_examples(self):
        self.assertEqual(serialize_varint(0), b'\x00')
        self.assertEqual(serialize_varint(0xfc), b'\xfc')
        self.assertEqual(serialize_varint(0xfd), b'\xfd\xfd\x00')
        self.assertEqual(serialize_varint(0xffff), b'\xfd\xff\xff')
        self.assertEqual(serialize_varint(0x10000), b'\xfe\x00\x00\x01\x00')

    def test_sighash_single_bug_returns_one(self):
        tx = Transaction(version=1, locktime=0)
        tx.add_input(TxIn(b'\x00' * 32, 0, b'', 0xffffffff))
        tx.add_input(TxIn(b'\x01' * 32, 0, b'', 0xffffffff))
        tx.add_output(TxOut(50_000, b'\x00' * 25))
        self.assertEqual(tx.sighash(1, b'\x00' * 25, sighash_type=0x03), 1)

    def test_sighash_changes_with_locktime(self):
        script_code = b'\x00' * 25
        tx1 = Transaction(version=1, locktime=0)
        tx1.add_input(TxIn(b'\x01' * 32, 0, b'', 0xffffffff))
        tx1.add_output(TxOut(50_000, b'\x00' * 25))
        tx2 = Transaction(version=1, locktime=1)
        tx2.add_input(TxIn(b'\x01' * 32, 0, b'', 0xffffffff))
        tx2.add_output(TxOut(50_000, b'\x00' * 25))
        self.assertNotEqual(tx1.sighash(0, script_code), tx2.sighash(0, script_code))

    def test_push_data_and_push_number_encodings(self):
        self.assertEqual(push_data(b'\xaa\xbb'), b'\x02\xaa\xbb')
        self.assertEqual(push_data(b''), b'\x00')
        self.assertEqual(push_data(b'\x00' * 100)[:2], b'\x4c\x64')
        self.assertEqual(push_data(b'\x00' * 300)[:3], b'\x4d,\x01')
        self.assertEqual(push_number(0), b'\x00')
        self.assertEqual(push_number(1), b'\x51')
        self.assertEqual(push_number(16), b'\x60')

    def test_find_and_delete_removes_all_occurrences(self):
        needle = b'\xaa\xbb'
        script = push_data(needle) + push_data(b'\xcc\xdd') + push_data(needle)
        self.assertEqual(find_and_delete(script, needle), push_data(b'\xcc\xdd'))


class QsbBuilderPrimitiveTests(unittest.TestCase):
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

    def test_valid_small_r_values_are_curve_x_coordinates(self):
        valid = _valid_small_r_values()
        self.assertGreater(len(valid), 0)
        for r in valid:
            y_sq = (pow(r, 3, P) + 7) % P
            y = pow(y_sq, (P + 1) // 4, P)
            self.assertEqual(pow(y, 2, P), y_sq)

    def test_hors_commitments_are_hash160_of_secrets(self):
        for round_idx in range(2):
            for i in range(10):
                self.assertEqual(
                    self.builder.hors_commitments[round_idx][i],
                    hash160(self.builder.hors_secrets[round_idx][i]),
                )

    def test_dummy_signatures_are_unique_and_valid(self):
        for round_idx in range(2):
            sigs = self.builder.dummy_sigs[round_idx]
            self.assertEqual(len(sigs), len(set(map(bytes, sigs))))
            self.assertTrue(all(len(sig) == 9 and is_valid_der_sig(sig) for sig in sigs))

    def test_config_a_script_stays_within_limit(self):
        os.urandom = self._orig_urandom
        builder = QSBScriptBuilder(n=150, t1_signed=8, t1_bonus=1, t2_signed=7, t2_bonus=2)
        builder.generate_keys()
        script = builder.build_full_script(
            encode_der_sig(111, 222, sighash=0x01),
            encode_der_sig(333, 444, sighash=0x01),
            encode_der_sig(555, 666, sighash=0x01),
        )
        self.assertLessEqual(len(script), 10_000)

