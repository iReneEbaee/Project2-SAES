import random
import unittest
import saes


class AlgorithmTests(unittest.TestCase):
    def test_pdf_examples(self):
        self.assertEqual(saes.expand_key(0x2D55), (0x2D55, 0xBCE9, 0xA34A))
        self.assertEqual(0xA749 ^ 0x2D55, 0x8A1C)
        self.assertEqual(saes.substitute(0x8A1C), 0x604C)
        self.assertEqual(saes.shift_rows(0x604C), 0x6C40)
        self.assertEqual(saes.mix_columns(0x6C40), 0x3743)
        self.assertEqual(saes.gf_multiply(4, 12), 5)

    def test_known_answer(self):
        self.assertEqual(saes.encrypt_block(0xD728, 0x4AF5), 0x24EC)
        self.assertEqual(saes.decrypt_block(0x24EC, 0x4AF5), 0xD728)

    def test_all_plaintexts(self):
        ciphertexts = set()
        for plain in range(65536):
            cipher = saes.encrypt_block(plain, 0x4AF5)
            ciphertexts.add(cipher)
            self.assertEqual(saes.decrypt_block(cipher, 0x4AF5), plain)
        self.assertEqual(len(ciphertexts), 65536)

    def test_multiple_and_varied_keys(self):
        generator = random.Random(42)
        for _ in range(300):
            plain, key = generator.randrange(65536), generator.randrange(65536)
            self.assertEqual(saes.decrypt_block(saes.encrypt_block(plain, key), key), plain)
            for count in (2, 3):
                secret = generator.randrange(1 << (16 * count))
                cipher = saes.multiple_encrypt(plain, secret, count)
                self.assertEqual(saes.multiple_decrypt(cipher, secret, count), plain)
        self.assertEqual(saes.multiple_encrypt(0x1234, 0xABCD5678), saes.encrypt_block(saes.encrypt_block(0x1234, 0xABCD), 0x5678))

    def test_strings_and_cbc(self):
        for length in range(34):
            data = bytes(range(length))
            encrypted = saes.transform_bytes(data, 0x1234)
            self.assertEqual(saes.transform_bytes(encrypted, 0x1234, True), data)
            cipher = saes.cbc_encrypt(data, 0xABCD, 0x2468)
            self.assertEqual(saes.cbc_decrypt(cipher, 0xABCD, 0x2468), data)

    def test_cbc_tampering(self):
        cipher = saes.cbc_encrypt(b'Hello CBC mode!', 0x4AF5, 0x1234)
        modified = bytearray(cipher)
        modified[0] ^= 1
        before = saes.cbc_decrypt(cipher, 0x4AF5, 0x1234, False)
        after = saes.cbc_decrypt(modified, 0x4AF5, 0x1234, False)
        self.assertNotEqual(before[:2], after[:2])
        self.assertEqual(int.from_bytes(before[2:4], 'big') ^ int.from_bytes(after[2:4], 'big'), 0x0100)
        self.assertEqual(before[4:], after[4:])
        other_iv = saes.cbc_decrypt(cipher, 0x4AF5, 0x1235, False)
        self.assertEqual(before[2:], other_iv[2:])
        self.assertEqual(before[1] ^ other_iv[1], 1)

    def test_full_mitm(self):
        key = 0x1234ABCD
        pairs = [(plain, saes.multiple_encrypt(plain, key)) for plain in (0x1234, 0x5678, 0x9ABC)]
        candidates = saes.meet_in_the_middle(pairs)
        self.assertIn(key, candidates)
        self.assertTrue(all(all(saes.multiple_encrypt(plain, candidate) == cipher for plain, cipher in pairs) for candidate in candidates))

    def test_invalid_inputs(self):
        for text in ('', '0' * 15, '2' * 16, '0' * 17):
            with self.assertRaises(ValueError):
                saes.parse_bits(text)
        for value in (-1, 65536, True):
            with self.assertRaises(ValueError):
                saes.encrypt_block(value, 0)
        for data in (b'', b'x', b'\x00\x00', b'\x01\x02'):
            with self.assertRaises(ValueError):
                saes.unpad(data)
        with self.assertRaises(ValueError):
            saes.meet_in_the_middle([])
        with self.assertRaises(InterruptedError):
            saes.meet_in_the_middle([(0, 0)], cancelled=lambda: True)


if __name__ == '__main__':
    unittest.main(verbosity=2)

