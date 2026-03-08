"""
Unit Tests for SecureChat — test_securechat.py
Run with:  python -m unittest test_securechat -v
"""
import unittest
import hashlib
from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    load_public_key,
    aes_encrypt,
    aes_decrypt,
    rsa_encrypt,
    rsa_decrypt,
)


def hash_password(pw):
    """SHA-256 hash of a password string."""
    return hashlib.sha256(pw.encode()).hexdigest()


class TestAESEncryption(unittest.TestCase):

    def test_aes_encrypt_returns_three_values(self):
        """aes_encrypt must return ciphertext, iv, and key"""
        ct, iv, key = aes_encrypt("hello world")
        self.assertIsNotNone(ct)
        self.assertIsNotNone(iv)
        self.assertIsNotNone(key)

    def test_aes_decrypt_recovers_plaintext(self):
        """Decrypted text must match original plaintext"""
        original = "SecureChat test message"
        ct, iv, key = aes_encrypt(original)
        result = aes_decrypt(ct, iv, key)
        self.assertEqual(result, original)

    def test_aes_empty_string(self):
        """Empty string should encrypt and decrypt without error"""
        ct, iv, key = aes_encrypt("")
        result = aes_decrypt(ct, iv, key)
        self.assertEqual(result, "")

    def test_aes_different_keys_each_call(self):
        """Every call to aes_encrypt must produce a unique key (random key per message)"""
        _, _, key1 = aes_encrypt("same message")
        _, _, key2 = aes_encrypt("same message")
        self.assertNotEqual(key1, key2)

    def test_aes_wrong_key_fails(self):
        """Decrypting with the wrong key must raise an exception"""
        ct, iv, _ = aes_encrypt("secret")
        _, _, wrong_key = aes_encrypt("other")
        with self.assertRaises(Exception):
            aes_decrypt(ct, iv, wrong_key)


class TestRSAEncryption(unittest.TestCase):

    def setUp(self):
        self.private_key, self.public_key = generate_rsa_keypair()

    def test_rsa_encrypt_decrypt(self):
        """RSA encrypt then decrypt must recover original bytes"""
        data = b"aes-session-key-32-bytes-padding"
        encrypted = rsa_encrypt(self.public_key, data)
        decrypted = rsa_decrypt(self.private_key, encrypted)
        self.assertEqual(decrypted, data)

    def test_rsa_wrong_key_fails(self):
        """Decrypting with a different private key must fail"""
        other_private, _ = generate_rsa_keypair()
        data = b"some key bytes here 123456789012"
        encrypted = rsa_encrypt(self.public_key, data)
        with self.assertRaises(Exception):
            rsa_decrypt(other_private, encrypted)

    def test_serialize_and_load_public_key(self):
        """Serialised public key must reload identically"""
        pem = serialize_public_key(self.public_key)
        loaded = load_public_key(pem)
        data = b"test key data 1234567890123456"
        enc = rsa_encrypt(loaded, data)
        dec = rsa_decrypt(self.private_key, enc)
        self.assertEqual(dec, data)


class TestPasswordHashing(unittest.TestCase):

    def test_same_password_same_hash(self):
        """Same password must always produce the same hash"""
        self.assertEqual(hash_password("mypassword"), hash_password("mypassword"))

    def test_different_passwords_different_hashes(self):
        """Different passwords must produce different hashes"""
        self.assertNotEqual(hash_password("password1"), hash_password("password2"))

    def test_hash_is_64_chars(self):
        """SHA-256 hex digest must be exactly 64 characters"""
        self.assertEqual(len(hash_password("test")), 64)


if __name__ == "__main__":
    unittest.main()