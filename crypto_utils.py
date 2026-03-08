"""
=============================================================
  CRYPTO UTILITIES  |  crypto_utils.py
  RSA key generation, AES-256 encryption/decryption helpers
=============================================================
"""

import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ─────────────────────────────────────────────────────────
#  RSA KEY GENERATION
# ─────────────────────────────────────────────────────────

def generate_rsa_keypair():
    """
    Generate a 2048-bit RSA key pair.
    Returns (private_key, public_key) objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key) -> str:
    """Convert public key to PEM string for transmission."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode("utf-8")


def load_public_key(pem_str: str):
    """Load a public key from a PEM string."""
    return serialization.load_pem_public_key(
        pem_str.encode("utf-8"),
        backend=default_backend()
    )


# ─────────────────────────────────────────────────────────
#  RSA ENCRYPT / DECRYPT  (used for AES key exchange)
# ─────────────────────────────────────────────────────────

def rsa_encrypt(public_key, data: bytes) -> str:
    """
    Encrypt bytes with RSA public key using OAEP padding.
    Returns base64-encoded ciphertext string.
    """
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode("utf-8")


def rsa_decrypt(private_key, ciphertext_b64: str) -> bytes:
    """
    Decrypt base64-encoded RSA ciphertext with private key.
    Returns original plaintext bytes.
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# ─────────────────────────────────────────────────────────
#  AES-256-CBC ENCRYPT / DECRYPT  (used for messages)
# ─────────────────────────────────────────────────────────

def aes_encrypt(plaintext: str) -> tuple[str, str, str]:
    """
    Encrypt a plaintext string using AES-256-CBC.

    Returns:
        (ciphertext_b64, iv_b64, aes_key_b64)
        - ciphertext_b64 : base64-encoded encrypted message
        - iv_b64         : base64-encoded initialization vector
        - aes_key_b64    : base64-encoded 256-bit AES key (raw, not encrypted)
    """
    aes_key = os.urandom(32)       # 256-bit key
    iv = os.urandom(16)            # 128-bit IV

    # PKCS7 manual padding
    data = plaintext.encode("utf-8")
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    return (
        base64.b64encode(ciphertext).decode("utf-8"),
        base64.b64encode(iv).decode("utf-8"),
        base64.b64encode(aes_key).decode("utf-8")
    )


def aes_decrypt(ciphertext_b64: str, iv_b64: str, aes_key_b64: str) -> str:
    """
    Decrypt an AES-256-CBC encrypted message.

    Args:
        ciphertext_b64 : base64-encoded ciphertext
        iv_b64         : base64-encoded IV
        aes_key_b64    : base64-encoded AES key

    Returns:
        Original plaintext string.

    Raises:
        Exception: If padding is invalid (wrong key or corrupted data).
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    aes_key = base64.b64decode(aes_key_b64)

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # ── Validated PKCS7 unpadding ──────────────────────────
    pad_len = padded[-1]

    # pad_len must be between 1 and 16
    if pad_len < 1 or pad_len > 16:
        raise Exception("Decryption failed: invalid padding length")

    # every padding byte must equal pad_len
    if padded[-pad_len:] != bytes([pad_len] * pad_len):
        raise Exception("Decryption failed: invalid padding bytes (wrong key?)")

    return padded[:-pad_len].decode("utf-8")


# ─────────────────────────────────────────────────────────
#  HYBRID ENCRYPT  (AES message + RSA-wrapped AES key)
# ─────────────────────────────────────────────────────────

def hybrid_encrypt(plaintext: str, recipient_public_key) -> dict:
    """
    Encrypt a message using hybrid encryption:
      1. Generate random AES-256 key
      2. Encrypt message with AES-256-CBC
      3. Encrypt AES key with recipient's RSA public key

    Returns dict with: encrypted_text, iv, aes_key_enc
    """
    ciphertext_b64, iv_b64, aes_key_b64 = aes_encrypt(plaintext)
    aes_key_raw = base64.b64decode(aes_key_b64)
    aes_key_enc = rsa_encrypt(recipient_public_key, aes_key_raw)

    return {
        "encrypted_text": ciphertext_b64,
        "iv": iv_b64,
        "aes_key_enc": aes_key_enc   # RSA-encrypted AES key
    }


def hybrid_decrypt(encrypted_text: str, iv: str, aes_key_enc: str, private_key) -> str:
    """
    Decrypt a hybrid-encrypted message.
      1. Decrypt AES key using RSA private key
      2. Decrypt message using AES key

    Returns original plaintext.
    """
    aes_key_raw = rsa_decrypt(private_key, aes_key_enc)
    aes_key_b64 = base64.b64encode(aes_key_raw).decode("utf-8")
    return aes_decrypt(encrypted_text, iv, aes_key_b64)