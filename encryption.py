"""
Symmetric encryption helpers (AES-256 via Fernet).
"""

from cryptography.fernet import Fernet


def generate_key() -> bytes:
    """Generate a Fernet-compatible symmetric key."""
    return Fernet.generate_key()


def encrypt_message(plaintext: str, key: bytes) -> bytes:
    """Encrypt plaintext and return token bytes."""
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)
    return Fernet(key).encrypt(plaintext.encode("utf-8"))


def decrypt_message(ciphertext: bytes, key: bytes) -> str:
    """Decrypt token bytes and return plaintext."""
    return Fernet(key).decrypt(ciphertext).decode("utf-8")
