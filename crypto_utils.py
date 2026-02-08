"""
Symmetric encryption utilities for the steganography application.
Uses AES-256 via Fernet (cryptography library).
Key is generated and managed by the system.
"""

from cryptography.fernet import Fernet


def generate_key() -> bytes:
    """Generate a new 256-bit symmetric key (Fernet-compatible)."""
    return Fernet.generate_key()


def encrypt_message(plaintext: str, key: bytes) -> bytes:
    """
    Encrypt a string message using the symmetric key.
    Returns raw bytes (not base64) for embedding in images.
    """
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)
    f = Fernet(key)
    token = f.encrypt(plaintext.encode("utf-8"))
    return token


def decrypt_message(ciphertext: bytes, key: bytes) -> str:
    """
    Decrypt ciphertext (raw Fernet token bytes) using the symmetric key.
    Returns the original plaintext string.
    """
    f = Fernet(key)
    return f.decrypt(ciphertext).decode("utf-8")


def key_to_file(path: str, key: bytes) -> None:
    """Save key bytes to a file (e.g. .key file)."""
    with open(path, "wb") as f:
        f.write(key)


def key_from_file(path: str) -> bytes:
    """Load key bytes from a file."""
    with open(path, "rb") as f:
        return f.read()
