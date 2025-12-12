from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets
# REMOVED: import base64 (Not needed anymore)

IV_size = 16

# --- Helper Functions ---

def pad_data(data: bytes) -> bytes:
    """
    Applies PKCS7 padding.
    Expects input 'data' to be BYTES.
    """
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def unpad_data(padded_data: bytes) -> bytes:
    """
    Removes PKCS7 padding.
    """
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def derive_AES256_key(hex_key: str) -> bytes:
    return bytes.fromhex(hex_key)


def split_iv_ciphertext(data_bytes: bytes):
    """
    Splits the IV and ciphertext directly from raw bytes.
    No Base64 decoding here.
    """
    iv = data_bytes[:IV_size]
    ciphertext = data_bytes[IV_size:]
    return iv, ciphertext


# --- Main Encryption/Decryption ---

def encrypt_AES256(plaintext_bytes: bytes, hex_key: str) -> bytes:
    # 1. Derive Key
    byte_key = derive_AES256_key(hex_key)

    # 2. Pad (Input must be bytes)
    padded_data = pad_data(plaintext_bytes)

    # 3. Encrypt
    iv = secrets.token_bytes(IV_size)
    cipher = Cipher(algorithms.AES(byte_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # RETURN RAW BYTES (IV + Ciphertext)
    return iv + ciphertext


def decrypt_AES256(ciphertext_bytes: bytes, hex_key: str, mode="CBC") -> bytes:
    byte_key = derive_AES256_key(hex_key)

    if mode == "CBC":
        padded_plaintext = decrypt_AES256_CBC(ciphertext_bytes, byte_key)
    else:
        raise ValueError("Unsupported mode. Use 'CBC'.")

    try:
        # Return UNPADDED BYTES directly
        return unpad_data(padded_plaintext)
    except ValueError:
        # Raise error so the receiver can catch it (don't return a string!)
        raise ValueError("Decryption Error: Invalid Padding")


def decrypt_AES256_CBC(ciphertext_bytes: bytes, byte_key: bytes) -> bytes:
    # Split raw bytes directly
    iv, ciphertext = split_iv_ciphertext(ciphertext_bytes)

    cipher = Cipher(algorithms.AES(byte_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data