from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
import secrets

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# AES-GCM Standard Nonce (IV) size is 12 bytes
IV_size = 12
# AES-GCM Standard Tag size is 16 bytes
TAG_SIZE = 16


# --- Helper Functions ---

def derive_AES256_key(hex_key: str, context_info: bytes = b"QKD_File_Transfer") -> bytes:
    """
    Derives a 32-byte AES key from the raw QKD hex string using HKDF.
    """
    # 1. Convert hex to raw bytes (Input Key Material)
    raw_key_material = bytes.fromhex(hex_key)

    # 2. Setup HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=32,                  # AES-256 requires 32 bytes
        salt=None,
        info=context_info,          
        backend=default_backend()
    )

    # 3. Derive the specific session key
    return hkdf.derive(raw_key_material)


def split_iv_tag_ciphertext(data_bytes: bytes):
    """
    Splits the IV, Tag, and ciphertext directly from raw bytes.
    Structure: IV (12 bytes) | Tag (16 bytes) | Ciphertext (...)
    """
    if len(data_bytes) < IV_size + TAG_SIZE:
        raise ValueError("Data too short to contain IV and Tag")

    iv = data_bytes[:IV_size]
    tag = data_bytes[IV_size: IV_size + TAG_SIZE]
    ciphertext = data_bytes[IV_size + TAG_SIZE:]
    return iv, tag, ciphertext


# --- Main Encryption/Decryption ---

def encrypt_AES256(plaintext_bytes: bytes, hex_key: str) -> bytes:
    # 1. Derive Key
    byte_key = derive_AES256_key(hex_key)

    # 2. No Padding needed for GCM (it acts as a stream cipher)

    # 3. Encrypt
    iv = secrets.token_bytes(IV_size)

    # Initialize GCM Cipher
    cipher = Cipher(algorithms.AES(byte_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the payload
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()

    # Retrieve the Authentication Tag
    tag = encryptor.tag

    # RETURN RAW BYTES (IV + Tag + Ciphertext)
    return iv + tag + ciphertext


def decrypt_AES256(encrypted_bytes: bytes, hex_key: str, mode="GCM") -> bytes:
    byte_key = derive_AES256_key(hex_key)

    try:
        # 1. Split raw bytes into components
        iv, tag, ciphertext = split_iv_tag_ciphertext(encrypted_bytes)

        # 2. Initialize GCM Cipher for Decryption
        # We must pass the Tag here for verification
        cipher = Cipher(algorithms.AES(byte_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # 3. Decrypt and Verify
        # finalize() will raise InvalidTag if the tag does not match
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        return decrypted_data

    except InvalidTag:
        # Raise ValueError to maintain compatibility with receiver.py's error handling
        raise ValueError("Decryption Error: Invalid Tag (Authentication Failed)")