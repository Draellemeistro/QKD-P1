from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets
import math
from quantcrypt.cipher import Krypton
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


def bytes_to_hex(key_bytes: bytes) -> str:
    return key_bytes.hex()


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


def decrypt_AES256_CBC(
    ciphertext_bytes: bytes, byte_key: bytes
) -> bytes:  # NOTE: Delete?
    # Split raw bytes directly
    iv, ciphertext = split_iv_ciphertext(ciphertext_bytes)

    cipher = Cipher(algorithms.AES(byte_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data


# -------------------
# --- Krypton PQC ---
# -------------------
# Based on AES256, but with additional step of obfuscating the plaintext by XOR-ing it with the output of a keyed hash function.
def create_Krypton_master_key(hex_key_1: str, hex_key_2) -> bytes:
    if hex_key_2 and isinstance(hex_key_2, str):
        master_key = derive_AES256_key(hex_key_1) + derive_AES256_key(hex_key_2)
    else:
        master_key = derive_AES256_key(hex_key_1)
    if len(master_key) != 64:
        raise ValueError("Krypton requires a key length of 64 bytes (512 bits).")
    return master_key


def basic_Krypton_encrypt(
    plaintext: str, hex_key_1: str, hex_key_2
) -> tuple[bytes, bytes]:
    master_key = create_Krypton_master_key(hex_key_1, hex_key_2)
    plaintext_bytes = bytes(plaintext, "utf-8")
    krypton = Krypton(master_key)
    krypton.begin_encryption()
    ciphertext = krypton.encrypt(plaintext_bytes)
    verif_dp = krypton.finish_encryption()
    return ciphertext, verif_dp


def basic_Krypton_decrypt(ciphertect, verif_dp, hex_key_1, hex_key_2) -> bytes:
    master_key = create_Krypton_master_key(hex_key_1, hex_key_2)
    krypton = Krypton(master_key)
    krypton.begin_decryption(verif_dp)
    plaintext_copy = krypton.decrypt(ciphertect)
    krypton.finish_decryption()
    if isinstance(plaintext_copy, bytes):
        return plaintext_copy
    else:
        return bytes(plaintext_copy, "utf-8")


# ------------------------------------------------
# --- One-Time Pad (OTP) Encryption/Decryption ---
# ------------------------------------------------
def otp_encrypt(plaintext: bytes, key_material: bytes) -> bytes:
    return bytes([p ^ k for p, k in zip(plaintext, key_material)])


def otp_how_many_keys(message: bytes) -> int:
    num_blocks = math.ceil(len(message) / 32)
    # key_length = num_blocks * 32
    return num_blocks


def derive_key() -> bytes:
    # NOTE: PLACEHOLDER - In real implementation, fetch from KMS
    return secrets.token_bytes(32)


def otp_encrypt_message(message: bytes):
    keys = [derive_key() for _ in range(otp_how_many_keys(message))]
    master_key = b"".join(keys)
    ciphertext = otp_encrypt(message, master_key)
    return ciphertext, master_key


def otp_decrypt_message(ciphertext: bytes, key: bytes):
    return otp_encrypt(ciphertext, key)
