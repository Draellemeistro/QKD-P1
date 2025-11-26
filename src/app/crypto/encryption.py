from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets  # For secure random number generation
import base64

token_size = 32  # Size of the AES-256 key in bytes


def encrypt_AES256(plaintext, hex_key, mode="CBC"):
    byte_key = derive_AES256_key(hex_key)
    if mode == "CBC":
        return encrypt_AES256_CBC(plaintext, byte_key)
    elif mode == "ECB":
        return encrypt_AES256_ECB(plaintext, byte_key)
    else:
        raise ValueError("Unsupported mode. Use 'CBC' or 'ECB'.")


def derive_AES256_key(hex_key):
    # Requires key of length 32 bytes
    key_bytes = bytes.fromhex(hex_key)
    return key_bytes


def split_iv_ciphertext(b64_ciphertext):
    encrypted_data_bytes = base64.b64decode(b64_ciphertext)
    iv = encrypted_data_bytes[:token_size]  # Extract the IV from the beginning
    ciphertext = encrypted_data_bytes[token_size:]  # The rest is the ciphertext
    return iv, ciphertext


def encrypt_AES256_CBC(plaintext, byte_key):
    iv = secrets.token_bytes(token_size)  # Generate a secure random IV
    cipher = Cipher(algorithms.AES(byte_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode(
        "utf-8"
    )  # Prepend IV to ciphertext for later use


def decrypt_AES256_CBC(b64_ciphertext, byte_key):
    iv, ciphertext = split_iv_ciphertext(b64_ciphertext)

    cipher = Cipher(algorithms.AES(byte_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data.decode("utf-8")


def encrypt_AES256_ECB(plaintext, byte_key):
    cipher = Cipher(algorithms.AES(byte_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt_AES256_ECB(b64_ciphertext, byte_key):
    encrypted_data_bytes = base64.b64decode(b64_ciphertext)

    cipher = Cipher(algorithms.AES(byte_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data_bytes) + decryptor.finalize()

    return decrypted_data.decode("utf-8")
