from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets  # For secure random number generation
import base64

IV_size = 16  # IV needs to match AES block size in bytes


# Helper functions
def pad_data(data):
    """
    Applies PKCS7 padding to the data to ensure it is a multiple of the block size (128 bits).
    Handles string-to-bytes conversion automatically.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    # AES always works on 128-bit blocks
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def unpad_data(padded_data):
    """
    Removes PKCS7 padding to retrieve the original data.
    """
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def derive_AES256_key(hex_key):
    # Requires key of length 32 bytes
    key_bytes = bytes.fromhex(hex_key)
    return key_bytes


def split_iv_ciphertext(b64_ciphertext):
    encrypted_data_bytes = base64.b64decode(b64_ciphertext)
    #Use IV size instead of key size
    iv = encrypted_data_bytes[:IV_size]  # Extract the IV from the beginning
    ciphertext = encrypted_data_bytes[IV_size:]  # The rest is the ciphertext
    return iv, ciphertext



#Encryption/Decryption functions
def encrypt_AES256(plaintext, hex_key, mode="CBC"):
    byte_key = derive_AES256_key(hex_key)
    #add padding
    padded_data = pad_data(plaintext)

    if mode == "CBC":
        return encrypt_AES256_CBC(padded_data, byte_key)
    elif mode == "ECB":
        return encrypt_AES256_ECB(padded_data, byte_key)
    else:
        raise ValueError("Unsupported mode. Use 'CBC' or 'ECB'.")


def decrypt_AES256(b64_ciphertext, hex_key, mode="CBC"):
    byte_key = derive_AES256_key(hex_key)

    # 1. Decrypt to get PADDED bytes
    if mode == "CBC":
        padded_plaintext = decrypt_AES256_CBC(b64_ciphertext, byte_key)
    elif mode == "ECB":
        padded_plaintext = decrypt_AES256_ECB(b64_ciphertext, byte_key)
    else:
        raise ValueError("Unsupported mode. Use 'CBC' or 'ECB'.")

    # 2. Unpad centrally
    try:
        plaintext_bytes = unpad_data(padded_plaintext)
        # 3. Decode to string
        return plaintext_bytes.decode("utf-8")
    except ValueError:
        return "[Decryption Error: Invalid Padding]"

def encrypt_AES256_CBC(plaintext, byte_key):
    iv = secrets.token_bytes(IV_size)  # Generate a secure random IV
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
    return decrypted_data


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

    return decrypted_data
