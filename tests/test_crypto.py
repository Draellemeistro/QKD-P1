import pytest
from src.app.crypto import encryption

# Constants defined in your encryption.py
IV_SIZE = 12
TAG_SIZE = 16
VALID_HEX_KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"


def test_derive_AES256_key():
    """
    Unit Test: Verifies that the helper function correctly converts
    a hex string into the 32 bytes required for AES-256.
    """
    expected_bytes = bytes.fromhex(VALID_HEX_KEY)
    derived_key = encryption.derive_AES256_key(VALID_HEX_KEY)

    assert derived_key == expected_bytes
    assert len(derived_key) == 32


def test_encrypt_decrypt_success():
    """
    Unit Test: Verifies the 'Happy Path'.
    Data encrypted with a key must be decryptable by the same key.
    """
    plaintext = b"Patient Record: Critical Condition - ID 12345"

    # 1. Encrypt
    encrypted_payload = encryption.encrypt_AES256(plaintext, VALID_HEX_KEY)

    # Verify Structure: IV + Tag + Ciphertext
    # AES-GCM does not pad, so ciphertext length = plaintext length
    expected_length = IV_SIZE + TAG_SIZE + len(plaintext)
    assert len(encrypted_payload) == expected_length

    # 2. Decrypt
    decrypted_text = encryption.decrypt_AES256(encrypted_payload, VALID_HEX_KEY)

    # 3. Assert
    assert decrypted_text == plaintext


def test_integrity_check_tampered_ciphertext():
    """
    Unit Test: Security Verification.
    Verifies that if a payload is modified (tampered) after encryption,
    decryption fails. This proves AES-GCM integrity is working.
    """
    plaintext = b"Sensitive Data"
    # Encrypt and convert to mutable bytearray
    encrypted_payload = bytearray(encryption.encrypt_AES256(plaintext, VALID_HEX_KEY))

    # ATTACK: Flip the very last bit of the ciphertext
    encrypted_payload[-1] ^= 0xFF

    # Expect failure (your code raises ValueError on InvalidTag)
    with pytest.raises(ValueError, match="Decryption Error"):
        encryption.decrypt_AES256(bytes(encrypted_payload), VALID_HEX_KEY)


def test_integrity_check_tampered_tag():
    """
    Unit Test: Security Verification.
    Verifies that if the Authentication Tag is modified, decryption fails.
    The Tag is located between bytes [12] and [28] (IV=12, Tag=16).
    """
    plaintext = b"Sensitive Data"
    encrypted_payload = bytearray(encryption.encrypt_AES256(plaintext, VALID_HEX_KEY))

    # ATTACK: Flip a byte inside the Tag region
    encrypted_payload[15] ^= 0xFF

    with pytest.raises(ValueError, match="Decryption Error"):
        encryption.decrypt_AES256(bytes(encrypted_payload), VALID_HEX_KEY)


def test_split_iv_tag_helper():
    """
    Unit Test: Verifies the helper function that dissects the packet.
    """
    # Create dummy components
    dummy_iv = b"I" * IV_SIZE
    dummy_tag = b"T" * TAG_SIZE
    dummy_cipher = b"CiphertextData"

    full_packet = dummy_iv + dummy_tag + dummy_cipher

    # Call the internal helper
    iv, tag, ciphertext = encryption.split_iv_tag_ciphertext(full_packet)

    assert iv == dummy_iv
    assert tag == dummy_tag
    assert ciphertext == dummy_cipher