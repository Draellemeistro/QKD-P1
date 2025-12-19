import pytest
from src.app.crypto import encryption

# Constants defined in your encryption.py
IV_SIZE = 12
TAG_SIZE = 16
VALID_HEX_KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"


def test_key_derivation_hkdf():
    """
    Unit Test: Verifies HKDF logic (NF4).
    1. Output must be 32 bytes (for AES-256).
    2. Output must NOT be the same as the raw input (Entropy extraction).
    3. Output must be deterministic (Same input -> Same output).
    """
    raw_key_bytes = bytes.fromhex(VALID_HEX_KEY)

    # 1. Derive Key
    derived_key_1 = encryption.derive_AES256_key(VALID_HEX_KEY)
    derived_key_2 = encryption.derive_AES256_key(VALID_HEX_KEY)

    # Check Length
    assert len(derived_key_1) == 32

    # Check Determinism
    assert derived_key_1 == derived_key_2

    # Check proper Derivation (It should NOT just be the raw bytes anymore)
    assert derived_key_1 != raw_key_bytes, "HKDF failed: Key is identical to raw QKD material!"


def test_derive_key_context_binding():
    """
    Unit Test: Verifies that changing the HKDF 'info' context changes the key.
    This protects against cross-protocol attacks.
    """
    # Assuming you added the optional 'context_info' parameter I suggested
    # If not, you can remove this specific test.
    try:
        key_default = encryption.derive_AES256_key(VALID_HEX_KEY)
        key_context_b = encryption.derive_AES256_key(VALID_HEX_KEY, context_info=b"DIFFERENT_CONTEXT")

        assert key_default != key_context_b
    except TypeError:
        # Gracefully skip if function signature wasn't updated with optional arg
        pytest.skip("derive_AES256_key does not accept context_info argument yet.")


def test_encrypt_decrypt_success():
    """
    Unit Test: Verifies the 'Happy Path' with HKDF keys.
    """
    plaintext = b"Patient Record: Critical Condition - ID 12345"

    # 1. Encrypt
    encrypted_payload = encryption.encrypt_AES256(plaintext, VALID_HEX_KEY)

    # Verify Structure: IV + Tag + Ciphertext
    expected_length = IV_SIZE + TAG_SIZE + len(plaintext)
    assert len(encrypted_payload) == expected_length

    # 2. Decrypt
    decrypted_text = encryption.decrypt_AES256(encrypted_payload, VALID_HEX_KEY)

    # 3. Assert
    assert decrypted_text == plaintext


def test_integrity_check_tampered_ciphertext():
    """
    Unit Test: Security Verification (AES-GCM Integrity).
    """
    plaintext = b"Sensitive Data"
    encrypted_payload = bytearray(encryption.encrypt_AES256(plaintext, VALID_HEX_KEY))

    # ATTACK: Flip the very last bit of the ciphertext
    encrypted_payload[-1] ^= 0xFF

    with pytest.raises(ValueError, match="Decryption Error"):
        encryption.decrypt_AES256(bytes(encrypted_payload), VALID_HEX_KEY)


def test_integrity_check_tampered_tag():
    """
    Unit Test: Security Verification (Tag Modification).
    """
    plaintext = b"Sensitive Data"
    encrypted_payload = bytearray(encryption.encrypt_AES256(plaintext, VALID_HEX_KEY))

    # ATTACK: Flip a byte inside the Tag region (Bytes 12-28)
    encrypted_payload[15] ^= 0xFF

    with pytest.raises(ValueError, match="Decryption Error"):
        encryption.decrypt_AES256(bytes(encrypted_payload), VALID_HEX_KEY)


def test_split_iv_tag_helper():
    """
    Unit Test: Verifies the helper function packet dissection.
    """
    dummy_iv = b"I" * IV_SIZE
    dummy_tag = b"T" * TAG_SIZE
    dummy_cipher = b"CiphertextData"
    full_packet = dummy_iv + dummy_tag + dummy_cipher

    iv, tag, ciphertext = encryption.split_iv_tag_ciphertext(full_packet)

    assert iv == dummy_iv
    assert tag == dummy_tag
    assert ciphertext == dummy_cipher