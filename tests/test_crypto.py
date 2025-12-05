from unittest.mock import patch
from src.app.crypto.keylogic import (
    refresh_key_block,
    refresh_key,
    encrypt_chunk,
    encrypt_all_chunks,
)
import src.app.crypto.encryption as encryption


def test_refresh_key_block():
    assert refresh_key_block(0, 100) is True
    assert refresh_key_block(100, 100) is True
    assert refresh_key_block(150, 100) is False
    assert refresh_key_block(200, 100) is True


def test_refresh_key():
    assert refresh_key(0, 1024) is True
    assert refresh_key(1024, 1024) is True
    assert refresh_key(512, 1024) is False


def test_encrypt_chunk():
    chunk = {"id": 1, "data": b"testdata", "size": 512}
    key = b"testkey"

    with patch.object(
        encryption, "encrypt_AES256", return_value=b"encrypteddata"
    ) as mock_encrypt:
        encrypted_data = encrypt_chunk(chunk, key)
        mock_encrypt.assert_called_once_with(chunk["data"], key)
        assert encrypted_data == b"encrypteddata"


def test_encrypt_all_chunks():
    chunks = [
        {"id": 1, "data": b"data1", "size": 1024 * 1024},
        {"id": 2, "data": b"data2", "size": 600000},
        {"id": 3, "data": b"data3", "size": 700000},
    ]
    keys = [b"key1", b"key2"]

    with patch.object(
        encryption, "encrypt_AES256", side_effect=[b"enc1", b"enc2", b"enc3"]
    ) as mock_encrypt:
        encrypted_chunks = encrypt_all_chunks(chunks, keys)
        assert len(encrypted_chunks) == 3
        assert encrypted_chunks[0]["data"] == b"enc1"
        assert encrypted_chunks[1]["data"] == b"enc2"  # represents error
        assert encrypted_chunks[2]["data"] == b"enc3"
        assert mock_encrypt.call_count == 3


def test_key_logic():
    test_refresh_key_block()
    test_refresh_key()
    test_encrypt_chunk()
    test_encrypt_all_chunks()


def test_derive_AES256_key():
    hex_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    expected_bytes = bytes.fromhex(hex_key)
    hex_from_bytes = bytes.hex(expected_bytes)
    if hex_key != hex_from_bytes:
        raise ValueError("Hex key conversion mismatch")

    derived_key = encryption.derive_AES256_key(hex_key)
    assert derived_key == expected_bytes


def test_AES256_encryption_decryption():
    test_AES256_CBC()
    test_AES256_ECB()


def test_AES256_CBC(plaintext="This is a test message."):
    hex_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    byte_key = encryption.derive_AES256_key(hex_key)

    ciphertext = encryption.encrypt_AES256_CBC(plaintext, byte_key)
    decrypted_text = encryption.decrypt_AES256_CBC(ciphertext, byte_key)

    assert decrypted_text == plaintext


def test_AES256_ECB(plaintext="This is a test message."):
    hex_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    byte_key = encryption.derive_AES256_key(hex_key)

    ciphertext = encryption.encrypt_AES256_ECB(plaintext, byte_key)
    decrypted_text = encryption.decrypt_AES256_ECB(ciphertext, byte_key)

    assert decrypted_text == plaintext


def test_encryption_module():
    test_derive_AES256_key()
    test_AES256_encryption_decryption()
