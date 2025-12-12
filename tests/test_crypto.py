from src.app.crypto.encryption import (
    pad_data,
    unpad_data,
    derive_AES256_key,
    split_iv_ciphertext,
    encrypt_AES256,
    decrypt_AES256,
    encrypt_AES256_CBC,
    decrypt_AES256_CBC,
)


class TestAESCrypto:
    def test_derive_AES256_key_basic(self):
        hex_key = "a" * 64
        key = derive_AES256_key(hex_key)
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_derive_AES256_key(self):
        hex_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        expected_bytes = bytes.fromhex(hex_key)
        hex_from_bytes = bytes.hex(expected_bytes)
        if hex_key != hex_from_bytes:
            raise ValueError("Hex key conversion mismatch")
        key = derive_AES256_key(hex_key)
        assert isinstance(key, bytes)
        assert len(key) == 32
        assert key == expected_bytes

    def test_split_iv_ciphertext(self):
        # Prepare a valid b64 string with IV + ciphertext
        pass

    def test_encrypt_decrypt_AES256(self):
        plaintext = b"secret"
        hex_key = "a" * 64
        ct = encrypt_AES256(plaintext, hex_key)
        pt = decrypt_AES256(ct, hex_key)
        assert pt == plaintext

    def test_encrypt_decrypt_AES256_CBC(self):
        plaintext = b"secret"
        key = b"a" * 32
        ct = encrypt_AES256_CBC(plaintext, key)
        pt = decrypt_AES256_CBC(ct, key)
        assert pt == plaintext


class TestCryptoUtils:
    def test_pad_unpad(self):
        data = b"test"
        padded = pad_data(data)
        assert padded != data
        assert unpad_data(padded) == data
