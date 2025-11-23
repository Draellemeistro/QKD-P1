import pytest
from unittest.mock import patch, MagicMock
from dotenv import load_dotenv
import os

load_dotenv()

# Access variables
kms_ip_env_var = os.getenv("KMS_URL")

if kms_ip_env_var:
    kms_server_ip = kms_ip_env_var
else:
    print("KMS_URL not found in environment variables.")
    kms_server_ip = "http://localhost:8095"  # Default value if not set


def test_kms_api():
    test_get_key()
    test_new_key()


@pytest.fixture
def get_key_response():
    return {"index": 42, "hexKey": "deadbeefcafebabe", "blockId": "1234"}


def new_key_response():
    return {"index": 1, "hexKey": "abcdef1234567890", "blockId": "5678"}


def api_response_pattern():
    return {"index": int, "hexKey": str, "blockId": str}


@patch("src.app.kms_api.requests.post")
def test_get_key(mock_post, get_key_response):
    from src.app.kms_api import get_key

    receiver = "B"
    block_id = "1234"
    index = 42
    url_path = kms_server_ip + "/api/getkey"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = get_key_response
    mock_post.return_value = mock_response

    result = get_key(receiver, block_id, index)

    assert result == get_key_response
    mock_post.assert_called_once_with(
        url_path,
        params={"siteid": receiver, "blockid": block_id, "index": index},
    )


@patch("src.app.kms_api.requests.post")
def test_new_key(mock_post, new_key_response):
    from src.app.kms_api import new_key

    sender = "A"
    url_path = kms_server_ip + "/api/newkey"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = new_key_response
    mock_post.return_value = mock_response

    result = new_key(sender)

    assert result == new_key_response
    mock_post.assert_called_once_with(url_path, data={"siteid": sender})


def test_refresh_key_block():
    from src.app.crypto.keylogic import refresh_key_block

    assert refresh_key_block(0, 100) is True
    assert refresh_key_block(100, 100) is True
    assert refresh_key_block(150, 100) is False
    assert refresh_key_block(200, 100) is True


def test_refresh_key():
    from src.app.crypto.keylogic import refresh_key

    assert refresh_key(0, 1024) is True
    assert refresh_key(1024, 1024) is True
    assert refresh_key(512, 1024) is False


def test_encrypt_chunk():
    from src.app.crypto.keylogic import encrypt_chunk
    import src.app.crypto.encryption_module as encryption_module

    chunk = {"id": 1, "data": b"testdata", "size": 512}
    key = b"testkey"

    with patch.object(
        encryption_module, "encrypt_AES256", return_value=b"encrypteddata"
    ) as mock_encrypt:
        encrypted_data = encrypt_chunk(chunk, key)
        mock_encrypt.assert_called_once_with(chunk["data"], key)
        assert encrypted_data == b"encrypteddata"


def test_encrypt_all_chunks():
    from src.app.crypto.keylogic import encrypt_all_chunks
    import src.app.crypto.encryption_module as encryption_module

    chunks = [
        {"id": 1, "data": b"data1", "size": 1024 * 1024},
        {"id": 2, "data": b"data2", "size": 600000},
        {"id": 3, "data": b"data3", "size": 700000},
    ]
    keys = [b"key1", b"key2"]

    with patch.object(
        encryption_module, "encrypt_AES256", side_effect=[b"enc1", b"enc2", b"enc3"]
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
    from src.app.crypto.encryption_module import derive_AES256_key

    hex_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    expected_bytes = bytes.fromhex(hex_key)
    hex_from_bytes = bytes.hex(expected_bytes)
    if hex_key != hex_from_bytes:
        raise ValueError("Hex key conversion mismatch")

    derived_key = derive_AES256_key(hex_key)
    assert derived_key == expected_bytes


def test_AES256_encryption_decryption():
    test_AES256_CBC()
    test_AES256_ECB()


def test_AES256_CBC(plaintext="This is a test message."):
    from src.app.crypto.encryption_module import (
        encrypt_AES256_CBC,
        decrypt_AES256_CBC,
        derive_AES256_key,
    )

    hex_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    byte_key = derive_AES256_key(hex_key)

    ciphertext = encrypt_AES256_CBC(plaintext.encode("utf-8"), byte_key)
    decrypted_text = decrypt_AES256_CBC(ciphertext, byte_key)

    assert decrypted_text == plaintext


def test_AES256_ECB(plaintext="This is a test message."):
    from src.app.crypto.encryption_module import (
        encrypt_AES256_ECB,
        decrypt_AES256_ECB,
        derive_AES256_key,
    )

    hex_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    byte_key = derive_AES256_key(hex_key)

    ciphertext = encrypt_AES256_ECB(plaintext.encode("utf-8"), byte_key)
    decrypted_text = decrypt_AES256_ECB(ciphertext, byte_key)

    assert decrypted_text == plaintext


def test_encryption_module():
    test_derive_AES256_key()
    test_AES256_encryption_decryption()
