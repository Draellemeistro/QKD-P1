import pytest
from unittest.mock import MagicMock, patch, call
import requests
from src.app.sender import ensure_valid_key, fetch_key_blocking, run_file_transfer


# ... (Keep the existing fixtures and first 3 tests: test_fetch_key..., test_ensure_valid...) ...
# START COPYING FROM HERE to overwrite the end of the file

@pytest.fixture
def mock_key_response():
    return {
        "index": 10,
        "hexKey": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "blockId": "block_123"
    }


@pytest.fixture
def mock_transport():
    with patch("src.app.sender.TcpTransport") as mock:
        instance = mock.return_value
        instance.connect.return_value = True
        yield instance


# (Include the other tests: test_fetch_key_blocking_retries_on_503, test_ensure_valid_key_over_soft_limit_success, test_ensure_valid_key_hard_limit_kms_down here if not already present)
# ...

@patch("src.app.sender.hash_file")
@patch("src.app.sender.encryption.encrypt_AES256")
@patch("src.app.sender.split_file_into_chunks")
@patch("src.app.sender.new_key")
@patch("src.app.sender.resolve_host")
@patch("src.app.sender.TcpTransport")
def test_run_file_transfer_flow(
        mock_transport_cls, mock_resolve, mock_new_key,
        mock_split, mock_encrypt, mock_hash, mock_key_response
):
    # 1. Setup Mocks
    mock_transport = mock_transport_cls.return_value
    mock_transport.connect.return_value = True

    mock_resolve.return_value = ("1.2.3.4", 9999, "B")
    mock_new_key.return_value = mock_key_response

    # Simulate 2 chunks
    mock_split.return_value = [
        {"id": 0, "data": b"chunk1", "size": 6},
        {"id": 1, "data": b"chunk2", "size": 6}
    ]

    mock_encrypt.return_value = b"encrypted_bytes"
    mock_hash.return_value = "dummy_sha256"

    # FIX: Return a valid ACK string that matches your protocol format (Key:Value|...)
    mock_transport.receive_packet.return_value = b'type:ACK|status:OK|message:Done\n'

    # 2. Run
    run_file_transfer("B", "1.2.3.4", 9999, "dummy_path.txt")

    # 3. Assertions
    mock_transport.connect.assert_called_with("1.2.3.4", 9999)
    assert mock_transport.send_reliable.call_count == 3

    # FIX: Use assert_any_call because encrypt is called multiple times
    mock_encrypt.assert_any_call(b"chunk1", mock_key_response["hexKey"])
    mock_encrypt.assert_any_call(b"chunk2", mock_key_response["hexKey"])