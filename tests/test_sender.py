import pytest
from unittest.mock import MagicMock, patch, call
import requests
from src.app.sender import ensure_valid_key, fetch_key_blocking, run_file_transfer


# --- FIXTURES ---

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
        # Setup connect to always succeed
        instance.connect.return_value = True
        yield instance


# --- 1. RETRY LOGIC TESTS ---

@patch("src.app.sender.time.sleep")  # Don't actually sleep in tests
@patch("src.app.sender.new_key")
def test_fetch_key_blocking_retries_on_503(mock_new_key, mock_sleep, mock_key_response):
    """
    Verifies that the sender retries if the KMS returns a 503 (Busy) error,
    and eventually succeeds when the KMS recovers.
    """
    # Create a 503 error exception
    error_503 = requests.exceptions.HTTPError("Service Unavailable")
    error_503.response = MagicMock()
    error_503.response.status_code = 503

    # Scenario: Fail twice with 503, then succeed
    mock_new_key.side_effect = [error_503, error_503, mock_key_response]

    result = fetch_key_blocking("receiver_B")

    assert result == mock_key_response
    assert mock_new_key.call_count == 3
    # Verify we waited between retries
    assert mock_sleep.call_count == 2


@patch("src.app.sender.new_key")
def test_fetch_key_blocking_raises_on_other_errors(mock_new_key):
    """
    Verifies that non-503 errors (like 404 or 500) crash the sender immediately
    instead of entering an infinite retry loop.
    """
    error_404 = requests.exceptions.HTTPError("Not Found")
    error_404.response = MagicMock()
    error_404.response.status_code = 404

    mock_new_key.side_effect = error_404

    with pytest.raises(requests.exceptions.HTTPError):
        fetch_key_blocking("receiver_B")


# --- 2. KEY ROTATION LOGIC TESTS ---

@patch("src.app.sender.new_key")
def test_ensure_valid_key_initial_fetch(mock_new_key, mock_key_response):
    """Test Case: First run (no key) -> Must fetch immediately."""
    mock_new_key.return_value = mock_key_response

    current_key = None
    bytes_used = 0

    result = ensure_valid_key(current_key, bytes_used, 1000, 2000, "B")

    assert result == mock_key_response
    mock_new_key.assert_called_once()


@patch("src.app.sender.new_key")
def test_ensure_valid_key_under_limit(mock_new_key, mock_key_response):
    """Test Case: Usage is low -> Reuse existing key (No KMS call)."""
    current_key = mock_key_response
    bytes_used = 500
    soft_limit = 1000

    result = ensure_valid_key(current_key, bytes_used, soft_limit, 2000, "B")

    assert result == current_key
    mock_new_key.assert_not_called()


@patch("src.app.sender.new_key")
def test_ensure_valid_key_over_soft_limit_success(mock_new_key, mock_key_response):
    """Test Case: Usage > Soft Limit, KMS Available -> Rotate Key."""
    mock_new_key.return_value = {"index": 11, "hexKey": "new_key", "blockId": "new_block"}

    current_key = mock_key_response
    bytes_used = 1500
    soft_limit = 1000

    result = ensure_valid_key(current_key, bytes_used, soft_limit, 2000, "B")

    assert result["index"] == 11
    mock_new_key.assert_called_once()


@patch("src.app.sender.fetch_key_blocking")
@patch("src.app.sender.new_key")
def test_ensure_valid_key_soft_limit_kms_down(mock_new_key, mock_blocking, mock_key_response):
    """
    Test Case: Usage > Soft Limit, KMS Busy (503).
    Result: Should EXTEND key life (return old key) and NOT block.
    """
    error_503 = requests.exceptions.HTTPError()
    error_503.response = MagicMock()
    error_503.response.status_code = 503
    mock_new_key.side_effect = error_503

    current_key = mock_key_response
    bytes_used = 1500
    soft_limit = 1000
    hard_limit = 2000  # We are below hard limit

    result = ensure_valid_key(current_key, bytes_used, soft_limit, hard_limit, "B")

    # Critical: Should return OLD key to keep traffic flowing
    assert result == current_key
    # Should NOT have called the blocking retry function
    mock_blocking.assert_not_called()


@patch("src.app.sender.fetch_key_blocking")
@patch("src.app.sender.new_key")
def test_ensure_valid_key_hard_limit_kms_down(mock_new_key, mock_blocking, mock_key_response):
    """
    Test Case: Usage > HARD Limit, KMS Busy (503).
    Result: Must BLOCK and force a new key. Security > Availability.
    """
    error_503 = requests.exceptions.HTTPError()
    error_503.response = MagicMock()
    error_503.response.status_code = 503
    mock_new_key.side_effect = error_503

    mock_blocking.return_value = {"index": 99, "hexKey": "forced_key"}

    current_key = mock_key_response
    bytes_used = 2500  # > Hard Limit (2000)
    soft_limit = 1000
    hard_limit = 2000

    result = ensure_valid_key(current_key, bytes_used, soft_limit, hard_limit, "B")

    # Critical: Must return NEW key (from blocking fetch)
    assert result["index"] == 99
    # Must have entered blocking mode
    mock_blocking.assert_called_once()


# --- 3. INTEGRATION FLOW TEST ---

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
    """
    Verifies the full sender loop:
    Connect -> Fetch Key -> Split File -> Encrypt -> Send -> Terminate -> Wait ACK
    """
    # 1. Setup Mocks
    mock_transport = mock_transport_cls.return_value
    mock_transport.connect.return_value = True

    # Simulate resolving 'bob'
    mock_resolve.return_value = ("1.2.3.4", 9999, "B")

    # Simulate KMS returning a valid key
    mock_new_key.return_value = mock_key_response

    # Simulate File Splitting (2 chunks)
    mock_split.return_value = [
        {"id": 0, "data": b"chunk1", "size": 6},
        {"id": 1, "data": b"chunk2", "size": 6}
    ]

    # Simulate Encryption
    mock_encrypt.return_value = b"encrypted_bytes"

    # Simulate File Hash
    mock_hash.return_value = "dummy_sha256"

    # Simulate receiving an ACK at the end
    # We return a valid ACK packet structure (Type 4 = ACK)
    mock_transport.receive_packet.return_value = b'\x00\x00\x00\x04{"status":"OK"}\n'

    # 2. Run the Sender
    run_file_transfer("B", "1.2.3.4", 9999, "dummy_path.txt")

    # 3. Assertions

    # Connection established?
    mock_transport.connect.assert_called_with("1.2.3.4", 9999)

    # Key fetched?
    mock_new_key.assert_called()

    # Data sent? (2 chunks + 1 termination = 3 packets)
    assert mock_transport.send_reliable.call_count == 3

    # Correct key used for encryption?
    mock_encrypt.assert_called_with(b"chunk1", mock_key_response["hexKey"])

    # Termination packet contained hash?
    # Inspect the last call to send_reliable
    last_packet_sent = mock_transport.send_reliable.call_args_list[-1][0][0]
    # Check if hash is inside the JSON part of the packet bytes
    assert b"dummy_sha256" in last_packet_sent

    # Connection closed?
    mock_transport.close.assert_called_once()