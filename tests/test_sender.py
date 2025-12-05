import pytest
from unittest.mock import MagicMock, patch
from src.app.sender import (
    should_rotate_key,
    create_packet,
    run_file_transfer
)


# --- 1. Pure Logic Tests (No Mocks) ---


def test_should_rotate_key_logic():
    # Case 1: First run (no key) -> Should rotate
    assert should_rotate_key(None, bytes_used=0, rotation_limit=1000) is True

    # Case 2: Under limit -> Should NOT rotate
    current_key = {"blockId": "1", "index": 1}
    assert should_rotate_key(current_key, bytes_used=500, rotation_limit=1000) is False

    # Case 3: At/Over limit -> Should rotate
    assert should_rotate_key(current_key, bytes_used=1000, rotation_limit=1000) is True


# --- 2. Data Structure Test (High Value) ---
# This ensures the Receiver gets the exact JSON format it expects.
# We mock encryption because we trust the AES library, we just want to check the packaging.

@patch("src.app.sender.encryption.encrypt_AES256")
def test_create_packet_structure(mock_encrypt):
    # Setup
    mock_encrypt.return_value = "encrypted_base64_string"
    chunk_id = 42
    data_bytes = b"secret data"
    # Key data as returned by your KMS API
    key_data = {"blockId": "blk_123", "index": 5, "hexKey": "deadbeef"}

    # Action
    packet = create_packet(chunk_id, data_bytes, key_data)

    # Assertions - Verify the CONTRACT with the receiver
    assert packet["chunk_id"] == 42
    assert packet["key_block_id"] == "blk_123"
    assert packet["key_index"] == 5
    assert packet["data"] == "encrypted_base64_string"
    assert packet["is_last"] is False


# --- 3. Integration Flow ---
# Mock Network, FileSystem, KMS API.
# The internal logic (encryption, packet creation, json dumping) runs for real.

@patch("src.app.sender.split_file_into_chunks")  # Mock Disk IO
@patch("src.app.sender.Transport")  # Mock Network IO
@patch("src.app.sender.get_encryption_key")  # Mock API IO
def test_run_file_transfer_integration(mock_get_key, mock_transport_cls, mock_split):
    # --- Setup Mocks ---

    # 1. Simulate the Network
    mock_transport_instance = MagicMock()
    mock_transport_instance.connect.return_value = True
    mock_transport_cls.return_value = mock_transport_instance

    # 2. Simulate the File System (Yield 2 chunks)
    mock_split.return_value = [
        {"id": 0, "data": b"chunk1", "size": 512},
        {"id": 1, "data": b"chunk2", "size": 512}
    ]

    # 3. Simulate KMS API (Return a usable key)
    # We provide a real-looking key so the real create_packet code doesn't crash
    mock_get_key.return_value = {
        "blockId": "b1",
        "index": 100,
        "hexKey": "00" * 32  # valid hex string for AES
    }

    # --- Run Code ---
    run_file_transfer("A", "localhost", 1234, "dummy.txt")

    # --- Verify Interactions ---

    # 1. Verify Connection
    mock_transport_instance.connect.assert_called_once()

    # 2. Verify Key Fetching
    # Since total size (1024) is small, we expect 1 key fetch (the initial one)
    mock_get_key.assert_called_with("A")

    # 3. Verify Data Transmission
    # We check the actual bytes sent to 'send_reliable'
    # This verifies: create_packet -> json.dumps -> transport.send_reliable
    assert mock_transport_instance.send_reliable.call_count == 3  # 2 chunks + 1 termination

    # Inspect the first packet sent
    args, _ = mock_transport_instance.send_reliable.call_args_list[0]
    sent_bytes = args[0]

    # Verify the JSON structure was actually serialized
    assert b'"chunk_id": 0' in sent_bytes
    assert b'"key_block_id": "b1"' in sent_bytes

    # Inspect the termination packet (last call)
    args, _ = mock_transport_instance.send_reliable.call_args_list[-1]
    assert b'"is_last": true' in args[0]