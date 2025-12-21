import pytest
from unittest.mock import MagicMock, patch
from src.app.receiver import process_single_packet, run_reception_loop


# --- Unit Tests ---

@patch("src.app.receiver.encryption.decrypt_AES256")
@patch("src.app.receiver.get_decryption_key")
def test_process_single_packet_data(mock_get_key, mock_decrypt):
    """Verifies data packet processing with key caching."""
    mock_writer = MagicMock()
    # Mock returning a key
    mock_get_key.return_value = {"hexKey": "dummy_hex", "blockId": "b1", "index": 0}
    mock_decrypt.return_value = b"decrypted_content"

    packet = {
        "chunk_id": 1,
        "key_block_id": "b1",
        "key_index": 0,
        "data": b"encrypted_blob",
        "is_last": False
    }

    # Cache is required by the implementation
    dummy_cache = {"id": None, "data": None}

    # Run
    process_single_packet(packet, mock_writer, "B", dummy_cache)

    # Verify
    mock_get_key.assert_called_with("B", "b1", 0)
    mock_writer.append.assert_called_once_with(b"decrypted_content")


# --- Integration Test ---

@patch("src.app.receiver.validate_file_hash")
@patch("src.app.receiver.create_ack_packet")
@patch("src.app.receiver.FileStreamWriter")
@patch("src.app.receiver.process_single_packet")
def test_reception_loop_flow(mock_process, mock_writer_cls, mock_create_ack, mock_validate):
    """
    Tests that the loop correctly handles data packets and then exits on termination.
    """
    mock_transport = MagicMock()
    mock_validate.return_value = True

    # Standard Data Packet Header (type:chunk_id|...)
    event1 = b'chunk_id:1|key_block_id:A|key_index:1\n' + b'data'
    # Termination Packet Header (must have is_last:true)
    event2 = b'chunk_id:-1|is_last:true|file_hash:abc\n'

    # Simulate the socket receiving these two packets
    mock_transport.receive_packet.side_effect = [event1, event2]
    mock_process.return_value = False

    # Run loop
    run_reception_loop(mock_transport, "out.txt", "B")

    # Assertions
    assert mock_transport.receive_packet.call_count == 2
    mock_transport.send_reliable.assert_called()