import pytest
import json
from unittest.mock import MagicMock, patch
from src.app.receiver import process_single_packet, run_reception_loop, start_server


# --- 1. Pure Logic Tests (No Network Needed) ---

@patch("src.app.receiver.encryption.decrypt_AES256")
@patch("src.app.receiver.get_decryption_key")
def test_process_single_packet_data(mock_get_key, mock_decrypt):
    """
    Verifies that a normal data packet triggers key fetch, decryption, and writing.
    """
    # Setup Mocks
    mock_writer = MagicMock()
    mock_get_key.return_value = {"hexKey": "dummy_hex", "blockId": "b1", "index": 0}
    mock_decrypt.return_value = "decrypted_content"

    # Input Packet
    packet = {
        "chunk_id": 1,
        "key_block_id": "b1",
        "key_index": 0,
        "data": "encrypted_blob",
        "is_last": False
    }

    # Execute
    finished = process_single_packet(packet, mock_writer, sender_id="B")

    # Assertions
    assert finished is False
    mock_get_key.assert_called_with("B", "b1", 0)
    mock_decrypt.assert_called_with("encrypted_blob", "dummy_hex")

    # Crucial: Verify we wrote the bytes of the string
    mock_writer.append.assert_called_once_with(b"decrypted_content")


def test_process_single_packet_termination():
    """
    Verifies that the 'is_last' flag correctly signals completion.
    """
    mock_writer = MagicMock()
    packet = {"chunk_id": -1, "is_last": True}

    finished = process_single_packet(packet, mock_writer, "B")

    assert finished is True
    # Should not attempt to write anything
    mock_writer.append.assert_not_called()


# --- 2. Integration / Loop Tests ---

@patch("src.app.receiver.FileStreamWriter")
@patch("src.app.receiver.process_single_packet")
def test_reception_loop_flow(mock_process, mock_file_writer):
    """
    Tests that the loop:
    1. Polls the transport
    2. Decodes JSON
    3. Feeds data to process_single_packet
    4. Exits when process_single_packet returns True
    """
    # Setup Transport Mock
    mock_transport = MagicMock()

    # Packet 1: Normal Data
    event1 = MagicMock()
    event1.type = 1  # EVENT_TYPE_RECEIVE
    event1.packet.data = b'{"id": 1, "data": "foo"}'  # Valid JSON bytes

    # Packet 2: Termination (We control loop exit via process_single_packet return value)
    event2 = MagicMock()
    event2.type = 1
    event2.packet.data = b'{"is_last": true}'

    # Simulate loop events
    mock_transport.service.side_effect = [event1, event2]

    # Mock process logic: First packet continues (False), second packet exits (True)
    mock_process.side_effect = [False, True]

    # Execute
    run_reception_loop(mock_transport, "dummy_output.txt", "B")

    # Assertions
    assert mock_transport.service.call_count == 2
    assert mock_process.call_count == 2
    # Verify the JSON decoding happened before passing to process logic
    args, _ = mock_process.call_args_list[0]
    assert args[0] == {"id": 1, "data": "foo"}


@patch("src.app.receiver.Transport")
def test_start_server(mock_transport_cls):
    """Simple test to ensure server binds to correct IP/Port."""
    mock_transport_cls.return_value = MagicMock()

    start_server("127.0.0.1", 9999)

    mock_transport_cls.assert_called_with(is_server=True, ip="127.0.0.1", port=9999)