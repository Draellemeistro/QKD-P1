import pytest
from src.app.transfer.protocol import (
    create_data_packet,
    create_termination_packet,
    create_ack_packet,
    decode_packet_with_headers,
    encode_packet_with_headers
)


# --- 1. CORE SERIALIZATION TESTS ---

def test_encode_packet_structure():
    """
    Verifies that the encoder correctly formats the headers and separates
    them from data with a newline character.
    """
    headers = {"key": "value", "id": 123}
    data = b"payload"

    encoded = encode_packet_with_headers(headers, data)

    # Check that it ends with the data
    assert encoded.endswith(b"payload")

    # Check that the separator exists
    assert b"\n" in encoded

    # Check specific header format (key:value|...)
    header_section = encoded.split(b"\n")[0].decode('utf-8')
    assert "key:value" in header_section
    assert "id:123" in header_section


def test_decode_packet_parsing():
    """
    Verifies that the decoder correctly splits headers and parses types.
    """
    # Simulate a raw packet received from the network
    # Headers: id=99 (int), flag=True (bool), name=test (str)
    raw_packet = b"id:99|flag:true|name:test\nBinaryData"

    headers, data = decode_packet_with_headers(raw_packet)

    assert data == b"BinaryData"
    assert headers["id"] == 99  # Should be int
    assert headers["flag"] is True  # Should be bool
    assert headers["name"] == "test"  # Should be str


def test_roundtrip_fidelity():
    """
    Verifies that encoding -> decoding returns the exact original data.
    """
    original_headers = {
        "chunk_id": 500,
        "is_last": False,
        "key_block": "AB-123"
    }
    original_data = b"\x00\xFF\xAA\xBB"

    # Encode
    packet = encode_packet_with_headers(original_headers, original_data)

    # Decode
    decoded_headers, decoded_data = decode_packet_with_headers(packet)

    assert decoded_data == original_data
    assert decoded_headers == original_headers


# --- 2. PACKET TYPE HELPERS ---

def test_create_data_packet():
    """Verifies standard data packet construction."""
    chunk_id = 1
    key_block = "B1"
    key_index = 5
    payload = b"encrypted"

    packet = create_data_packet(chunk_id, key_block, key_index, payload)

    headers, data = decode_packet_with_headers(packet)

    assert data == payload
    assert headers["chunk_id"] == 1
    assert headers["key_block_id"] == "B1"
    assert headers["key_index"] == 5
    assert headers["is_last"] is False


def test_create_termination_packet():
    """Verifies termination packet signals 'is_last' correctly."""
    file_hash = "abcdef123"

    packet = create_termination_packet(file_hash)
    headers, data = decode_packet_with_headers(packet)

    assert headers["is_last"] is True
    assert headers["file_hash"] == file_hash
    assert headers["chunk_id"] == -1
    assert data == b""  # Termination should have empty body


def test_create_ack_packet():
    """Verifies the ACK packet sent by Receiver."""
    packet = create_ack_packet(status="ERROR", message="Hash Mismatch")
    headers, data = decode_packet_with_headers(packet)

    assert headers["type"] == "ACK"
    assert headers["status"] == "ERROR"
    assert headers["message"] == "Hash Mismatch"


# --- 3. ERROR HANDLING ---

def test_malformed_packet_no_delimiter():
    """
    Test Case: Packet missing the newline separator.
    Result: Should raise ValueError (or crash gracefully).
    """
    bad_packet = b"header:valuedata"  # No \n

    with pytest.raises(ValueError, match="Invalid packet format"):
        decode_packet_with_headers(bad_packet)


def test_malformed_header_format():
    """
    Test Case: Header missing the key:value structure.
    """
    # 'brokenheader' has no colon
    bad_packet = b"brokenheader|id:1\nData"

    # Your implementation currently ignores bad parts or might handle them.
    # Based on your code: `if ':' in part` it processes, else ignores.
    # So this packet IS valid, but 'brokenheader' is skipped.
    headers, _ = decode_packet_with_headers(bad_packet)

    assert headers["id"] == 1
    assert "brokenheader" not in headers