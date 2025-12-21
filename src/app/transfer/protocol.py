from typing import Tuple, Dict

def create_ack_packet(status="OK", message="Transfer Complete") -> bytes:
    """Creates a confirmation packet to send back to the source."""
    headers = {
        "type": "ACK",
        "status": status,
        "message": message
    }

    return encode_packet_with_headers(headers, b"")

def encode_packet_with_headers(headers: dict, data: bytes) -> bytes:
    """Encodes metadata as headers followed by data."""
    header_parts = [f"{k}:{v}" for k, v in headers.items()]
    header_str = "|".join(header_parts) + "\n"
    return header_str.encode('utf-8') + data


def decode_packet_with_headers(packet_data: bytes) -> Tuple[Dict, bytes]:
    try:
        header_end = packet_data.index(b'\n')
        header_bytes = packet_data[:header_end]
        data_bytes = packet_data[header_end + 1:]

        header_str = header_bytes.decode('utf-8')
        headers = {}
        for part in header_str.split('|'):
            if ':' in part:
                key, value = part.split(':', 1)
                if value.lower() == 'true':
                    headers[key] = True
                elif value.lower() == 'false':
                    headers[key] = False
                elif value.isdigit() or (value.startswith('-') and value[1:].isdigit()):
                    headers[key] = int(value)
                else:
                    headers[key] = value

        return headers, data_bytes
    except (ValueError, IndexError) as e:
        raise ValueError(f"Invalid packet format: {e}")


def create_data_packet(chunk_id: int, key_block_id: str, key_index: int, data: bytes) -> bytes:
    """Creates a standard data packet with encrypted payload."""
    headers = {
        "chunk_id": str(chunk_id),
        "key_block_id": str(key_block_id),
        "key_index": str(key_index),
        "is_last": False
    }
    return encode_packet_with_headers(headers, data)


def create_termination_packet(file_hash="") -> bytes:
    """Creates the signal packet to end transmission."""
    headers = {
        "chunk_id": "-1",
        "is_last": True,
        "file_hash": file_hash
    }
    return encode_packet_with_headers(headers, b"")