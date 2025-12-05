import json
import time
import os
from src.app.kms_api import new_key
from src.app.transfer.transport import Transport
from src.app.file_utils import split_file_into_chunks
from src.app.crypto import encryption

# Configuration Constants
KEY_ROTATION_LIMIT = 1024 * 100  # 100KB


def establish_connection(ip, port):
    """
    Initializes transport and connects to the receiver.
    Returns the transport object if successful, None otherwise.
    """
    transport = Transport(is_server=False)
    if transport.connect(ip, port):
        return transport
    return None


def should_rotate_key(current_key_data, bytes_used, rotation_limit):
    """
    Pure logic: Decides if a new key is needed.
    Testable without any network or file IO.
    """
    if current_key_data is None:
        return True
    if bytes_used >= rotation_limit:
        return True
    return False


def get_encryption_key(sender_id):
    """
    Wrapper for KMS interaction.
    Can be easily mocked in tests to return a dummy key object.
    """
    return new_key(sender_id)


def create_packet(chunk_id, data_bytes, key_data):
    """
    Encrypts data and formats the packet.
    """
    #
    encrypted_payload = encryption.encrypt_AES256(data_bytes, key_data["hexKey"])

    return {
        "chunk_id": chunk_id,
        "key_block_id": key_data["blockId"],
        "key_index": key_data["index"],
        "data": encrypted_payload,
        "is_last": False
    }


def send_packet(transport, packet_dict):
    """
    Handles JSON serialization and reliable sending.
    """
    json_bytes = json.dumps(packet_dict).encode('utf-8')
    transport.send_reliable(json_bytes)


def run_file_transfer(sender_id, destination_ip, destination_port, file_path):
    """
    Main orchestration function.
    """
    transport = establish_connection(destination_ip, destination_port)
    if not transport:
        print("Could not connect to receiver.")
        return

    current_key_data = None
    bytes_encrypted_with_current_key = 0

    print(f"Starting transfer of {file_path}...")

    #
    for chunk in split_file_into_chunks(file_path, 1024):
        # 1. Key Management Logic
        if should_rotate_key(current_key_data, bytes_encrypted_with_current_key, KEY_ROTATION_LIMIT):
            print(f"Refreshing key... (Used {bytes_encrypted_with_current_key} bytes)")
            try:
                current_key_data = get_encryption_key(sender_id)
                bytes_encrypted_with_current_key = 0
            except Exception as e:
                print(f"Critical Error: Could not fetch key - {e}")
                break

        # 2. Packet Creation
        packet = create_packet(chunk["id"], chunk["data"], current_key_data)

        # 3. Network IO
        send_packet(transport, packet)
        transport.service(10)  # Keep connection alive

        # 4. Update State
        bytes_encrypted_with_current_key += chunk["size"]

    # Termination
    send_packet(transport, {"chunk_id": -1, "is_last": True})
    transport.flush()
    print("Transfer complete.")


if __name__ == "__main__":
    # Example Usage
    run_file_transfer("A", "127.0.0.1", 12345, "data/file.txt")