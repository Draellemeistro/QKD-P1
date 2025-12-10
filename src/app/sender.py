import json
import time
import os
import sys

# Updated imports to match your project structure
from src.app.kms_api import new_key
from src.app.transfer.transport import Transport
from src.app.file_utils import split_file_into_chunks
from src.app.crypto import encryption
from src.app.transfer.network_utils import resolve_host
from src.app.transfer.protocol import create_data_packet, create_termination_packet, encode_packet_with_headers

# Configuration Constants
# 64KB:
CHUNK_SIZE = 64 * 1024
KEY_ROTATION_LIMIT = 1024 * 1024 * 10  # Rotate key every 10 MB




def establish_connection(ip, port):
    """
    Initializes transport and connects to the receiver.
    """
    transport = Transport(is_server=False)
    if transport.connect(ip, port):
        return transport
    return None


def ensure_valid_key(current_key, bytes_used, limit, receiver_id):
    """
    Checks if the current key is valid or needs rotation.
    Returns: The active key (either the current one or a newly fetched one).
    """
    # 1. Check if we need a new key
    needs_rotation = (current_key is None) or (bytes_used >= limit)

    if needs_rotation:
        print(f"Fetching new key... (Previous used for {bytes_used} bytes)")
        #
        return new_key(receiver_id)

    return current_key


def send_chunk_packet(transport, chunk, key_data):
    """
    Encrypts a single chunk, formats the packet, and sends it.
    """
    # 1. Encrypt Payload
    encrypted_payload = encryption.encrypt_AES256(chunk["data"], key_data["hexKey"])
    # 2. Create Packet with headers
    packet = create_data_packet(chunk["id"], key_data["blockId"], key_data["index"], encrypted_payload.encode('utf-8'))    # 3. Send Packet Reliably
    transport.send_reliable(packet)


def run_file_transfer(receiver_id, destination_ip, destination_port, file_path):
    """
    Main Orchestration Loop.
    """
    # 1. Setup
    transport = establish_connection(destination_ip, destination_port)
    if not transport:
        print(f"Error: Could not connect to {destination_ip}:{destination_port}")
        return

    current_key_data = None
    bytes_encrypted_with_current_key = 0
    total_bytes = 0
    start_time = time.time()

    print(f"Starting transfer of {file_path} (Chunk Size: {CHUNK_SIZE / 1024} KB)...")

    # 2. Streaming Loop
    for chunk in split_file_into_chunks(file_path, CHUNK_SIZE):
        try:
            # A. Key Management
            current_key_data = ensure_valid_key(
                current_key_data,
                bytes_encrypted_with_current_key,
                KEY_ROTATION_LIMIT,
                receiver_id
            )

            # If a new key was fetched, reset the counter
            if bytes_encrypted_with_current_key >= KEY_ROTATION_LIMIT:
                bytes_encrypted_with_current_key = 0

            # B. Processing & Sending
            send_chunk_packet(transport, chunk, current_key_data)

            # C. Network Pump (Non-blocking for speed)
            transport.service(0)

            # D. State Update
            bytes_encrypted_with_current_key += chunk["size"]
            total_bytes += chunk["size"]

            # Progress Log
            if chunk["id"] % 10 == 0:
                print(f"Sent chunk {chunk['id']}...", end='\r')

        except Exception as e:
            print(f"\nCritical Error during transmission: {e}")
            break

    # 3. Termination
    print("\nSending termination signal...")
    end_packet = create_termination_packet()
    transport.send_reliable(end_packet)

    # Ensure everything leaves the buffer
    transport.flush()

    duration = time.time() - start_time
    print(f"Transfer complete. {total_bytes / 1024 / 1024:.2f} MB in {duration:.2f}s")


if __name__ == "__main__":
    # 1. Parse Arguments
    if len(sys.argv) > 1:
        target_name = sys.argv[1]
    else:
        target_name = "bob"

    # 2. Resolve
    target_ip, target_port, peer_site_id = resolve_host(target_name)

    print(f"Resolved '{target_name}':")
    print(f"IP: {target_ip}")
    print(f"Site ID: {peer_site_id}")

    run_file_transfer(peer_site_id, target_ip, target_port, "data/patient_records.txt")


