import json
import time
import os
import requests
from src.app.transfer.transport import Transport
from src.app.crypto import encryption
from src.app.file_utils import FileStreamWriter, split_file_into_chunks

# ----- BOB = SENDER ------

# Configuration
receiver_id = "B"
destination_ip = "172.18.0.4"
destination_port = 12345
file_path = "data/patient_records.txt"

# QKD Node Interaction
NODE_RECEIVER_ID = "B"
NODE_SENDER_ID = "A"
NODE_API_URL = f"http://{os.getenv('NODE_HOST', 'localhost')}:{os.getenv('NODE_PORT', '8000')}"  # øøøh, det var autocomplete


def new_key():
    r = requests.get(f"{NODE_API_URL}/new_key")
    r.raise_for_status()
    return r.json()


def get_key(block_id, index):
    params = {"sender_id": NODE_SENDER_ID, "block_id": block_id, "index": index}
    r = requests.get(f"{NODE_API_URL}/get_key", params=params)
    r.raise_for_status()
    return r.json()


def authenticate():
    params = dummy_authenticate()
    r = requests.post(f"{NODE_API_URL}/authenticate", data=params)
    r.raise_for_status()
    if r.json().get("status") == "success":
        return True
    elif r.json().get("message") == "Authenticated":
        return True
    else:
        return r.json()


def dummy_authenticate():
    return {"username": "user", "password": "pass"}


def connect_to_node():
    r = requests.get(f"{NODE_API_URL}/connect", params={"purpose": "sender"})
    r.raise_for_status()
    NODE_ID = r.json()["node_id"]

    authenticated = authenticate()
    if authenticated is True:
        print(f"Authenticated with node as {NODE_ID}")
        return NODE_ID
    elif authenticated is False:
        print("Authentication failed.")
        return None
    else:
        print(f"Authentication response: {authenticated}")
        return None


# Configuration Constants
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
        return new_key()

    return current_key


def send_chunk_packet(transport, chunk, key_data):
    """
    Encrypts a single chunk, formats the packet, and sends it.
    """
    # 1. Encrypt Payload
    encrypted_payload = encryption.encrypt_AES256(chunk["data"], key_data["hexKey"])

    # 2. Format Packet
    packet = {
        "chunk_id": chunk["id"],
        "key_block_id": key_data["blockId"],
        "key_index": key_data["index"],
        "data": encrypted_payload,
        "is_last": False,
    }

    # 3. Serialize & Send
    json_bytes = json.dumps(packet).encode("utf-8")
    transport.send_reliable(json_bytes)


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
                receiver_id,
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
                print(f"Sent chunk {chunk['id']}...", end="\r")

        except Exception as e:
            print(f"\nCritical Error during transmission: {e}")
            break

    # 3. Termination
    print("\nSending termination signal...")
    end_packet = json.dumps({"chunk_id": -1, "is_last": True}).encode("utf-8")
    transport.send_reliable(end_packet)

    # Ensure everything leaves the buffer
    transport.flush()

    duration = time.time() - start_time
    print(f"Transfer complete. {total_bytes / 1024 / 1024:.2f} MB in {duration:.2f}s")


if __name__ == "__main__":
    # Example Usage
    NODE_ID = connect_to_node()
    if not NODE_ID:
        print("Failed to connect to QKD node. Exiting.")

    run_file_transfer("B", "172.18.0.4", 12345, "data/patient_records.txt")
